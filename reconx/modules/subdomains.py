"""Subdomain enumeration — passive + brute-force + permutation.

Coverage is the foundation of recon, so this merges several independent methods:

  passive  : subfinder/assetfinder/amass (all sources) + Certificate Transparency
             (crt.sh) + free HTTP sources (hackertarget, certspotter, OTX,
             rapiddns) — no API key required (keys make subfinder stronger).
  brute    : resolve a wordlist of common names against the apex.
  permute  : generate variants of what we found (dev-api, api2, staging-www, …)
             and resolve them.

Brute/permutation candidates are resolved and wildcard-filtered (via dnsx when
available, else the stdlib resolver) so only names that actually exist survive.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import httpx

from ..config import settings
from .. import tools
from .dns_resolve import _resolve_stdlib, _wildcard_ips

DATA = Path(__file__).parent.parent / "data"


def _wordlist() -> list[str]:
    p = Path(settings.subdomain_wordlist) if settings.subdomain_wordlist else DATA / "subdomains.txt"
    try:
        return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]
    except Exception:
        return []


def _perm_words() -> list[str]:
    try:
        return [l.strip() for l in (DATA / "permutation_words.txt").read_text().splitlines() if l.strip()]
    except Exception:
        return ["dev", "staging", "test", "prod", "api", "admin", "old", "new", "2", "v2"]


# ---------------- passive HTTP sources (no API key) ----------------
async def _passive_http(domain: str) -> set[str]:
    found: set[str] = set()
    headers = {"User-Agent": settings.user_agent}
    async with httpx.AsyncClient(timeout=25, headers=headers, verify=False) as c:
        async def crtsh():
            try:
                r = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
                if r.status_code == 200:
                    for row in r.json():
                        for n in str(row.get("name_value", "")).splitlines():
                            found.add(n.strip().lstrip("*.").lower())
            except Exception:
                pass

        async def hackertarget():
            try:
                r = await c.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
                if r.status_code == 200 and "," in r.text:
                    for line in r.text.splitlines():
                        found.add(line.split(",")[0].strip().lower())
            except Exception:
                pass

        async def certspotter():
            try:
                r = await c.get(f"https://api.certspotter.com/v1/issuances?domain={domain}"
                                f"&include_subdomains=true&expand=dns_names")
                if r.status_code == 200:
                    for row in r.json():
                        for n in row.get("dns_names", []):
                            found.add(n.strip().lstrip("*.").lower())
            except Exception:
                pass

        async def otx():
            try:
                r = await c.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
                if r.status_code == 200:
                    for row in r.json().get("passive_dns", []):
                        found.add(str(row.get("hostname", "")).strip().lower())
            except Exception:
                pass

        async def rapiddns():
            try:
                r = await c.get(f"https://rapiddns.io/subdomain/{domain}?full=1")
                if r.status_code == 200:
                    for m in re.findall(r"<td>([a-zA-Z0-9_.-]+\." + re.escape(domain) + r")</td>", r.text):
                        found.add(m.strip().lower())
            except Exception:
                pass

        await asyncio.gather(crtsh(), hackertarget(), certspotter(), otx(), rapiddns())
    return {f for f in found if f.endswith(domain)}


# ---------------- resolution / wildcard filter ----------------
async def _resolve_filter(candidates: list[str], apex: str, wc: set[str],
                          concurrency: int = 120) -> set[str]:
    cands = list(dict.fromkeys(c for c in candidates if c))
    if not cands:
        return set()

    if await tools.verify_pd("dnsx"):
        res = await tools.run(["dnsx", "-silent", "-wd", apex], stdin="\n".join(cands), timeout=600)
        return {l.strip().lower().split()[0] for l in res.lines if l.strip()}

    sem = asyncio.Semaphore(concurrency)
    out: set[str] = set()

    async def one(h: str):
        async with sem:
            ips = await _resolve_stdlib(h)
            if ips and not (wc and set(ips).issubset(wc)):
                out.add(h)

    await asyncio.gather(*(one(h) for h in cands))
    return out


def _gen_permutations(known: set[str], domain: str, words: list[str], cap: int = 3000) -> list[str]:
    perms: set[str] = set()
    labels = []
    for full in known:
        if full.endswith("." + domain):
            lbl = full[: -len(domain) - 1]
            base = lbl.split(".")[0]
            if base:
                labels.append(base)
    for base in list(dict.fromkeys(labels))[:40]:
        for w in words:
            perms.add(f"{base}-{w}.{domain}")
            perms.add(f"{w}-{base}.{domain}")
            perms.add(f"{base}{w}.{domain}")
            if len(perms) >= cap:
                return list(perms)
    return list(perms)


# ---------------- main ----------------
async def enumerate(domain: str, do_brute: bool = True, do_perm: bool = True) -> dict:
    found: set[str] = set()
    srcs: list[str] = []

    tool = tools.first_available("subdomains")
    if tool == "subfinder":
        res = await tools.run(["subfinder", "-silent", "-all", "-d", domain], timeout=600)
        found.update(l.strip().lower() for l in res.lines if l.strip()); srcs.append("subfinder")
    elif tool == "assetfinder":
        res = await tools.run(["assetfinder", "--subs-only", domain], timeout=600)
        found.update(l.strip().lower() for l in res.lines if l.strip()); srcs.append("assetfinder")
    elif tool == "amass":
        res = await tools.run(["amass", "enum", "-passive", "-d", domain], timeout=900)
        found.update(l.strip().lower() for l in res.lines if l.strip()); srcs.append("amass")

    hp = await _passive_http(domain)
    if hp:
        found |= hp; srcs.append(f"passive-http(+{len(hp)})")
    found.add(domain)
    found = {f for f in found if f.endswith(domain)}

    wc = await _wildcard_ips(domain) if (do_brute or do_perm) else set()

    if do_brute and settings.brute_force:
        cands = [f"{w}.{domain}" for w in _wordlist()]
        res = await _resolve_filter(cands, domain, wc)
        new = res - found
        if new:
            srcs.append(f"brute(+{len(new)})")
        found |= res

    if do_perm and settings.brute_force:
        perms = _gen_permutations(found, domain, _perm_words())
        res = await _resolve_filter(perms, domain, wc)
        new = res - found
        if new:
            srcs.append(f"perm(+{len(new)})")
        found |= res

    return {"subdomains": sorted(f for f in found if f.endswith(domain)),
            "source": "+".join(srcs) or "crtsh"}
