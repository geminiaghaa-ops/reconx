"""DNS resolution, wildcard detection, and CNAME lookup.

Why this stage exists: subdomain enumeration produces *candidate* names; many
don't actually resolve. Resolving first means later stages (ports, http,
takeover) only touch hosts that really exist, and it gives us the A records and
CNAMEs that drive IP-based work and subdomain-takeover checks.

Preferred: dnsx (ProjectDiscovery). Fallbacks: dnspython if importable, else the
standard-library resolver (A records only; CNAME best-effort).

Wildcard DNS detection: if random non-existent names under the apex resolve,
the zone is a wildcard, so a name resolving *only* to the wildcard IPs is not
proof the host is real. Such names are flagged (meta.wildcard=True) rather than
dropped.
"""
from __future__ import annotations

import asyncio
import random
import socket
import string

from ..config import settings
from .. import tools

try:  # optional, nicer (gives CNAME)
    import dns.resolver as _dnspy  # type: ignore
    import dns.asyncresolver as _dnsasync  # type: ignore
    _HAVE_DNSPY = True
except Exception:  # noqa: BLE001
    _HAVE_DNSPY = False


def _rand_label(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


async def _resolve_stdlib(host: str) -> list[str]:
    loop = asyncio.get_event_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=6)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


async def _resolve_dnspy(host: str) -> tuple[list[str], str]:
    ips: list[str] = []
    cname = ""
    try:
        res = _dnsasync.Resolver()
        res.lifetime = 6
        try:
            ans = await res.resolve(host, "CNAME")
            cname = str(ans[0].target).rstrip(".").lower()
        except Exception:
            cname = ""
        try:
            ans = await res.resolve(host, "A")
            ips = sorted({r.address for r in ans})
        except Exception:
            ips = []
    except Exception:
        pass
    return ips, cname


async def _wildcard_ips(apex: str) -> set[str]:
    probes = [f"{_rand_label()}.{apex}" for _ in range(3)]
    results = await asyncio.gather(*(_resolve_stdlib(h) for h in probes))
    wc: set[str] = set()
    for r in results:
        wc.update(r)
    return wc


async def resolve(hosts: list[str], apex: str) -> dict:
    """Return {'resolved': {host: {'ips':[...], 'cname':str, 'wildcard':bool}},
               'live_hosts': [...], 'wildcard_ips': [...]}."""
    hosts = sorted(set(h.strip().lower() for h in hosts if h.strip()))

    # Preferred: dnsx tool (verified so a shadowing binary can't break us).
    if await tools.verify_pd("dnsx"):
        res = await tools.run(["dnsx", "-silent", "-a", "-cname", "-resp", "-json"],
                              stdin="\n".join(hosts), timeout=600)
        resolved: dict[str, dict] = {}
        for obj in tools.parse_jsonl(res.lines):
            h = (obj.get("host") or "").lower()
            if not h:
                continue
            resolved[h] = {
                "ips": obj.get("a", []) or [],
                "cname": (obj.get("cname", [""]) or [""])[0] if isinstance(obj.get("cname"), list) else obj.get("cname", ""),
                "wildcard": False,
            }
        wc = await _wildcard_ips(apex)
        for h, d in resolved.items():
            if d["ips"] and wc and set(d["ips"]).issubset(wc):
                d["wildcard"] = True
        return {"resolved": resolved, "live_hosts": sorted(resolved.keys()),
                "wildcard_ips": sorted(wc)}

    # Fallback: built-in resolver.
    wc = await _wildcard_ips(apex)
    sem = asyncio.Semaphore(max(20, settings.http_concurrency))
    resolved = {}

    async def one(h: str):
        async with sem:
            if _HAVE_DNSPY:
                ips, cname = await _resolve_dnspy(h)
            else:
                ips, cname = await _resolve_stdlib(h), ""
            if ips or cname:
                resolved[h] = {
                    "ips": ips, "cname": cname,
                    "wildcard": bool(ips and wc and set(ips).issubset(wc)),
                }

    await asyncio.gather(*(one(h) for h in hosts))
    return {"resolved": resolved, "live_hosts": sorted(resolved.keys()),
            "wildcard_ips": sorted(wc)}
