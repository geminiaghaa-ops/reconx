"""JavaScript analysis.

Downloads JS files discovered during crawling and mines them for:
  * secrets      - API keys / tokens / private keys (regex + entropy sanity)
  * endpoints    - API paths & URLs referenced in the code (new attack surface)
  * sinks        - DOM-XSS-relevant sink/source usage worth manual review
  * sourcemap    - exposed .map files that leak original source
  * library      - known-vulnerable JS libraries via retire.js (if installed)

Built-in detectors run everywhere; retire.js is used when available for
authoritative CVE matching.
"""
from __future__ import annotations

import asyncio
import math
import re
import tempfile
from pathlib import Path

import httpx

from ..config import settings
from .. import tools

# --- secret signatures -------------------------------------------------
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # name, severity, regex
    ("AWS Access Key", "high", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", "high", r"(?i)aws(.{0,20})?(secret|private).{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Google API Key", "high", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth", "medium", r"ya29\.[0-9A-Za-z\-_]+"),
    ("Firebase URL", "low", r"[a-z0-9.-]+\.firebaseio\.com"),
    ("Slack Token", "high", r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    ("Slack Webhook", "high", r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+"),
    ("Stripe Live Key", "high", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable", "low", r"pk_live_[0-9a-zA-Z]{24,}"),
    ("GitHub Token", "high", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("GitLab Token", "high", r"glpat-[0-9A-Za-z\-_]{20,}"),
    ("JWT", "medium", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("Private Key", "high", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("Mailgun Key", "high", r"key-[0-9a-zA-Z]{32}"),
    ("Twilio SID", "medium", r"AC[a-z0-9]{32}"),
    ("SendGrid Key", "high", r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    ("Generic API Key assignment", "medium",
     r"(?i)(?:api[_-]?key|apikey|secret|token|passwd|password|auth)[\"']?\s*[:=]\s*[\"'][0-9a-zA-Z\-_\.]{16,64}[\"']"),
    ("Basic Auth in URL", "medium", r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
]

# --- endpoint extraction ----------------------------------------------
ENDPOINT_RE = re.compile(
    r"""["'`]((?:/|\.\./|\./)?(?:[a-zA-Z0-9_?&=\-./]+)?(?:/api/|/v[0-9]+/|graphql|\.json|\.php|\.aspx)[a-zA-Z0-9_?&=\-./]*)["'`]"""
)
URL_RE = re.compile(r"""["'`](https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)["'`]""")

# --- DOM XSS relevant sinks / sources ---------------------------------
SINKS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(", "location.href", "location.assign",
    "location.replace", ".src=", "jQuery.globalEval", "$.globalEval",
]
SOURCES = ["location.hash", "location.search", "location.href", "document.URL",
           "document.referrer", "window.name", "postMessage"]

_NOISE = re.compile(r"(?i)(example|changeme|your[_-]?\w{0,6}[_-]?key|api[_-]?key[_-]?here|insert.{0,12}here|placeholder|dummy|test[_-]?key|lorem|redacted|xxxx|<[a-z_\-]+>)")


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _plausible_secret(value: str) -> bool:
    """Reduce false positives: reject obvious placeholders, require some entropy
    for generic matches."""
    if _NOISE.search(value):
        return False
    core = re.sub(r"""['\"]""", "", value)
    if len(core) >= 16 and _shannon(core) < 2.5:
        return False
    return True


def scan_text(src_url: str, text: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple] = set()

    def add(kind, value, name="", severity="info", context=""):
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        findings.append({"kind": kind, "value": value, "name": name,
                         "severity": severity, "context": context})

    # secrets
    for name, severity, pat in SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            val = m.group(0)
            if not _plausible_secret(val):
                continue
            start = max(0, m.start() - 30)
            add("secret", val, name=name, severity=severity, context=text[start:m.end() + 20].replace("\n", " "))

    # endpoints
    for m in ENDPOINT_RE.finditer(text):
        ep = m.group(1)
        if 3 < len(ep) < 180:
            add("endpoint", ep, name="path")
    for m in URL_RE.finditer(text):
        add("endpoint", m.group(1)[:300], name="url")

    # DOM sinks / sources
    present_sinks = [s for s in SINKS if s in text]
    present_sources = [s for s in SOURCES if s in text]
    if present_sinks and present_sources:
        add("sink", f"sinks={present_sinks} sources={present_sources}",
            name="possible DOM-XSS", severity="medium",
            context="source-to-sink data flow present; manual review needed")
    elif present_sinks:
        add("sink", ",".join(present_sinks), name="dangerous sinks", severity="low")

    # source map reference
    for m in re.finditer(r"//[#@]\s*sourceMappingURL=(\S+)", text):
        add("sourcemap", m.group(1), name="sourceMappingURL", severity="low",
            context="exposed source map can reveal original source")

    for f in findings:
        f["source_url"] = src_url
    return findings


async def _fetch(url: str, client: httpx.AsyncClient) -> tuple[str, str] | None:
    try:
        r = await client.get(url, follow_redirects=True)
        if r.status_code == 200 and len(r.text) < 5_000_000:
            return url, r.text
    except Exception:
        return None
    return None


async def _retirejs(js_files: list[tuple[str, str]]) -> list[dict]:
    """Run retire.js over downloaded JS for known-CVE library detection."""
    if not tools.which("retire") or not js_files:
        return []
    out: list[dict] = []
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        mapping = {}
        for i, (url, text) in enumerate(js_files):
            fp = tdp / f"f{i}.js"
            fp.write_text(text, errors="replace")
            mapping[str(fp)] = url
        res = await tools.run(["retire", "--path", td, "--outputformat", "json",
                               "--outputpath", str(tdp / "out.json")], timeout=300)
        outfile = tdp / "out.json"
        if outfile.exists():
            import json
            try:
                data = json.loads(outfile.read_text() or "{}")
            except Exception:
                data = {}
            for entry in (data.get("data") or data if isinstance(data, list) else []):
                fpath = entry.get("file", "")
                for res_item in entry.get("results", []):
                    comp = res_item.get("component", "")
                    ver = res_item.get("version", "")
                    for v in res_item.get("vulnerabilities", []):
                        sev = v.get("severity", "medium")
                        ids = v.get("identifiers", {})
                        cve = ",".join(ids.get("CVE", []) or [ids.get("summary", "")])
                        out.append({
                            "kind": "library", "severity": sev,
                            "name": f"{comp} {ver}",
                            "value": f"{comp}@{ver} {cve}".strip(),
                            "context": (v.get("info") or [""])[0] if v.get("info") else "",
                            "source_url": mapping.get(fpath, fpath),
                        })
    return out


async def analyze(js_urls: list[str]) -> list[dict]:
    if not js_urls:
        return []
    findings: list[dict] = []
    downloaded: list[tuple[str, str]] = []
    sem = asyncio.Semaphore(settings.http_concurrency)

    async with httpx.AsyncClient(timeout=settings.http_timeout, verify=False,
                                 headers={"User-Agent": settings.user_agent}) as client:
        async def one(u):
            async with sem:
                return await _fetch(u, client)

        for coro in asyncio.as_completed([one(u) for u in js_urls[:800]]):
            got = await coro
            if got:
                url, text = got
                downloaded.append(got)
                findings.extend(scan_text(url, text))

    findings.extend(await _retirejs(downloaded))
    return findings
