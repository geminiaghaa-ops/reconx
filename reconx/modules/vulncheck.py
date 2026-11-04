"""Built-in active vulnerability checks (complement nuclei, work without it).

Safe, low-noise checks worth running on every live host:
  * CORS misconfiguration  — reflected/arbitrary Origin, null origin, * + creds
  * Open redirect          — common redirect params pointed at an external host
  * Security headers       — missing HSTS / CSP / X-Frame-Options / nosniff

All run auth-aware and in-scope only. These are detections, not exploits.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from ..config import settings
from ..auth import NO_AUTH

EVIL = "evil-reconx.example"
REDIRECT_PARAMS = ["url", "redirect", "redirect_url", "redirect_uri", "next",
                   "return", "returnurl", "return_url", "dest", "destination",
                   "continue", "goto", "r", "u", "target", "rurl"]
SEC_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "nosniff",
}


async def _cors(url: str, client) -> dict | None:
    origin = f"https://{EVIL}"
    try:
        r = await client.get(url, headers={"Origin": origin})
    except Exception:
        return None
    acao = r.headers.get("access-control-allow-origin", "")
    acac = (r.headers.get("access-control-allow-credentials", "") or "").lower()
    if acao == origin:
        return {"url": url, "name": "CORS: arbitrary origin reflected",
                "severity": "high" if acac == "true" else "medium",
                "note": f"ACAO reflects {origin}" + (" with credentials" if acac == "true" else "")}
    if acao == "null":
        return {"url": url, "name": "CORS: null origin allowed", "severity": "medium",
                "note": "Access-Control-Allow-Origin: null"}
    if acao == "*" and acac == "true":
        return {"url": url, "name": "CORS: wildcard with credentials", "severity": "low",
                "note": "ACAO * with credentials (browser-blocked, still a misconfig)"}
    return None


def _sec_headers(headers) -> list[str]:
    present = {k.lower() for k in headers.keys()}
    return [label for h, label in SEC_HEADERS.items() if h not in present]


async def _open_redirect(base: str, client) -> dict | None:
    payload = f"https://{EVIL}/"
    for p in REDIRECT_PARAMS[:6]:
        test = urljoin(base + "/", f"?{p}={payload}")
        try:
            r = await client.get(test, follow_redirects=False)
        except Exception:
            continue
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and (loc.startswith(payload) or EVIL in urlparse(loc).netloc):
            return {"url": test, "name": "Open redirect", "severity": "medium",
                    "note": f"param '{p}' redirects to {loc[:80]}"}
    return None


async def check(live_urls: list[str], auth=None, scope=None, cap: int = 25) -> list[dict]:
    auth = auth or NO_AUTH
    findings: list[dict] = []
    urls = live_urls[:cap]
    async with auth.client(scope=scope, timeout=settings.http_timeout) as client:
        sem = asyncio.Semaphore(settings.http_concurrency)

        async def one(url: str):
            async with sem:
                c = await _cors(url, client)
                if c:
                    findings.append(c)
                o = await _open_redirect(url, client)
                if o:
                    findings.append(o)
                try:
                    r = await client.get(url, follow_redirects=True)
                    missing = _sec_headers(r.headers)
                    if missing:
                        findings.append({"url": url, "name": "Missing security headers",
                                         "severity": "info", "note": ", ".join(missing)})
                except Exception:
                    pass

        await asyncio.gather(*(one(u) for u in urls))
    return findings
