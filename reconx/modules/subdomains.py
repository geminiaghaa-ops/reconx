"""Subdomain enumeration.

Preferred: subfinder / assetfinder / amass (passive, fast, many sources).
Fallback (always available, no external deps): Certificate Transparency via
crt.sh, which needs only outbound HTTPS.
"""
from __future__ import annotations

import httpx

from ..config import settings
from .. import tools


async def _crtsh(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=30, headers={"User-Agent": settings.user_agent}) as client:
            r = await client.get(url)
            if r.status_code == 200:
                for row in r.json():
                    for name in str(row.get("name_value", "")).splitlines():
                        name = name.strip().lstrip("*.").lower()
                        if name.endswith(domain):
                            found.add(name)
    except Exception:
        pass
    return sorted(found)


async def enumerate(domain: str) -> dict:
    """Return {'subdomains': [...], 'source': 'tool|crtsh'}."""
    tool = tools.first_available("subdomains")
    results: set[str] = set()
    source = "crtsh"

    if tool == "subfinder":
        res = await tools.run(["subfinder", "-silent", "-d", domain], timeout=600)
        results.update(l.strip().lower() for l in res.lines if l.strip())
        source = "subfinder"
    elif tool == "assetfinder":
        res = await tools.run(["assetfinder", "--subs-only", domain], timeout=600)
        results.update(l.strip().lower() for l in res.lines if l.strip())
        source = "assetfinder"
    elif tool == "amass":
        res = await tools.run(["amass", "enum", "-passive", "-d", domain], timeout=900)
        results.update(l.strip().lower() for l in res.lines if l.strip())
        source = "amass"

    # Always merge in crt.sh (cheap, independent corroboration).
    results.update(await _crtsh(domain))
    results.add(domain)
    return {"subdomains": sorted(r for r in results if r.endswith(domain)), "source": source}
