"""URL discovery / crawling.

Preferred: katana (active crawl), gau / waybackurls (passive, historical URLs).
Fallback: a light pure-Python crawler that pulls links + script srcs one level
deep from each live host.

The main job here is to surface JavaScript files for the JS-analysis stage and
to expand the URL surface for nuclei.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from ..config import settings
from ..auth import NO_AUTH
from .. import tools

_SRC = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+)["']""", re.I)
# Links that must never be requested while authenticated (they end the session
# or change state), filtered out of crawl output during authed scans.
_DANGER = re.compile(r"(?i)(log[\-_]?out|sign[\-_]?out|/logoff|/delete|/destroy|/remove|/deactivate|/revoke|/reset)")


async def _crawl_py(base: str, client: httpx.AsyncClient) -> set[str]:
    urls: set[str] = set()
    try:
        r = await client.get(base, follow_redirects=True)
    except Exception:
        return urls
    host = urlparse(str(r.url)).hostname or ""
    for m in _SRC.finditer(r.text[:400000]):
        link = m.group(1)
        if link.startswith(("data:", "mailto:", "javascript:", "tel:")):
            continue
        full = urljoin(str(r.url), link)
        if urlparse(full).hostname and host and urlparse(full).hostname.endswith(host.split(".", 1)[-1]):
            urls.add(full.split("#")[0])
    return urls


async def crawl(live_urls: list[str], auth=None, scope=None) -> dict:
    """Return {'urls': [...], 'js': [...]}."""
    auth = auth or NO_AUTH
    all_urls: set[str] = set(live_urls)

    katana = tools.which("katana")
    gau = tools.which("gau") or tools.which("waybackurls")

    if katana:
        args = ["katana", "-silent", "-jc", "-d", "2", "-list", "-"]
        for pair in auth.header_pairs():
            args += ["-H", pair]
        res = await tools.run(args, stdin="\n".join(live_urls), timeout=900)
        all_urls.update(l.strip() for l in res.lines if l.strip())
    if gau:
        hosts = {urlparse(u).hostname for u in live_urls if urlparse(u).hostname}
        res = await tools.run([tools.which("gau") and "gau" or "waybackurls"],
                              stdin="\n".join(sorted(h for h in hosts if h)), timeout=600)
        all_urls.update(l.strip() for l in res.lines if l.strip().startswith("http"))

    if not katana:
        # pure-python fallback crawl (auth-aware, in-scope only)
        async with auth.client(scope=scope, timeout=settings.http_timeout) as client:
            sem = asyncio.Semaphore(settings.http_concurrency)

            async def one(u):
                async with sem:
                    return await _crawl_py(u, client)

            for coro in asyncio.as_completed([one(u) for u in live_urls]):
                all_urls.update(await coro)

    # While authenticated, drop session-ending / state-changing links so we
    # never log ourselves out or trigger a destructive action.
    if auth.active:
        all_urls = {u for u in all_urls if not _DANGER.search(u)}

    js = sorted({u for u in all_urls if urlparse(u).path.lower().endswith(".js") or ".js?" in u.lower()})
    return {"urls": sorted(all_urls), "js": js}
