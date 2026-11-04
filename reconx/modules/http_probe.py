"""HTTP probing.

Preferred: httpx (projectdiscovery) for rich metadata (tech, status, title,
webserver, ip) in one pass.
Fallback: pure-Python async probing with httpx(python lib), trying https then
http, extracting status / title / server header / basic tech hints.
"""
from __future__ import annotations

import asyncio
import re

import httpx

from ..config import settings
from .. import tools
from . import waf_cdn

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_TECH_HINTS = {
    "wordpress": re.compile(r"wp-content|wp-includes", re.I),
    "drupal": re.compile(r"Drupal|/sites/default/", re.I),
    "react": re.compile(r"__REACT_DEVTOOLS|data-reactroot", re.I),
    "nextjs": re.compile(r"/_next/|__NEXT_DATA__", re.I),
    "vue": re.compile(r"data-v-[0-9a-f]{8}", re.I),
    "angular": re.compile(r"ng-version|angular", re.I),
    "laravel": re.compile(r"laravel_session|XSRF-TOKEN", re.I),
    "django": re.compile(r"csrfmiddlewaretoken", re.I),
    "jquery": re.compile(r"jquery[.-]", re.I),
}


async def _probe_py(host: str, client: httpx.AsyncClient, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        # Accept both bare hosts (try https then http) and full URLs (use as-is).
        if host.startswith(("http://", "https://")):
            candidates = [host]
        else:
            candidates = [f"https://{host}", f"http://{host}"]
        for url in candidates:
            try:
                r = await client.get(url, follow_redirects=True)
            except Exception:
                continue
            body = r.text[:200000]
            title_m = _TITLE.search(body)
            title = (title_m.group(1).strip()[:200] if title_m else "")
            tech = [name for name, rx in _TECH_HINTS.items() if rx.search(body) or rx.search(str(r.headers))]
            ip = ""
            try:
                ip = r.extensions.get("network_stream").get_extra_info("peername")[0]  # type: ignore
            except Exception:
                ip = ""
            cdn, waf = waf_cdn.detect(dict(r.headers), body_snippet=body[:2000])
            return {
                "input": url,            # the in-scope host/URL we probed
                "url": str(r.url),       # final URL (may be a redirect target)
                "status": r.status_code,
                "title": title,
                "tech": ",".join(tech),
                "webserver": r.headers.get("server", ""),
                "ip": ip,
                "content_len": len(r.content),
                "cdn": cdn,
                "waf": waf,
            }
    return None


async def probe(hosts: list[str]) -> list[dict]:
    tool = tools.first_available("http")
    if tool == "httpx" and await tools.verify_pd("httpx"):
        args = ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code",
                "-web-server", "-ip", "-cdn", "-follow-redirects", "-no-color"]
        res = await tools.run(args, stdin="\n".join(hosts), timeout=900)
        out = []
        for obj in tools.parse_jsonl(res.lines):
            out.append({
                "input": obj.get("input") or obj.get("url", ""),
                "url": obj.get("url") or obj.get("input", ""),
                "status": obj.get("status_code") or obj.get("status-code"),
                "title": obj.get("title", ""),
                "tech": ",".join(obj.get("tech", []) or obj.get("technologies", []) or []),
                "webserver": obj.get("webserver") or obj.get("web-server", ""),
                "ip": obj.get("host") or obj.get("ip", ""),
                "content_len": obj.get("content_length") or obj.get("content-length", 0) or 0,
                "cdn": obj.get("cdn_name", "") if obj.get("cdn") else "",
                "waf": "",
            })
        if out:
            return out

    # Fallback: pure python
    sem = asyncio.Semaphore(settings.http_concurrency)
    results = []
    async with httpx.AsyncClient(
        timeout=settings.http_timeout, verify=False,
        headers={"User-Agent": settings.user_agent},
    ) as client:
        tasks = [_probe_py(h, client, sem) for h in hosts]
        for coro in asyncio.as_completed(tasks):
            r = await coro
            if r:
                results.append(r)
    return results
