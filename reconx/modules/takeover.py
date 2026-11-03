"""Subdomain takeover detection.

A dangling CNAME pointing at a de-provisioned service (GitHub Pages, S3, Heroku,
…) can often be claimed by an attacker. High value, low noise. We flag a host
when its CNAME matches a known service AND the live response carries that
service's "unclaimed" fingerprint.
"""
from __future__ import annotations

import asyncio

import httpx

from ..config import settings

# service -> (cname substrings, response body fingerprint)
FINGERPRINTS: list[tuple[str, tuple[str, ...], str]] = [
    ("GitHub Pages", (".github.io",), "There isn't a GitHub Pages site here"),
    ("AWS S3", (".amazonaws.com", "s3-website"), "NoSuchBucket"),
    ("Heroku", (".herokuapp.com", ".herokudns.com"), "No such app"),
    ("Shopify", (".myshopify.com",), "Sorry, this shop is currently unavailable"),
    ("Fastly", (".fastly.net",), "Fastly error: unknown domain"),
    ("Surge.sh", (".surge.sh",), "project not found"),
    ("Bitbucket", (".bitbucket.io",), "Repository not found"),
    ("Ghost", (".ghost.io",), "The thing you were looking for is no longer here"),
    ("Zendesk", (".zendesk.com",), "Help Center Closed"),
    ("Unbounce", (".unbouncepages.com",), "The requested URL was not found on this server"),
    ("Readme.io", (".readme.io",), "Project doesnt exist"),
    ("Tilda", (".tilda.ws",), "Please renew your subscription"),
    ("Pantheon", (".pantheonsite.io",), "The gods are wise, but do not know of the site"),
    ("Wordpress", (".wordpress.com",), "Do you want to register"),
    ("Azure", (".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net",
               ".blob.core.windows.net"), "404 Web Site not found"),
    ("Netlify", (".netlify.app", ".netlify.com"), "Not Found - Request ID"),
    ("Cargo", (".cargocollective.com",), "404 Not Found"),
    ("Help Scout", (".helpscoutdocs.com",), "No settings were found for this company"),
]


def _match_service(cname: str) -> tuple[str, str] | None:
    cl = (cname or "").lower()
    if not cl:
        return None
    for service, subs, fp in FINGERPRINTS:
        if any(s in cl for s in subs):
            return service, fp
    return None


async def check(resolved: dict) -> list[dict]:
    """resolved: {host: {'ips':[...], 'cname': str, ...}}.
    Returns potential-takeover findings."""
    candidates = []
    for host, d in resolved.items():
        m = _match_service(d.get("cname", ""))
        if m:
            candidates.append((host, d.get("cname", ""), *m))
    if not candidates:
        return []

    findings: list[dict] = []
    sem = asyncio.Semaphore(settings.http_concurrency)
    async with httpx.AsyncClient(timeout=settings.http_timeout, verify=False,
                                 headers={"User-Agent": settings.user_agent}) as client:
        async def probe(host, cname, service, fp):
            body = ""
            for scheme in ("https", "http"):
                try:
                    r = await client.get(f"{scheme}://{host}", follow_redirects=True)
                    body = r.text[:100000]
                    break
                except Exception:
                    continue
            confirmed = fp.lower() in body.lower()
            # Report matches; "confirmed" when the fingerprint body is present.
            findings.append({
                "host": host, "service": service, "cname": cname,
                "severity": "high" if confirmed else "info",
                "confirmed": confirmed,
                "evidence": f"CNAME->{cname}; fingerprint {'MATCHED' if confirmed else 'not found (verify manually)'}",
            })

        async def one(c):
            async with sem:
                await probe(*c)

        await asyncio.gather(*(one(c) for c in candidates))
    return findings
