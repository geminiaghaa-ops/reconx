"""Content & API discovery.

Expands the attack surface beyond what crawling finds:
  * directory/file brute-force over a wordlist (baseline-filtered so catch-all
    200 pages don't create noise)
  * sensitive-file exposure (.git, .env, backups, actuator, phpinfo, …)
  * API discovery: Swagger/OpenAPI docs and GraphQL introspection

Preferred external tools: ffuf / feroxbuster (dir brute). Fallback: a
concurrency-limited async fuzzer. Everything runs auth-aware and in-scope only.
"""
from __future__ import annotations

import asyncio
import random
import string
from pathlib import Path
from urllib.parse import urljoin

from ..config import settings
from ..auth import NO_AUTH

DATA = Path(__file__).parent.parent / "data"

SENSITIVE = {
    ".git/HEAD": ("high", "exposed .git repository"),
    ".git/config": ("high", "exposed .git config"),
    ".env": ("high", "exposed .env (often holds secrets)"),
    ".env.local": ("high", "exposed .env.local"),
    ".env.production": ("high", "exposed .env.production"),
    ".DS_Store": ("low", "exposed .DS_Store (dir listing)"),
    ".svn/entries": ("medium", "exposed .svn"),
    ".htaccess": ("medium", "exposed .htaccess"),
    "web.config": ("medium", "exposed web.config"),
    "phpinfo.php": ("medium", "phpinfo exposed"),
    "server-status": ("medium", "Apache server-status exposed"),
    "actuator/env": ("high", "Spring Actuator env exposed"),
    "actuator/health": ("low", "Spring Actuator exposed"),
    "wp-config.php.bak": ("high", "WordPress config backup"),
    "config.php.bak": ("high", "config backup"),
    "backup.zip": ("high", "backup archive exposed"),
    "backup.sql": ("high", "database backup exposed"),
    "dump.sql": ("high", "database dump exposed"),
    ".well-known/security.txt": ("info", "security.txt present"),
}

API_PATHS = {
    "swagger.json": "Swagger/OpenAPI spec",
    "openapi.json": "OpenAPI spec",
    "v2/api-docs": "Swagger v2 docs",
    "v3/api-docs": "OpenAPI v3 docs",
    "swagger/v1/swagger.json": "Swagger spec",
    "api-docs": "API docs",
    "swagger-ui.html": "Swagger UI",
    "graphiql": "GraphiQL console",
}

_GQL_INTROSPECT = '{"query":"{__schema{queryType{name}}}"}'


def _wordlist() -> list[str]:
    try:
        return [l.strip().lstrip("/") for l in (DATA / "content.txt").read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    except Exception:
        return []


def _rand() -> str:
    return "".join(random.choices(string.ascii_lowercase, k=16))


async def _baseline(base: str, client) -> tuple[int, int]:
    """Fetch a random path to learn the catch-all response (status, length)."""
    try:
        r = await client.get(urljoin(base + "/", _rand() + "xyz123"), follow_redirects=False)
        return r.status_code, len(r.content)
    except Exception:
        return 404, 0


async def discover(live_urls: list[str], auth=None, scope=None, per_host_cap: int = 8) -> dict:
    """Return {'urls': [...discovered paths...], 'findings': [...]}.
    findings: {url, kind, name, severity, note}."""
    auth = auth or NO_AUTH
    # Always probe the sensitive-file and API paths too, not just the wordlist.
    words = list(dict.fromkeys(_wordlist() + list(SENSITIVE) + list(API_PATHS)))
    discovered: set[str] = set()
    findings: list[dict] = []
    # limit how many hosts we brute (dir brute is heavy); prefer https roots
    hosts = [u for u in live_urls][: max(1, per_host_cap)]

    async with auth.client(scope=scope, timeout=settings.http_timeout) as client:
        sem = asyncio.Semaphore(settings.http_concurrency)

        async def check(base: str, path: str, baseline: tuple[int, int]):
            url = urljoin(base + "/", path)
            async with sem:
                try:
                    r = await client.get(url, follow_redirects=False)
                except Exception:
                    return
            st, ln = r.status_code, len(r.content)
            if st == 404:
                return
            # skip catch-all matches (same status & similar length as baseline)
            if st == baseline[0] and abs(ln - baseline[1]) < 48:
                return
            if st in (200, 201, 202, 204, 301, 302, 307, 401, 403, 405, 500):
                discovered.add(url)
                if path in SENSITIVE and st in (200, 206):
                    sev, note = SENSITIVE[path]
                    findings.append({"url": url, "kind": "exposure", "name": path,
                                     "severity": sev, "note": note})
                if path in API_PATHS and st in (200, 401, 403):
                    findings.append({"url": url, "kind": "api", "name": path,
                                     "severity": "low", "note": API_PATHS[path]})

        for base in hosts:
            baseline = await _baseline(base, client)
            await asyncio.gather(*(check(base, p, baseline) for p in words))

            # GraphQL introspection
            for gp in ("graphql", "api/graphql", "v1/graphql"):
                gurl = urljoin(base + "/", gp)
                try:
                    r = await client.post(gurl, content=_GQL_INTROSPECT,
                                           headers={"Content-Type": "application/json"})
                    if r.status_code == 200 and "__schema" in r.text:
                        findings.append({"url": gurl, "kind": "api", "name": "graphql",
                                         "severity": "medium", "note": "GraphQL introspection enabled"})
                        discovered.add(gurl)
                except Exception:
                    pass

    return {"urls": sorted(discovered), "findings": findings}
