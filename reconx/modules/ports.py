"""Port scanning.

Most interesting bug-bounty surface isn't on 80/443 — dev panels, admin UIs and
forgotten services hide on 8080/8443/3000/9000/etc. This stage finds open ports
so http-probing can target them, not just the web defaults.

Preferred: naabu (ProjectDiscovery). Fallback: a concurrency-limited async TCP
connect scan over a curated top-ports list.
"""
from __future__ import annotations

import asyncio

from ..config import settings
from .. import tools

# Curated "interesting" ports: web defaults + common alt-web/admin/dev/service.
TOP_PORTS = [
    80, 443, 8080, 8443, 8000, 8008, 8888, 8081, 8082, 8090, 3000, 5000, 9000,
    9090, 9200, 9443, 7001, 7070, 4443, 10000, 2082, 2083, 2086, 2087, 2095,
    2096, 8880, 8889, 3306, 5432, 6379, 27017, 11211, 21, 22, 23, 25, 53, 110,
    143, 445, 993, 995, 1433, 1521, 3389, 5900, 161, 8443, 8834, 8161, 15672,
]


async def _check(host: str, port: int, sem: asyncio.Semaphore, timeout: float) -> int | None:
    async with sem:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port
        except Exception:
            return None


async def scan(hosts: list[str], ports: list[int] | None = None,
               timeout: float = 2.5, concurrency: int = 300) -> dict:
    """Return {host: [open_ports]} for hosts with >=1 open port."""
    hosts = [h for h in {h.strip().lower() for h in hosts} if h]
    if not hosts:
        return {}
    ports = sorted(set(ports or TOP_PORTS))

    # Preferred: naabu.
    if tools.which("naabu"):
        plist = ",".join(str(p) for p in ports)
        res = await tools.run(["naabu", "-silent", "-json", "-p", plist],
                              stdin="\n".join(hosts), timeout=900)
        out: dict[str, list[int]] = {}
        for obj in tools.parse_jsonl(res.lines):
            h = (obj.get("host") or obj.get("ip") or "").lower()
            p = obj.get("port")
            if h and p:
                out.setdefault(h, []).append(int(p))
        if out:
            return {h: sorted(set(ps)) for h, ps in out.items()}

    # Fallback: async TCP connect scan.
    sem = asyncio.Semaphore(concurrency)
    tasks = {(h, p): _check(h, p, sem, timeout) for h in hosts for p in ports}
    results = await asyncio.gather(*tasks.values())
    out: dict[str, list[int]] = {}
    for (h, p), r in zip(tasks.keys(), results):
        if r is not None:
            out.setdefault(h, []).append(p)
    return {h: sorted(ps) for h, ps in out.items()}


def ports_to_urls(host: str, open_ports: list[int]) -> list[str]:
    """Map open ports to candidate URLs for http-probing."""
    urls = []
    https_ports = {443, 8443, 9443, 4443, 2083, 2087, 2096, 8834, 10000}
    for p in open_ports:
        if p in https_ports:
            urls.append(f"https://{host}:{p}" if p != 443 else f"https://{host}")
        elif p in (80,):
            urls.append(f"http://{host}")
        elif p in (8080, 8000, 8008, 8888, 8081, 8082, 8090, 3000, 5000, 9000,
                   9090, 8880, 8889, 8161, 15672, 7001, 7070, 2082, 2086, 2095):
            urls.append(f"http://{host}:{p}")
    return urls
