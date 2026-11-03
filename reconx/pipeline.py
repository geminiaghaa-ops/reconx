"""Recon pipeline orchestrator.

Wires the stages together for one target, enforcing scope at every boundary and
consulting the health monitor before each heavy stage so we never pile load on
a struggling target. Results stream into SQLite; new assets trigger notifications.

Stages:
  1. subdomains   -> assets(kind=subdomain)
  2. http probe   -> http_services        [health-gated]
  3. crawl        -> assets(kind=url) + JS list   [health-gated]
  4. js analysis  -> js_findings
  5. nuclei       -> findings              [health-gated]
"""
from __future__ import annotations

import asyncio
import time

from .config import settings
from .db import get_db
from .scope import Scope
from . import notify, tools
from .modules import subdomains, http_probe, crawl, jsanalysis, nuclei_scan
from .modules.uptime import HealthMonitor


class Pipeline:
    def __init__(self, target_id: int, run_nuclei: bool = True):
        self.db = get_db()
        self.target_id = target_id
        self.t = self.db.get_target(target_id)
        self.scope = Scope(self.t["domain"], self.t["scope_in"], self.t["scope_out"])
        self.run_id = self.db.create_run(target_id)
        self.monitor = HealthMonitor(target_id=target_id, on_event=self._health_event)
        self.run_nuclei = run_nuclei
        self.stats: dict = {}

    # -- helpers ---------------------------------------------------------
    def log(self, msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        self.db.append_log(self.run_id, line)

    def _health_event(self, host: str, old: str, new: str) -> None:
        self.db.set_health(self.target_id, self.monitor.state)
        self.log(f"HEALTH {host}: {old} -> {new}")
        if new in ("down", "degraded"):
            asyncio.create_task(notify.send(
                f":warning: ReconX: {host} is {new.upper()} during scan of {self.t['domain']} — backing off."
            ))

    async def _gate(self, stage: str) -> None:
        """Pause a heavy stage while the target is unhealthy."""
        self.db.set_health(self.target_id, self.monitor.state)
        if not self.monitor.healthy():
            self.log(f"PAUSE before {stage}: target {self.monitor.state}; waiting to recover")
            self.db.update_run(self.run_id, status="paused", stage=f"paused:{stage}")
            ok = await self.monitor.wait_until_healthy(max_wait=180)
            self.db.update_run(self.run_id, status="running")
            self.log(f"RESUME {stage}: healthy={ok} (state={self.monitor.state})")

    # -- main ------------------------------------------------------------
    async def run(self) -> None:
        self.db.update_run(self.run_id, status="running", started_at=time.time())
        self.log(f"Start recon for {self.t['domain']}")
        avail = tools.availability()
        self.log(f"Toolchain: " + ", ".join(
            f"{s}:{','.join(k for k,v in d.items() if v) or 'builtin'}" for s, d in avail.items()))

        try:
            # 1. subdomains
            self.db.update_run(self.run_id, stage="subdomains")
            sd = await subdomains.enumerate(self.t["domain"])
            subs = self.scope.filter(sd["subdomains"])
            new_subs = [s for s in subs if self.db.upsert_asset(self.target_id, "subdomain", s, {"source": sd["source"]})]
            self.stats["subdomains"] = len(subs)
            self.stats["new_subdomains"] = len(new_subs)
            self.log(f"subdomains: {len(subs)} in-scope ({len(new_subs)} new) via {sd['source']}")
            if new_subs:
                await notify.send(f"ReconX {self.t['domain']}: {len(new_subs)} new subdomains")

            # start health monitoring on discovered hosts
            self.monitor.set_hosts(subs or [self.t["domain"]])
            self.monitor.start()
            await asyncio.sleep(1)

            # 2. http probe
            await self._gate("http-probe")
            self.db.update_run(self.run_id, stage="http-probe")
            services = await http_probe.probe(subs or [self.t["domain"]])
            services = [s for s in services if self.scope.in_scope(s["url"])]
            for s in services:
                self.db.upsert_http(self.target_id, **s)
            live = [s["url"] for s in services]
            self.stats["http_services"] = len(live)
            self.log(f"http: {len(live)} live services")
            self.monitor.set_hosts(live or subs)

            # 3. crawl
            await self._gate("crawl")
            self.db.update_run(self.run_id, stage="crawl")
            crawled = await crawl.crawl(live)
            urls = self.scope.filter(crawled["urls"])
            js = self.scope.filter(crawled["js"])
            for u in urls:
                self.db.upsert_asset(self.target_id, "url", u)
            self.stats["urls"] = len(urls)
            self.stats["js_files"] = len(js)
            self.log(f"crawl: {len(urls)} urls, {len(js)} js files")

            # 4. js analysis
            self.db.update_run(self.run_id, stage="js-analysis")
            jsf = await jsanalysis.analyze(js)
            njs = 0
            for f in jsf:
                if self.db.add_js_finding(self.target_id, f["source_url"], f["kind"],
                                          f["value"], f.get("name", ""), f.get("severity", "info"),
                                          f.get("context", "")):
                    njs += 1
            self.stats["js_findings"] = njs
            hi = [f for f in jsf if f.get("severity") in ("high", "critical")]
            self.log(f"js: {njs} findings ({len(hi)} high/critical)")
            if hi:
                await notify.send(f":rotating_light: ReconX {self.t['domain']}: {len(hi)} high-severity JS findings (secrets/libs)")

            # 5. nuclei
            if self.run_nuclei and tools.which("nuclei"):
                await self._gate("nuclei")
                self.db.update_run(self.run_id, stage="nuclei")
                nf = await nuclei_scan.scan(live)
                nn = 0
                for f in nf:
                    if self.db.add_finding(self.target_id, "nuclei", f["template"], f["name"],
                                           f["severity"], f["matched_at"], f["info"]):
                        nn += 1
                self.stats["findings"] = nn
                crit = [f for f in nf if f["severity"] in ("high", "critical")]
                self.log(f"nuclei: {nn} findings ({len(crit)} high/critical)")
                if crit:
                    await notify.send(f":rotating_light: ReconX {self.t['domain']}: {len(crit)} high/critical nuclei findings")
            else:
                self.log("nuclei: skipped (not installed or disabled)")

            self.db.update_run(self.run_id, status="done", stage="done",
                               finished_at=time.time(), stats=_json(self.stats))
            self.log("Recon complete.")
        except Exception as e:  # noqa: BLE001
            self.db.update_run(self.run_id, status="error", finished_at=time.time())
            self.log(f"ERROR: {e!r}")
            raise
        finally:
            await self.monitor.stop()
            self.db.set_health(self.target_id, self.monitor.state)


def _json(d: dict) -> str:
    import json
    return json.dumps(d)


async def run_target(target_id: int, run_nuclei: bool = True) -> int:
    p = Pipeline(target_id, run_nuclei=run_nuclei)
    await p.run()
    return p.run_id
