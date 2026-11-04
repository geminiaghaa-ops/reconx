"""Recon pipeline orchestrator.

Phase 1 = attack-surface mapping. Stages, in order (scope enforced at every
boundary; health-gated stages marked [G]):

  1. subdomains        -> assets(subdomain)
  2. dns resolve       -> resolved hosts (A + CNAME) + wildcard detection
  3. port scan         -> assets(port) + extra candidate URLs
  4. http probe (+WAF) -> http_services                               [G]
  5. takeover          -> findings(engine=takeover)
  6. screenshot        -> http_services.screenshot                    [G]
  7. crawl             -> assets(url) + JS list                       [G]
  8. js analysis       -> js_findings
  9. nuclei            -> findings                                    [G]

The health monitor runs in the background from stage 2 on; heavy stages pause
only if a target was healthy and then degraded under our load.
"""
from __future__ import annotations

import asyncio
import json
import time

from .config import settings
from .db import get_db
from .scope import Scope
from . import notify, tools
from .modules import (subdomains, dns_resolve, ports as portscan, http_probe,
                      takeover, screenshot, crawl, jsanalysis, nuclei_scan)
from .modules.uptime import HealthMonitor


def _json(d: dict) -> str:
    return json.dumps(d)


class Pipeline:
    def __init__(self, target_id: int, run_nuclei: bool = True, run_screenshot: bool = True):
        self.db = get_db()
        self.target_id = target_id
        self.t = self.db.get_target(target_id)
        self.scope = Scope(self.t["domain"], self.t["scope_in"], self.t["scope_out"])
        self.apex = self.t["domain"]
        self.run_id = self.db.create_run(target_id)
        self.monitor = HealthMonitor(target_id=target_id, on_event=self._health_event)
        self.run_nuclei = run_nuclei
        self.run_screenshot = run_screenshot
        self.stats: dict = {}

    def log(self, msg: str) -> None:
        self.db.append_log(self.run_id, f"[{time.strftime('%H:%M:%S')}] {msg}")

    def _begin(self, display: str, plan_key: str = "") -> None:
        """Mark a stage as started and log which engine it uses, so the live log
        shows what's happening *before* the stage finishes."""
        self._stage_t0 = time.time()
        self.db.update_run(self.run_id, stage=display)
        eng = getattr(self, "engines", {}).get(plan_key, "")
        self.log(f"▶ {display}" + (f"  —  via {eng}" if eng else "") + " …")

    def _took(self) -> str:
        return f"{time.time() - getattr(self, '_stage_t0', time.time()):.1f}s"

    def _representative_hosts(self, live_urls: list[str]) -> list[str]:
        """Pick a few canonical hosts to health-monitor (apex / www over https).

        We must NOT monitor every discovered service: alt-port / cPanel / plain
        HTTP endpoints behind a WAF are often flaky, and letting one of them flip
        to 'down' would pause the whole scan. The apex is the real 'is the target
        up' signal."""
        from urllib.parse import urlparse
        apex = self.apex
        want = {f"https://{apex}", f"https://www.{apex}",
                f"http://{apex}", f"http://www.{apex}"}
        reps = [u for u in live_urls if u in want]
        if not reps:
            roots = [u for u in live_urls
                     if not urlparse(u).port and urlparse(u).path in ("", "/")]
            reps = roots[:3] or live_urls[:3]
        return reps[:4]

    def _health_event(self, host: str, old: str, new: str) -> None:
        self.db.set_health(self.target_id, self.monitor.state)
        self.log(f"HEALTH {host}: {old} -> {new}")
        if new in ("down", "degraded"):
            asyncio.create_task(notify.send(
                f":warning: ReconX: {host} is {new.upper()} during scan of {self.t['domain']} — backing off."))

    async def _gate(self, stage: str) -> None:
        self.db.set_health(self.target_id, self.monitor.state)
        if self.monitor.healthy():
            return
        if self.monitor.ever_healthy:
            self.log(f"PAUSE before {stage}: target {self.monitor.state}; backing off to let it recover")
            self.db.update_run(self.run_id, status="paused", stage=f"paused:{stage}")
            ok = await self.monitor.wait_until_healthy(max_wait=180)
            self.db.update_run(self.run_id, status="running")
            self.log(f"RESUME {stage}: healthy={ok} (state={self.monitor.state})")
        else:
            self.log(f"NOTE before {stage}: target not reachable yet (state={self.monitor.state}); continuing")

    async def run(self) -> None:
        self.db.update_run(self.run_id, status="running", started_at=time.time())
        self.log(f"Start recon for {self.t['domain']}")
        plan = await tools.plan()
        self.engines = {r["stage"]: r["engine"] for r in plan}
        self.log("── Execution plan (engine per stage) ──")
        for r in plan:
            mark = "[tool]    " if r["using_tool"] else ("[built-in]" if "DISABLED" not in r["engine"] else "[off]     ")
            self.log(f"   {r['stage']:11s} {mark} {r['engine']}")
            if r["note"]:
                self.log(f"               ! {r['note']}")
        miss = sorted({t for r in plan for t in r["missing"]})
        if miss:
            self.log(f"Not installed, using fallbacks: {', '.join(miss)}  (run `python cli.py tools` for install commands)")
        self.log("───────────────────────────────────────")

        try:
            # 1. subdomains
            self._begin("subdomains", "subdomains")
            sd = await subdomains.enumerate(self.apex)
            subs = self.scope.filter(sd["subdomains"])
            new_subs = [s for s in subs if self.db.upsert_asset(self.target_id, "subdomain", s, {"source": sd["source"]})]
            self.stats["subdomains"] = len(subs)
            self.stats["new_subdomains"] = len(new_subs)
            self.log(f"✓ subdomains: {len(subs)} in-scope ({len(new_subs)} new) via {sd['source']} [{self._took()}]")
            if new_subs:
                await notify.send(f"ReconX {self.apex}: {len(new_subs)} new subdomains")
            subs = subs or [self.apex]

            # 2. dns resolve + wildcard
            self._begin("dns-resolve", "dns")
            dns = await dns_resolve.resolve(subs, self.apex)
            resolved = dns["resolved"]
            live_hosts = [h for h in dns["live_hosts"] if self.scope.in_scope(h)] or subs
            for h, d in resolved.items():
                self.db.upsert_asset(self.target_id, "subdomain", h,
                                     {"ips": d["ips"], "cname": d["cname"], "wildcard": d["wildcard"]})
            self.stats["resolved"] = len(resolved)
            self.stats["wildcard"] = len(dns["wildcard_ips"])
            self.log(f"✓ dns: {len(resolved)} resolved, wildcard_ips={len(dns['wildcard_ips'])} [{self._took()}]")

            # start health monitoring on a few canonical hosts (not every one)
            mon0 = [h for h in live_hosts if h in (self.apex, f"www.{self.apex}")] or live_hosts[:3]
            self.monitor.set_hosts(mon0)
            self.monitor.start()
            await asyncio.sleep(1)

            # 3. port scan
            self._begin("ports", "ports")
            port_map = await portscan.scan(live_hosts)
            extra_urls: list[str] = []
            n_ports = 0
            for h, plist in port_map.items():
                n_ports += len(plist)
                self.db.upsert_asset(self.target_id, "port", h, {"ports": plist})
                extra_urls += portscan.ports_to_urls(h, plist)
            self.stats["open_ports"] = n_ports
            self.log(f"✓ ports: {n_ports} open across {len(port_map)} hosts [{self._took()}]")

            # 4. http probe (+ WAF/CDN)
            await self._gate("http-probe")
            self._begin("http-probe", "http")
            probe_targets = sorted(set(live_hosts) | {u for u in extra_urls if self.scope.in_scope(u)})
            services = await http_probe.probe(probe_targets)
            services = [s for s in services if self.scope.in_scope(s["url"])]
            for s in services:
                self.db.upsert_http(self.target_id, **s)
            live = [s["url"] for s in services]
            self.stats["http_services"] = len(live)
            waffed = sum(1 for s in services if s.get("waf") or s.get("cdn"))
            self.log(f"✓ http: {len(live)} live services ({waffed} behind WAF/CDN) [{self._took()}]")
            if not live:
                self.log("No live HTTP services found — nothing more to scan. "
                         "Check the domain is correct, in-scope, and reachable from this host.")
                self.db.update_run(self.run_id, status="done", stage="done",
                                   finished_at=time.time(), stats=_json(self.stats))
                self.log("Recon complete.")
                return
            reps = self._representative_hosts(live)
            self.monitor.set_hosts(reps)
            self.log(f"health monitor watching {len(reps)} representative host(s): {', '.join(reps)}")

            # 5. subdomain takeover
            self._begin("takeover")
            tk = await takeover.check(resolved)
            nt = 0
            for f in tk:
                if self.db.add_finding(self.target_id, "takeover", f["service"], f["evidence"],
                                       f["severity"], f["host"], {"cname": f["cname"], "confirmed": f["confirmed"]}):
                    nt += 1
            self.stats["takeover"] = nt
            conf = [f for f in tk if f["confirmed"]]
            self.log(f"✓ takeover: {len(tk)} candidates ({len(conf)} fingerprint-confirmed) [{self._took()}]")
            if conf:
                await notify.send(f":rotating_light: ReconX {self.apex}: {len(conf)} likely subdomain takeover(s)!")

            # 6. screenshot
            if self.run_screenshot and (tools.which("gowitness") or screenshot.find_chrome()):
                await self._gate("screenshot")
                self._begin("screenshot", "screenshot")
                shots = await screenshot.capture(live, settings.artifacts_dir / f"shots_{self.target_id}")
                for url, path in shots.items():
                    self.db.set_screenshot(self.target_id, url, path)
                self.stats["screenshots"] = len(shots)
                self.log(f"✓ screenshot: captured {len(shots)}/{len(live)} [{self._took()}]")
            else:
                self.log("screenshot: skipped (no gowitness/chrome)")

            # 7. crawl
            await self._gate("crawl")
            self._begin("crawl", "crawl")
            crawled = await crawl.crawl(live)
            urls = self.scope.filter(crawled["urls"])
            js = self.scope.filter(crawled["js"])
            for u in urls:
                self.db.upsert_asset(self.target_id, "url", u)
            self.stats["urls"] = len(urls)
            self.stats["js_files"] = len(js)
            self.log(f"✓ crawl: {len(urls)} urls, {len(js)} js files [{self._took()}]")

            # 8. js analysis
            self._begin("js-analysis", "js")
            jsf = await jsanalysis.analyze(js)
            njs = 0
            for f in jsf:
                if self.db.add_js_finding(self.target_id, f["source_url"], f["kind"], f["value"],
                                          f.get("name", ""), f.get("severity", "info"), f.get("context", "")):
                    njs += 1
            self.stats["js_findings"] = njs
            hi = [f for f in jsf if f.get("severity") in ("high", "critical")]
            self.log(f"✓ js: {njs} findings ({len(hi)} high/critical) [{self._took()}]")
            if hi:
                await notify.send(f":rotating_light: ReconX {self.apex}: {len(hi)} high-severity JS findings")

            # 9. nuclei
            if self.run_nuclei and tools.which("nuclei"):
                await self._gate("nuclei")
                self._begin("nuclei", "vuln")
                nf = await nuclei_scan.scan(live)
                nn = 0
                for f in nf:
                    if self.db.add_finding(self.target_id, "nuclei", f["template"], f["name"],
                                           f["severity"], f["matched_at"], f["info"]):
                        nn += 1
                self.stats["findings"] = nn
                crit = [f for f in nf if f["severity"] in ("high", "critical")]
                self.log(f"✓ nuclei: {nn} findings ({len(crit)} high/critical) [{self._took()}]")
                if crit:
                    await notify.send(f":rotating_light: ReconX {self.apex}: {len(crit)} high/critical nuclei findings")
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


async def run_target(target_id: int, run_nuclei: bool = True, run_screenshot: bool = True) -> int:
    p = Pipeline(target_id, run_nuclei=run_nuclei, run_screenshot=run_screenshot)
    await p.run()
    return p.run_id
