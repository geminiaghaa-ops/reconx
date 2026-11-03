"""Target health monitor.

This runs continuously alongside a scan. Its job during bug bounty is twofold:
  1. Safety / politeness: if our scanning degrades or knocks the target over,
     we must notice immediately and back off. The pipeline consults
     `HealthMonitor.state` before every heavy stage and pauses while a target
     is 'degraded' or 'down'.
  2. Signal: an endpoint that flaps or returns 5xx under light load is itself
     interesting, and it's recorded for review.

A simple circuit-breaker drives the state:
  healthy  -> (fail_threshold consecutive failures OR sustained slowness) -> degraded/down
  down     -> (recover_threshold consecutive OKs) -> healthy
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import httpx

from ..config import settings
from ..db import get_db


@dataclass
class HostHealth:
    host: str
    up: bool = True
    state: str = "unknown"          # unknown|healthy|degraded|down
    consecutive_fail: int = 0
    consecutive_ok: int = 0
    last_ms: float = 0.0
    avg_ms: float = 0.0
    samples: int = 0
    baseline_ms: float | None = None


@dataclass
class HealthMonitor:
    target_id: int
    hosts: list[str] = field(default_factory=list)
    _task: asyncio.Task | None = None
    _stop: asyncio.Event = field(default_factory=asyncio.Event)
    health: dict[str, HostHealth] = field(default_factory=dict)
    on_event: callable = None  # optional callback(host, old_state, new_state)

    def set_hosts(self, hosts: list[str]) -> None:
        for h in hosts:
            h = h.strip().lower()
            if h and h not in self.health:
                self.health[h] = HostHealth(host=h)
        self.hosts = list(self.health.keys())

    @property
    def state(self) -> str:
        """Worst state across all monitored hosts -> gate for the pipeline."""
        order = {"down": 3, "degraded": 2, "healthy": 1, "unknown": 0}
        worst = "healthy"
        seen = False
        for hh in self.health.values():
            seen = True
            if order.get(hh.state, 0) > order.get(worst, 0):
                worst = hh.state
        return worst if seen else "unknown"

    def healthy(self) -> bool:
        return self.state in ("healthy", "unknown")

    async def _check_one(self, client: httpx.AsyncClient, hh: HostHealth) -> None:
        candidates = ([hh.host] if hh.host.startswith("http")
                      else [f"https://{hh.host}", f"http://{hh.host}"])
        start = time.perf_counter()
        up, status = False, None
        for url in candidates:
            try:
                r = await client.get(url, follow_redirects=True)
                status = r.status_code
                up = status < 500
                break
            except Exception:
                continue
        ms = (time.perf_counter() - start) * 1000.0

        hh.last_ms = ms
        hh.samples += 1
        hh.avg_ms = ms if hh.samples == 1 else (hh.avg_ms * 0.7 + ms * 0.3)
        if hh.baseline_ms is None and up and hh.samples >= 2:
            hh.baseline_ms = hh.avg_ms

        slow = ms > settings.health_slow_ms or (
            hh.baseline_ms and ms > max(settings.health_slow_ms, hh.baseline_ms * 4)
        )

        old = hh.state
        if up and not slow:
            hh.consecutive_ok += 1
            hh.consecutive_fail = 0
            if hh.consecutive_ok >= settings.health_recover_threshold or old == "unknown":
                hh.state = "healthy"
                hh.up = True
        else:
            hh.consecutive_fail += 1
            hh.consecutive_ok = 0
            if not up and hh.consecutive_fail >= settings.health_fail_threshold:
                hh.state = "down"
                hh.up = False
            elif slow or hh.consecutive_fail >= 1:
                hh.state = "degraded"

        get_db().add_uptime(self.target_id, hh.host, hh.up, status, round(ms, 1))
        if old != hh.state and self.on_event:
            try:
                self.on_event(hh.host, old, hh.state)
            except Exception:
                pass

    async def _loop(self) -> None:
        async with httpx.AsyncClient(
            timeout=settings.health_timeout if hasattr(settings, "health_timeout") else 10,
            headers={"User-Agent": settings.user_agent},
            verify=False,
        ) as client:
            while not self._stop.is_set():
                if self.health:
                    await asyncio.gather(*(self._check_one(client, hh) for hh in list(self.health.values())))
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=settings.health_interval_s)
                except asyncio.TimeoutError:
                    pass

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()

    async def wait_until_healthy(self, max_wait: float = 120) -> bool:
        """Block (up to max_wait) while the target is unhealthy, so heavy
        stages don't pile load onto a struggling server."""
        waited = 0.0
        step = max(2, settings.health_interval_s)
        while not self.healthy() and waited < max_wait:
            await asyncio.sleep(step)
            waited += step
        return self.healthy()
