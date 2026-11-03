"""FastAPI web dashboard + JSON API.

Serves a single-page dashboard and exposes endpoints to add targets, launch
scans, and read results (assets, services, JS findings, vuln findings, and the
live health timeline).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from ..db import get_db
from ..tools import availability
from ..pipeline import run_target
from ..util import normalize_target

BASE = Path(__file__).parent
app = FastAPI(title="ReconX", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

# in-process scan jobs: target_id -> asyncio.Task
_jobs: dict[int, asyncio.Task] = {}


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(str(BASE / "templates" / "index.html"))


@app.get("/api/tools")
async def api_tools():
    return availability()


@app.get("/api/targets")
async def api_targets():
    db = get_db()
    out = []
    for t in db.list_targets():
        c = db.counts(t["id"])
        run = db.latest_run(t["id"])
        out.append({**t, "counts": c,
                    "scan_status": (run or {}).get("status"),
                    "scan_stage": (run or {}).get("stage"),
                    "running": t["id"] in _jobs and not _jobs[t["id"]].done()})
    return out


@app.post("/api/targets")
async def api_add_target(payload: dict):
    raw = payload.get("domain") or ""
    domain = normalize_target(raw)
    if not domain:
        raise HTTPException(400, "a valid domain or URL is required")
    db = get_db()
    tid = db.add_target(domain, payload.get("scope_in", ""), payload.get("scope_out", ""))
    return {"id": tid, "domain": domain, "normalized_from": raw if raw.strip() != domain else None}


@app.post("/api/targets/{target_id}/scan")
async def api_scan(target_id: int, payload: dict | None = None):
    db = get_db()
    if not db.get_target(target_id):
        raise HTTPException(404, "target not found")
    if target_id in _jobs and not _jobs[target_id].done():
        raise HTTPException(409, "scan already running")
    run_nuclei = True if payload is None else bool(payload.get("nuclei", True))

    async def _job():
        try:
            await run_target(target_id, run_nuclei=run_nuclei)
        finally:
            _jobs.pop(target_id, None)

    _jobs[target_id] = asyncio.create_task(_job())
    return {"status": "started", "target_id": target_id}


@app.get("/api/targets/{target_id}")
async def api_target_detail(target_id: int):
    db = get_db()
    t = db.get_target(target_id)
    if not t:
        raise HTTPException(404, "target not found")
    run = db.latest_run(target_id)
    return {
        "target": t,
        "counts": db.counts(target_id),
        "run": run,
        "running": target_id in _jobs and not _jobs[target_id].done(),
        "subdomains": db.query(
            "SELECT value, is_new, first_seen FROM assets WHERE target_id=? AND kind='subdomain' ORDER BY is_new DESC, value",
            (target_id,)),
        "services": db.query(
            "SELECT url,status,title,tech,webserver,ip FROM http_services WHERE target_id=? ORDER BY status", (target_id,)),
        "js_findings": db.query(
            "SELECT source_url,kind,name,value,severity,context FROM js_findings WHERE target_id=? "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END", (target_id,)),
        "findings": db.query(
            "SELECT engine,template,name,severity,matched_at FROM findings WHERE target_id=? "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END", (target_id,)),
    }


@app.get("/api/targets/{target_id}/health")
async def api_health(target_id: int):
    db = get_db()
    rows = db.query(
        "SELECT host,up,status,response_ms,checked_at FROM uptime_checks WHERE target_id=? "
        "ORDER BY checked_at DESC LIMIT 200", (target_id,))
    t = db.get_target(target_id)
    return {"health": (t or {}).get("health"), "checks": list(reversed(rows))}


@app.get("/api/targets/{target_id}/log")
async def api_log(target_id: int):
    db = get_db()
    run = db.latest_run(target_id)
    return {"log": (run or {}).get("log", ""), "status": (run or {}).get("status"),
            "stage": (run or {}).get("stage")}


def run_server(host: str = "127.0.0.1", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")
