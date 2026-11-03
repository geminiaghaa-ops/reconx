"""SQLite persistence layer.

A thin, dependency-free wrapper. All recon output is stored so results can be
queried, diffed between runs, and served to the dashboard. Thread-safe via a
per-call connection (check_same_thread=False + WAL).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from .config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT UNIQUE NOT NULL,
    scope_in    TEXT DEFAULT '',
    scope_out   TEXT DEFAULT '',
    created_at  REAL NOT NULL,
    health      TEXT DEFAULT 'unknown'   -- unknown|healthy|degraded|down
);

CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    kind        TEXT NOT NULL,           -- subdomain|host|url|port
    value       TEXT NOT NULL,
    meta        TEXT DEFAULT '{}',
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    is_new      INTEGER DEFAULT 1,
    UNIQUE(target_id, kind, value)
);

CREATE TABLE IF NOT EXISTS http_services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    url         TEXT NOT NULL,
    status      INTEGER,
    title       TEXT DEFAULT '',
    tech        TEXT DEFAULT '',
    webserver   TEXT DEFAULT '',
    ip          TEXT DEFAULT '',
    content_len INTEGER DEFAULT 0,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    UNIQUE(target_id, url)
);

CREATE TABLE IF NOT EXISTS js_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    source_url  TEXT NOT NULL,
    kind        TEXT NOT NULL,           -- secret|endpoint|library|sink|sourcemap
    name        TEXT DEFAULT '',
    value       TEXT NOT NULL,
    severity    TEXT DEFAULT 'info',
    context     TEXT DEFAULT '',
    created_at  REAL NOT NULL,
    UNIQUE(target_id, source_url, kind, value)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    engine      TEXT NOT NULL,           -- nuclei|retirejs|...
    template    TEXT DEFAULT '',
    name        TEXT DEFAULT '',
    severity    TEXT DEFAULT 'info',
    matched_at  TEXT DEFAULT '',
    info        TEXT DEFAULT '{}',
    created_at  REAL NOT NULL,
    UNIQUE(target_id, engine, template, matched_at)
);

CREATE TABLE IF NOT EXISTS uptime_checks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    host        TEXT NOT NULL,
    up          INTEGER NOT NULL,
    status      INTEGER,
    response_ms REAL,
    checked_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    status      TEXT NOT NULL,           -- queued|running|paused|done|error
    stage       TEXT DEFAULT '',
    started_at  REAL,
    finished_at REAL,
    stats       TEXT DEFAULT '{}',
    log         TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id, kind);
CREATE INDEX IF NOT EXISTS idx_uptime_target ON uptime_checks(target_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_js_target ON js_findings(target_id, kind);
"""


class DB:
    def __init__(self, path: Path | None = None):
        settings.ensure_dirs()
        self.path = Path(path) if path else settings.db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA busy_timeout=5000;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @contextmanager
    def _cur(self):
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            finally:
                cur.close()

    # ---- targets -------------------------------------------------------
    def add_target(self, domain: str, scope_in: str = "", scope_out: str = "") -> int:
        with self._cur() as c:
            c.execute(
                "INSERT INTO targets(domain, scope_in, scope_out, created_at) VALUES(?,?,?,?) "
                "ON CONFLICT(domain) DO UPDATE SET scope_in=excluded.scope_in, scope_out=excluded.scope_out",
                (domain, scope_in, scope_out, time.time()),
            )
            c.execute("SELECT id FROM targets WHERE domain=?", (domain,))
            return c.fetchone()["id"]

    def get_target(self, target_id: int) -> dict | None:
        with self._cur() as c:
            c.execute("SELECT * FROM targets WHERE id=?", (target_id,))
            row = c.fetchone()
            return dict(row) if row else None

    def list_targets(self) -> list[dict]:
        with self._cur() as c:
            c.execute("SELECT * FROM targets ORDER BY created_at DESC")
            return [dict(r) for r in c.fetchall()]

    def set_health(self, target_id: int, health: str) -> None:
        with self._cur() as c:
            c.execute("UPDATE targets SET health=? WHERE id=?", (health, target_id))

    # ---- generic upserts ----------------------------------------------
    def upsert_asset(self, target_id: int, kind: str, value: str, meta: dict | None = None) -> bool:
        """Returns True if this asset is newly discovered."""
        now = time.time()
        with self._cur() as c:
            c.execute("SELECT id FROM assets WHERE target_id=? AND kind=? AND value=?", (target_id, kind, value))
            existing = c.fetchone()
            if existing:
                c.execute("UPDATE assets SET last_seen=?, is_new=0, meta=? WHERE id=?",
                          (now, json.dumps(meta or {}), existing["id"]))
                return False
            c.execute(
                "INSERT INTO assets(target_id, kind, value, meta, first_seen, last_seen, is_new) VALUES(?,?,?,?,?,?,1)",
                (target_id, kind, value, json.dumps(meta or {}), now, now),
            )
            return True

    def upsert_http(self, target_id: int, url: str, **fields: Any) -> None:
        now = time.time()
        with self._cur() as c:
            c.execute("SELECT id FROM http_services WHERE target_id=? AND url=?", (target_id, url))
            row = c.fetchone()
            cols = ["status", "title", "tech", "webserver", "ip", "content_len"]
            vals = [fields.get(k) for k in cols]
            if row:
                sets = ", ".join(f"{col}=?" for col in cols)
                c.execute(f"UPDATE http_services SET {sets}, last_seen=? WHERE id=?", (*vals, now, row["id"]))
            else:
                c.execute(
                    "INSERT INTO http_services(target_id,url,status,title,tech,webserver,ip,content_len,first_seen,last_seen) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (target_id, url, *vals, now, now),
                )

    def add_js_finding(self, target_id: int, source_url: str, kind: str, value: str,
                       name: str = "", severity: str = "info", context: str = "") -> bool:
        with self._cur() as c:
            try:
                c.execute(
                    "INSERT INTO js_findings(target_id,source_url,kind,name,value,severity,context,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (target_id, source_url, kind, name, value[:2000], severity, context[:500], time.time()),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def add_finding(self, target_id: int, engine: str, template: str, name: str,
                    severity: str, matched_at: str, info: dict | None = None) -> bool:
        with self._cur() as c:
            try:
                c.execute(
                    "INSERT INTO findings(target_id,engine,template,name,severity,matched_at,info,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (target_id, engine, template, name, severity, matched_at, json.dumps(info or {}), time.time()),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def add_uptime(self, target_id: int, host: str, up: bool, status: int | None, response_ms: float | None) -> None:
        with self._cur() as c:
            c.execute(
                "INSERT INTO uptime_checks(target_id,host,up,status,response_ms,checked_at) VALUES(?,?,?,?,?,?)",
                (target_id, host, 1 if up else 0, status, response_ms, time.time()),
            )

    # ---- scan runs -----------------------------------------------------
    def create_run(self, target_id: int) -> int:
        with self._cur() as c:
            c.execute("INSERT INTO scan_runs(target_id,status,started_at) VALUES(?,?,?)",
                      (target_id, "queued", time.time()))
            return c.lastrowid

    def update_run(self, run_id: int, **fields: Any) -> None:
        if not fields:
            return
        with self._cur() as c:
            sets = ", ".join(f"{k}=?" for k in fields)
            c.execute(f"UPDATE scan_runs SET {sets} WHERE id=?", (*fields.values(), run_id))

    def append_log(self, run_id: int, line: str) -> None:
        with self._cur() as c:
            c.execute("UPDATE scan_runs SET log = log || ? WHERE id=?", (line + "\n", run_id))

    def get_run(self, run_id: int) -> dict | None:
        with self._cur() as c:
            c.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,))
            row = c.fetchone()
            return dict(row) if row else None

    def latest_run(self, target_id: int) -> dict | None:
        with self._cur() as c:
            c.execute("SELECT * FROM scan_runs WHERE target_id=? ORDER BY id DESC LIMIT 1", (target_id,))
            row = c.fetchone()
            return dict(row) if row else None

    # ---- queries for the dashboard ------------------------------------
    def query(self, sql: str, params: Iterable = ()) -> list[dict]:
        with self._cur() as c:
            c.execute(sql, tuple(params))
            return [dict(r) for r in c.fetchall()]

    def counts(self, target_id: int) -> dict:
        with self._cur() as c:
            out = {}
            c.execute("SELECT COUNT(*) n FROM assets WHERE target_id=? AND kind='subdomain'", (target_id,))
            out["subdomains"] = c.fetchone()["n"]
            c.execute("SELECT COUNT(*) n FROM http_services WHERE target_id=?", (target_id,))
            out["http_services"] = c.fetchone()["n"]
            c.execute("SELECT COUNT(*) n FROM js_findings WHERE target_id=?", (target_id,))
            out["js_findings"] = c.fetchone()["n"]
            c.execute("SELECT COUNT(*) n FROM findings WHERE target_id=?", (target_id,))
            out["findings"] = c.fetchone()["n"]
            return out


_db: DB | None = None


def get_db() -> DB:
    global _db
    if _db is None:
        _db = DB()
    return _db
