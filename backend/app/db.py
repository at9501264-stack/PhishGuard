"""SQLite persistence layer (stdlib sqlite3, WAL mode, one connection per thread).

Environment:
  PHISHGUARD_DB_PATH  path of the SQLite file (default: backend/data/phishguard.db)

Schema v1 tables are created by ``SCHEMA``; v2 columns/tables/indexes are applied by ``migrate()``,
which is idempotent (every ``ALTER TABLE ... ADD COLUMN`` is guarded by ``PRAGMA table_info``).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger("phishguard.db")

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_DB_PATH = DATA_DIR / "phishguard.db"
DB_PATH = Path(os.environ.get("PHISHGUARD_DB_PATH") or DEFAULT_DB_PATH).expanduser()
SCREENSHOT_DIR = DATA_DIR / "screenshots"
SCHEMA_VERSION = 2

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    normalized_url TEXT,
    domain TEXT,
    registered_domain TEXT,
    tld TEXT,
    created_at TEXT NOT NULL,
    duration_ms INTEGER,
    source TEXT,
    verdict TEXT,
    risk_score INTEGER,
    confidence REAL,
    ml_prob REAL,
    heuristic_score REAL,
    brand TEXT,
    brand_technique TEXT,
    country_code TEXT,
    country TEXT,
    blacklisted INTEGER DEFAULT 0,
    tags TEXT DEFAULT '[]',
    notes TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS ix_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS ix_scans_regdomain ON scans(registered_domain);
CREATE INDEX IF NOT EXISTS ix_scans_tld ON scans(tld);
CREATE INDEX IF NOT EXISTS ix_scans_verdict ON scans(verdict);
CREATE INDEX IF NOT EXISTS ix_scans_risk ON scans(risk_score);
CREATE INDEX IF NOT EXISTS ix_scans_source ON scans(source);
CREATE INDEX IF NOT EXISTS ix_scans_brand ON scans(brand);
CREATE INDEX IF NOT EXISTS ix_scans_country ON scans(country_code);
CREATE INDEX IF NOT EXISTS ix_scans_bl ON scans(blacklisted);
CREATE INDEX IF NOT EXISTS ix_scans_duration ON scans(duration_ms);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    domain TEXT,
    label TEXT NOT NULL,
    brand TEXT,
    comment TEXT,
    reporter TEXT,
    created_at TEXT NOT NULL,
    phishing_votes INTEGER DEFAULT 0,
    legitimate_votes INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS ix_reports_domain ON reports(domain);
CREATE INDEX IF NOT EXISTS ix_reports_status ON reports(status);

CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    vote TEXT NOT NULL,
    voter TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_votes_report ON votes(report_id);

CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    label TEXT,
    interval_minutes INTEGER DEFAULT 60,
    monitor_typosquats INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    last_checked TEXT,
    last_risk INTEGER,
    last_verdict TEXT,
    prev_risk INTEGER,
    last_scan_id INTEGER,
    known_typosquats TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS watch_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id INTEGER NOT NULL,
    t TEXT NOT NULL,
    risk_score INTEGER,
    verdict TEXT,
    scan_id INTEGER,
    typosquats TEXT
);
CREATE INDEX IF NOT EXISTS ix_wc_watch ON watch_checks(watch_id);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL,
    read INTEGER DEFAULT 0,
    scan_id INTEGER,
    watch_id INTEGER
);
CREATE INDEX IF NOT EXISTS ix_alerts_read ON alerts(read);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    message TEXT,
    meta TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_type ON events(type);
CREATE INDEX IF NOT EXISTS ix_events_created ON events(created_at);

CREATE TABLE IF NOT EXISTS bulk_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    status TEXT DEFAULT 'queued',
    total INTEGER DEFAULT 0,
    done INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS bulk_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    scan_id INTEGER,
    error TEXT
);
CREATE INDEX IF NOT EXISTS ix_bi_job ON bulk_items(job_id);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- ------------------------------------------------------------------ v2 tables
CREATE TABLE IF NOT EXISTS scan_dom (
    scan_id INTEGER PRIMARY KEY,
    html_gz BLOB NOT NULL,
    size INTEGER,
    truncated INTEGER DEFAULT 0,
    source TEXT,
    created_at TEXT
);
"""

# v2 columns added to existing v1 tables (guarded by PRAGMA table_info -> idempotent)
V2_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "scans": [("ip", "TEXT"), ("asn", "TEXT"), ("registrar", "TEXT"), ("threat_type", "TEXT"),
              ("trust_score", "INTEGER"), ("tier", "TEXT"), ("category", "TEXT"), ("tested_depth", "TEXT")],
    "events": [("entity_type", "TEXT"), ("entity_id", "TEXT"), ("scan_id", "INTEGER"), ("domain", "TEXT")],
}

V2_INDEXES = [
    *[f"CREATE INDEX IF NOT EXISTS ix_scans_{c} ON scans({c})"
      for c in ("ip", "asn", "registrar", "threat_type", "trust_score", "tier", "category")],
    "CREATE INDEX IF NOT EXISTS ix_events_entity ON events(entity_type, entity_id)",
    "CREATE INDEX IF NOT EXISTS ix_events_scan ON events(scan_id)",
    "CREATE INDEX IF NOT EXISTS ix_events_domain ON events(domain)",
    "CREATE INDEX IF NOT EXISTS ix_alerts_created ON alerts(created_at)",
]

DATA_TABLES = ["scans", "reports", "votes", "watchlist", "watch_checks", "alerts", "events", "bulk_jobs",
               "bulk_items", "scan_dom"]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        s2 = str(s).strip().replace("Z", "+00:00")
        if len(s2) == 10:
            s2 += "T00:00:00+00:00"
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=OFF")
    return conn


def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _connect()
        _local.conn = conn
    return conn


def table_columns(table: str, conn: sqlite3.Connection | None = None) -> set[str]:
    conn = conn or get_conn()
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def migrate(conn: sqlite3.Connection | None = None) -> list[str]:
    """Apply v2 schema changes. Safe to run any number of times. Returns the list of added columns."""
    conn = conn or get_conn()
    added: list[str] = []
    for table, cols in V2_COLUMNS.items():
        have = table_columns(table, conn)
        for name, decl in cols:
            if name in have:
                continue
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                added.append(f"{table}.{name}")
            except sqlite3.OperationalError as e:  # concurrent migration by another process
                if "duplicate column" not in str(e).lower():
                    raise
    for stmt in V2_INDEXES:
        conn.execute(stmt)
    conn.execute("INSERT INTO settings(key, value) VALUES('_meta:schema_version', ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (str(SCHEMA_VERSION),))
    if added:
        log.info("DB migrated to v%s (+%d columns)", SCHEMA_VERSION, len(added))
    return added


def init_db() -> None:
    conn = get_conn()
    conn.executescript(SCHEMA)
    migrate(conn)


def execute(sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
    return get_conn().execute(sql, tuple(params))


def executemany(sql: str, seq: Iterable[Iterable[Any]]) -> sqlite3.Cursor:
    return get_conn().executemany(sql, [tuple(p) for p in seq])


def query(sql: str, params: Iterable[Any] = ()) -> list[dict]:
    return [dict(r) for r in get_conn().execute(sql, tuple(params)).fetchall()]


def query_one(sql: str, params: Iterable[Any] = ()) -> dict | None:
    r = get_conn().execute(sql, tuple(params)).fetchone()
    return dict(r) if r else None


def scalar(sql: str, params: Iterable[Any] = (), default: Any = None) -> Any:
    r = get_conn().execute(sql, tuple(params)).fetchone()
    if r is None or r[0] is None:
        return default
    return r[0]


def insert(table: str, values: dict) -> int:
    cols = ", ".join(values.keys())
    ph = ", ".join("?" for _ in values)
    cur = get_conn().execute(f"INSERT INTO {table} ({cols}) VALUES ({ph})", tuple(values.values()))
    return int(cur.lastrowid)


def update(table: str, row_id: int, values: dict) -> None:
    if not values:
        return
    sets = ", ".join(f"{k} = ?" for k in values)
    get_conn().execute(f"UPDATE {table} SET {sets} WHERE id = ?", (*values.values(), row_id))


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, ensure_ascii=False)


def loads(s: str | None, default: Any = None) -> Any:
    if s is None or s == "":
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def db_ok() -> bool:
    try:
        get_conn().execute("SELECT 1").fetchone()
        return True
    except Exception:
        return False


def wipe_data() -> None:
    conn = get_conn()
    for t in DATA_TABLES:
        conn.execute(f"DELETE FROM {t}")
    conn.execute("DELETE FROM sqlite_sequence WHERE name IN (%s)" % ",".join("?" for _ in DATA_TABLES),
                 DATA_TABLES)
