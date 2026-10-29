"""Activity log + alerts helpers.

Every event carries ``entity_type`` / ``entity_id`` (scan | domain | report | watch | bulk | settings) plus two
"related" columns, ``scan_id`` and ``domain``, used by the per-scan timeline (GET /api/scans/{id}/timeline).
"""
from __future__ import annotations

import logging
from typing import Any

from app import db

log = logging.getLogger("phishguard")

ENTITY_TYPES = ("scan", "domain", "report", "watch", "bulk", "settings")
# meta key -> entity type, in inference priority order (used when the caller gives no explicit entity)
_ENTITY_KEYS = (("report_id", "report"), ("job_id", "bulk"), ("watch_id", "watch"), ("scan_id", "scan"))
_STRING_ENTITIES = {"domain", "settings"}


def infer_entity(meta: dict | None) -> tuple[str | None, Any]:
    for key, et in _ENTITY_KEYS:
        v = (meta or {}).get(key)
        if v is not None and v != "":
            return et, v
    return None, None


def log_event(type_: str, message: str, meta: dict | None = None, created_at: str | None = None,
              entity_type: str | None = None, entity_id: Any = None, scan_id: int | None = None,
              domain: str | None = None) -> int | None:
    try:
        meta = meta or {}
        if entity_type is None:
            entity_type, entity_id = infer_entity(meta)
        if scan_id is None:
            sid = meta.get("scan_id")
            if isinstance(sid, int) and not isinstance(sid, bool):
                scan_id = sid
        if domain is None and isinstance(meta.get("domain"), str):
            domain = meta["domain"]
        return db.insert("events", {"type": type_, "message": message, "meta": db.dumps(meta),
                                    "created_at": created_at or db.now_iso(), "entity_type": entity_type,
                                    "entity_id": None if entity_id is None else str(entity_id),
                                    "scan_id": scan_id, "domain": (domain or None) and str(domain).lower()})
    except Exception as e:  # logging must never break a request
        log.warning("event log failed: %s", e)
        return None


def _entity_id_out(entity_type: str | None, value: Any) -> Any:
    if value is None:
        return None
    if entity_type not in _STRING_ENTITIES and str(value).lstrip("-").isdigit():
        return int(value)
    return value


def event_out(row: dict) -> dict:
    et = row.get("entity_type")
    return {"id": row["id"], "type": row["type"], "message": row["message"],
            "meta": db.loads(row["meta"], {}), "created_at": row["created_at"],
            "entity_type": et, "entity_id": _entity_id_out(et, row.get("entity_id")),
            "scan_id": row.get("scan_id"), "domain": row.get("domain")}


def create_alert(type_: str, severity: str, title: str, detail: str = "", scan_id: int | None = None,
                 watch_id: int | None = None, created_at: str | None = None, log: bool = True,
                 read: bool = False, domain: str | None = None) -> int:
    aid = db.insert("alerts", {"type": type_, "severity": severity, "title": title, "detail": detail,
                               "created_at": created_at or db.now_iso(), "read": 1 if read else 0,
                               "scan_id": scan_id, "watch_id": watch_id})
    if log:
        et, eid = ("scan", scan_id) if scan_id is not None else ("watch", watch_id) if watch_id is not None \
            else (None, None)
        log_event("alert", f"Alert: {title}", {"alert_id": aid, "alert_type": type_, "severity": severity,
                                                "scan_id": scan_id, "watch_id": watch_id},
                  created_at=created_at, entity_type=et, entity_id=eid, scan_id=scan_id, domain=domain)
    return aid


def alert_out(row: dict) -> dict:
    return {"id": row["id"], "type": row["type"], "severity": row["severity"], "title": row["title"],
            "detail": row["detail"], "created_at": row["created_at"], "read": bool(row["read"]),
            "scan_id": row["scan_id"], "watch_id": row["watch_id"]}


def backfill_entities() -> int:
    """Fill entity_type/entity_id/scan_id/domain for events written before v2 (runs once per DB)."""
    if db.scalar("SELECT value FROM settings WHERE key = '_meta:events_entity_backfill'"):
        return 0
    rows = db.query("SELECT id, type, meta FROM events WHERE entity_type IS NULL AND scan_id IS NULL "
                    "AND domain IS NULL LIMIT 100000")
    n = 0
    for r in rows:
        meta = db.loads(r["meta"], {}) or {}
        et, eid = infer_entity(meta)
        if r["type"] == "settings_update":
            et, eid = "settings", "settings"
        elif r["type"] == "typosquat" and meta.get("domain"):
            et, eid = "domain", meta["domain"]
        sid = meta.get("scan_id") if isinstance(meta.get("scan_id"), int) else None
        dom = None
        if sid is not None:
            s = db.query_one("SELECT domain FROM scans WHERE id = ?", (sid,))
            dom = s["domain"] if s else None
        if et is None and sid is None and dom is None:
            continue
        db.execute("UPDATE events SET entity_type = ?, entity_id = ?, scan_id = ?, domain = ? WHERE id = ?",
                   (et, None if eid is None else str(eid), sid, dom, r["id"]))
        n += 1
    db.execute("INSERT INTO settings(key, value) VALUES('_meta:events_entity_backfill', '1') "
               "ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    return n
