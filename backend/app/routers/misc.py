"""Alerts, feeds, events, settings, analytics, health, live stats, admin."""
from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app import db
from app.services import analytics, feeds_service, seed
from app.services.events import alert_out, event_out, log_event
from app.services.scanner import SUMMARY_COLS, row_to_summary
from app.services.settings_service import masked_settings, update_settings

START_TIME = time.time()
RangeT = Literal["24h", "7d", "30d", "90d", "all"]

# ---------------------------------------------------------------- alerts
alerts_router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@alerts_router.get("", summary="List alerts")
async def list_alerts(unread: Optional[bool] = None, severity: Optional[str] = None, limit: int = Query(200, ge=1, le=1000)):
    c, p = [], []
    if unread is True:
        c.append("read = 0")
    elif unread is False:
        c.append("read = 1")
    if severity:
        c.append("severity = ?")
        p.append(severity)
    w = (" WHERE " + " AND ".join(c)) if c else ""
    return [alert_out(r) for r in db.query(f"SELECT * FROM alerts{w} ORDER BY created_at DESC, id DESC LIMIT ?", [*p, limit])]


@alerts_router.post("/read-all", summary="Mark all alerts read")
async def read_all():
    cur = db.execute("UPDATE alerts SET read = 1 WHERE read = 0")
    return {"updated": cur.rowcount}


@alerts_router.post("/{alert_id}/read", summary="Mark alert read")
async def read_one(alert_id: int):
    r = db.query_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    if not r:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.execute("UPDATE alerts SET read = 1 WHERE id = ?", (alert_id,))
    r["read"] = 1
    return alert_out(r)


# ---------------------------------------------------------------- feeds
feeds_router = APIRouter(prefix="/api/feeds", tags=["Threat Feeds"])


@feeds_router.get("", summary="Feed status + stats")
async def feeds():
    status, stats = await asyncio.gather(asyncio.to_thread(feeds_service.safe_status),
                                         asyncio.to_thread(feeds_service.safe_stats))
    return {"feeds": status, "stats": stats, "refreshing": feeds_service.is_refreshing()}


@feeds_router.post("/refresh", summary="Refresh threat feeds",
                   description="Downloads all feeds (runs in a worker thread). Waits up to 120s; if still running, "
                               "returns `status: running` and continues in the background.")
async def refresh():
    task = feeds_service.refresh_in_background("manual")
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=120)
        status = "ok"
    except asyncio.TimeoutError:
        status = "running"
    except Exception as e:
        status = f"error: {e}"
    return {"status": status, "feeds": await asyncio.to_thread(feeds_service.safe_status),
            "stats": await asyncio.to_thread(feeds_service.safe_stats)}


@feeds_router.get("/search", summary="Search feed entries")
async def search(q: str = "", limit: int = Query(100, ge=1, le=1000)):
    try:
        items = await asyncio.to_thread(feeds_service.feeds_mod().search_entries, q, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"feed search failed: {e}")
    return {"items": items or [], "total": len(items or []), "q": q}


# ---------------------------------------------------------------- events
events_router = APIRouter(prefix="/api/events", tags=["Activity Log"])


@events_router.get("", summary="Activity log", description="`type` accepts a comma-separated list. "
                   "v2: filter by `entity_type` (scan|domain|report|watch|bulk|settings) and `entity_id`.")
async def events(type: Optional[str] = None, q: Optional[str] = None, entity_type: Optional[str] = None,
                 entity_id: Optional[str] = None, page: int = Query(1, ge=1),
                 page_size: int = Query(50, ge=1, le=500)):
    c, p = [], []
    if entity_type:
        c.append("entity_type = ?")
        p.append(entity_type)
    if entity_id not in (None, ""):
        c.append("entity_id = ?")
        p.append(str(entity_id).strip().lower() if entity_type == "domain" else str(entity_id).strip())
    if type:
        types = [t.strip() for t in type.split(",") if t.strip()]
        c.append(f"type IN ({','.join('?' for _ in types)})")
        p += types
    if q:
        c.append("message LIKE ?")
        p.append(f"%{q}%")
    w = (" WHERE " + " AND ".join(c)) if c else ""
    total = db.scalar(f"SELECT COUNT(*) FROM events{w}", p, 0)
    rows = db.query(f"SELECT * FROM events{w} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                    [*p, page_size, (page - 1) * page_size])
    types_all = [r["type"] for r in db.query("SELECT DISTINCT type FROM events ORDER BY type")]
    return {"items": [event_out(r) for r in rows], "total": total, "page": page, "page_size": page_size,
            "types": types_all}


# ---------------------------------------------------------------- settings
settings_router = APIRouter(prefix="/api/settings", tags=["Settings"])


class SettingsBody(BaseModel):
    suspicious_threshold: Optional[float] = None
    phishing_threshold: Optional[float] = None
    enable_network_checks: Optional[bool] = None
    enable_screenshots: Optional[bool] = None
    timeout_s: Optional[float] = None
    virustotal_api_key: Optional[str] = None
    google_safe_browsing_api_key: Optional[str] = None
    retention_days: Optional[int] = None
    enable_dnsbl: Optional[bool] = None
    enable_rdap: Optional[bool] = None


@settings_router.get("", summary="Get settings (API keys masked)")
async def get_settings_ep():
    return masked_settings()


@settings_router.put("", summary="Update settings", description="Partial update. Masked key values (`****abcd`) "
                     "are ignored so the real key is kept; send an empty string to clear a key.")
async def put_settings(body: SettingsBody):
    try:
        out, changed = update_settings(body.model_dump(exclude_unset=True))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    if changed:
        log_event("settings_update", f"Settings updated: {', '.join(changed)}", {"changed": changed},
                  entity_type="settings", entity_id="settings")
    return out


# ---------------------------------------------------------------- analytics
analytics_router = APIRouter(prefix="/api/analytics", tags=["Analytics"])


@analytics_router.get("/overview", summary="KPI overview",
                      description="detection_rate = (phishing+suspicious)/total*100. delta = % change vs previous equal period.")
async def overview(range: RangeT = "30d"):
    return await asyncio.to_thread(analytics.overview, range)


@analytics_router.get("/timeseries", summary="Scans over time")
async def timeseries(range: RangeT = "30d", bucket: Optional[Literal["hour", "day"]] = None):
    return await asyncio.to_thread(analytics.timeseries, range, bucket)


@analytics_router.get("/distribution", summary="Distributions",
                      description="heatmap weekday: 0=Monday..6=Sunday, hour in UTC.")
async def distribution(range: RangeT = "30d"):
    return await asyncio.to_thread(analytics.distribution, range)


@analytics_router.get("/model", summary="Model metrics + live stats")
async def model():
    return await asyncio.to_thread(analytics.model_analytics)


@analytics_router.get("/performance", summary="Scan performance")
async def performance(range: RangeT = "30d"):
    return await asyncio.to_thread(analytics.performance, range)


# ---------------------------------------------------------------- system
system_router = APIRouter(prefix="/api", tags=["System"])


@system_router.get("/health", summary="Health check")
async def health():
    model_loaded, version = False, None
    try:
        from ml.predictor import model_info
        info = model_info() or {}
        version = info.get("version")
        model_loaded = bool(info.get("models")) and version not in (None, "stub")
    except Exception:
        pass
    return {"status": "ok", "model_loaded": model_loaded, "model_version": version,
            "db": "ok" if db.db_ok() else "error", "uptime_s": round(time.time() - START_TIME, 1),
            "feeds_entries": await asyncio.to_thread(feeds_service.total_entries),
            "seeding": seed.status()["running"],
            "cloud": os.environ.get("PHISHGUARD_CLOUD", "").strip().lower() in ("1", "true", "yes", "on")}


@system_router.get("/stats/live", summary="Live stats (poll every 5s)")
async def live():
    now = datetime.now(timezone.utc)
    rows = db.query(f"SELECT {SUMMARY_COLS} FROM scans ORDER BY created_at DESC, id DESC LIMIT 10")
    return {"last_scans": [row_to_summary(r) for r in rows],
            "scans_last_minute": db.scalar("SELECT COUNT(*) FROM scans WHERE created_at >= ?",
                                           (db.to_iso(now - timedelta(minutes=1)),), 0),
            "scans_last_hour": db.scalar("SELECT COUNT(*) FROM scans WHERE created_at >= ?",
                                         (db.to_iso(now - timedelta(hours=1)),), 0),
            "unread_alerts": db.scalar("SELECT COUNT(*) FROM alerts WHERE read = 0", (), 0),
            "server_time": db.to_iso(now)}


admin_router = APIRouter(prefix="/api/admin", tags=["Admin"])


@admin_router.post("/seed", summary="Load demo data", description="Runs the demo seed in the background "
                   "(idempotent unless force=true). A dozen well-known sites get full network scans; the rest are "
                   "lexical + ML only unless deep=true (phishing URLs are never fetched).")
async def admin_seed(force: bool = False, deep: bool = False):
    st = seed.status()
    if st["running"]:
        return {"status": "already_running", **st}
    if not force and st["demo_scans"] > 0:
        return {"status": "skipped", "reason": "demo data already present (use force=true)", **st}
    seed.seed_in_background(force=True, deep=deep)
    return {"status": "started", "deep": deep}


@admin_router.get("/seed", summary="Seed status")
async def admin_seed_status():
    return seed.status()


@admin_router.post("/reset", summary="Wipe all data", description="Deletes scans, reports, votes, watchlist, alerts, "
                   "events and bulk jobs (settings are kept). `reseed=true` loads demo data afterwards.")
async def admin_reset(reseed: bool = False, deep: bool = False):
    from app.services import bulk
    bulk.cancel_all()
    db.wipe_data()
    log_event("reset", "All data wiped", {"reseed": reseed})
    if reseed:
        seed.seed_in_background(force=True, deep=deep)
    return {"status": "ok", "reseed": reseed}
