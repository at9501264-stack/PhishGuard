"""Watchlist monitoring endpoints."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app import db
from app.services import watcher
from app.services.events import log_event
from app.services.scanner import InvalidURL, normalize_url

router = APIRouter(prefix="/api/watchlist", tags=["Watchlist"])


class WatchRequest(BaseModel):
    target: str = Field(..., description="URL or domain to monitor")
    interval_minutes: int = Field(60, ge=1, le=10080)
    monitor_typosquats: bool = False
    label: Optional[str] = None


@router.post("", summary="Add watchlist item", description="The first check runs immediately in the background "
             "scheduler (within ~60s).")
async def add(req: WatchRequest):
    target = req.target.strip()
    try:
        host = normalize_url(target)[2]
    except InvalidURL as e:
        raise HTTPException(status_code=422, detail=str(e))
    wid = db.insert("watchlist", {"target": target, "label": req.label, "interval_minutes": req.interval_minutes,
                                  "monitor_typosquats": 1 if req.monitor_typosquats else 0,
                                  "created_at": db.now_iso(), "known_typosquats": "[]"})
    log_event("watch_add", f"Watching {target}", {"watch_id": wid, "interval_minutes": req.interval_minutes,
                                                  "monitor_typosquats": req.monitor_typosquats},
              entity_type="watch", entity_id=wid, domain=host)
    return watcher.watch_out(db.query_one("SELECT * FROM watchlist WHERE id = ?", (wid,)))


@router.get("", summary="List watchlist")
async def list_items():
    return [watcher.watch_out(r) for r in db.query("SELECT * FROM watchlist ORDER BY id DESC")]


def _row(wid: int) -> dict:
    r = db.query_one("SELECT * FROM watchlist WHERE id = ?", (wid,))
    if not r:
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    return r


@router.delete("/{watch_id}", summary="Remove watchlist item")
async def remove(watch_id: int):
    r = _row(watch_id)
    db.execute("DELETE FROM watchlist WHERE id = ?", (watch_id,))
    db.execute("DELETE FROM watch_checks WHERE watch_id = ?", (watch_id,))
    try:
        host = normalize_url(r["target"])[2]
    except InvalidURL:
        host = None
    log_event("watch_remove", f"Stopped watching {r['target']}", {"watch_id": watch_id},
              entity_type="watch", entity_id=watch_id, domain=host)
    return {"deleted": True, "id": watch_id}


@router.post("/{watch_id}/run", summary="Run a check now", description="Rescans the target (and typosquats if "
             "enabled) synchronously and returns the updated watchlist item.")
async def run_now(watch_id: int):
    _row(watch_id)
    try:
        res = await watcher.check_watch(watch_id)
    except InvalidURL as e:
        raise HTTPException(status_code=422, detail=str(e))
    return res


@router.get("/{watch_id}/history", summary="Check history")
async def history(watch_id: int):
    r = _row(watch_id)
    rows = db.query("SELECT * FROM watch_checks WHERE watch_id = ? ORDER BY t ASC, id ASC", (watch_id,))
    typos = []
    for c in reversed(rows):
        if c["typosquats"] is not None:
            typos = db.loads(c["typosquats"], []) or []
            break
    return {"item": watcher.watch_out(r),
            "checks": [{"t": c["t"], "risk_score": c["risk_score"], "verdict": c["verdict"], "scan_id": c["scan_id"]}
                       for c in rows],
            "typosquats": typos}
