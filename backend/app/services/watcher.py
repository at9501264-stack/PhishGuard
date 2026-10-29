"""Watchlist monitoring (CheckPhish-style): periodic rescans + typosquat monitoring + alerts.

The scheduler loop runs every 60 s (disabled with PHISHGUARD_NO_SCHEDULER=1) and also applies data retention.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app import db
from app.services.events import create_alert, log_event
from app.services.scanner import normalize_url, perform_scan, split_host
from app.services.settings_service import get_settings

log = logging.getLogger("phishguard.watch")
LOOP_SECONDS = 60
_running: set[int] = set()


def watch_out(row: dict) -> dict:
    change = None
    if row.get("last_risk") is not None and row.get("prev_risk") is not None:
        change = "up" if row["last_risk"] > row["prev_risk"] else "down" if row["last_risk"] < row["prev_risk"] else "same"
    return {"id": row["id"], "target": row["target"], "label": row["label"],
            "interval_minutes": row["interval_minutes"], "monitor_typosquats": bool(row["monitor_typosquats"]),
            "created_at": row["created_at"], "last_checked": row["last_checked"], "last_risk": row["last_risk"],
            "last_verdict": row["last_verdict"], "last_scan_id": row.get("last_scan_id"), "change": change,
            "alerts": db.scalar("SELECT COUNT(*) FROM alerts WHERE watch_id = ?", (row["id"],), 0),
            "known_typosquats": len(db.loads(row.get("known_typosquats"), []) or [])}


def target_domain(target: str) -> str:
    _, _, host = normalize_url(target)
    return split_host(host)["registered_domain"]


async def check_watch(watch_id: int, typosquat_limit: int = 60) -> dict | None:
    row = db.query_one("SELECT * FROM watchlist WHERE id = ?", (watch_id,))
    if not row:
        return None
    if watch_id in _running:
        return watch_out(row)
    _running.add(watch_id)
    try:
        scan = await perform_scan(row["target"], source="watch", event_type="watch",
                                  event_meta={"watch_id": watch_id}, log_events=False)
        typos: list[dict] | None = None
        new_resolving: list[str] = []
        known = set(db.loads(row["known_typosquats"], []) or [])
        domain = None
        if row["monitor_typosquats"]:
            try:
                from app.analysis.typosquat import check_permutations
                domain = target_domain(row["target"])
                typos = await asyncio.wait_for(check_permutations(domain, typosquat_limit), timeout=90)
            except Exception as e:
                log.warning("typosquat check failed: %s", e)
                typos = []
            resolving = [t["domain"] for t in typos if t.get("resolves")]
            new_resolving = [d for d in resolving if d not in known]
            first_baseline = row["last_checked"] is None and not known
            if new_resolving:
                if first_baseline:
                    create_alert("typosquat_baseline", "info",
                                 f"{len(new_resolving)} registered lookalike domains of {domain}",
                                 "Baseline: " + ", ".join(new_resolving[:8]) + (" ..." if len(new_resolving) > 8 else ""),
                                 scan_id=scan["id"], watch_id=watch_id, domain=domain)
                else:
                    create_alert("typosquat_new", "warning",
                                 f"New lookalike domain(s) resolving for {domain}",
                                 ", ".join(new_resolving[:8]) + (" ..." if len(new_resolving) > 8 else ""),
                                 scan_id=scan["id"], watch_id=watch_id, domain=domain)
            known |= set(resolving)

        now = db.now_iso()
        db.insert("watch_checks", {"watch_id": watch_id, "t": now, "risk_score": scan["risk_score"],
                                   "verdict": scan["verdict"], "scan_id": scan["id"],
                                   "typosquats": db.dumps(typos) if typos is not None else None})
        prev_verdict = row["last_verdict"]
        db.update("watchlist", watch_id, {"last_checked": now, "prev_risk": row["last_risk"],
                                          "last_risk": scan["risk_score"], "last_verdict": scan["verdict"],
                                          "last_scan_id": scan["id"], "known_typosquats": db.dumps(sorted(known))})
        if prev_verdict and prev_verdict != scan["verdict"]:
            sev = {"phishing": "critical", "suspicious": "warning"}.get(scan["verdict"], "info")
            create_alert("verdict_change", sev,
                         f"Verdict changed for {row['label'] or row['target']}: {prev_verdict} -> {scan['verdict']}",
                         f"Risk {row['last_risk']} -> {scan['risk_score']}", scan_id=scan["id"], watch_id=watch_id,
                         domain=scan["domain"])
        log_event("watch_run", f"Watch check {row['target']}: {scan['verdict']} ({scan['risk_score']})",
                  {"watch_id": watch_id, "scan_id": scan["id"], "risk_score": scan["risk_score"],
                   "verdict": scan["verdict"], "new_typosquats": new_resolving[:20],
                   "new_typosquats_count": len(new_resolving)},
                  entity_type="watch", entity_id=watch_id, scan_id=scan["id"], domain=scan["domain"])
        return watch_out(db.query_one("SELECT * FROM watchlist WHERE id = ?", (watch_id,)))
    finally:
        _running.discard(watch_id)


def due_items() -> list[dict]:
    now = datetime.now(timezone.utc)
    out = []
    for r in db.query("SELECT * FROM watchlist ORDER BY id"):
        last = db.parse_iso(r["last_checked"])
        if last is None or last + timedelta(minutes=max(1, r["interval_minutes"] or 60)) <= now:
            out.append(r)
    return out


def apply_retention() -> int:
    days = int(get_settings().get("retention_days") or 0)
    if days <= 0:
        return 0
    cutoff = db.to_iso(datetime.now(timezone.utc) - timedelta(days=days))
    cur = db.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,))
    db.execute("DELETE FROM events WHERE created_at < ?", (cutoff,))
    if cur.rowcount:
        db.execute("DELETE FROM scan_dom WHERE scan_id NOT IN (SELECT id FROM scans)")
    return cur.rowcount or 0


async def scheduler_loop(initial_delay: float = 20.0) -> None:
    await asyncio.sleep(initial_delay)
    ticks = 0
    while True:
        try:
            for r in due_items():
                try:
                    await check_watch(r["id"])
                except Exception:
                    log.exception("watch check %s failed", r["id"])
            if ticks % 60 == 0:
                n = await asyncio.to_thread(apply_retention)
                if n:
                    log_event("retention", f"Retention cleanup removed {n} scans", {"deleted": n})
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("scheduler tick failed")
        ticks += 1
        await asyncio.sleep(LOOP_SECONDS)
