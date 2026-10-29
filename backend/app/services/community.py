"""Community reports & voting (PhishTank style).

The reporter's label counts as the first vote. verified when phishing_votes - legitimate_votes >= 3,
rejected when <= -3, otherwise pending. A named voter can change their vote; anonymous votes always add.
"""
from __future__ import annotations

import asyncio
import logging

from app import db
from app.services.events import create_alert, log_event
from app.services.scanner import normalize_url, perform_scan

log = logging.getLogger("phishguard.community")
VERIFY_MARGIN = 3
_tasks: set[asyncio.Task] = set()

REPORT_FIELDS = ("id", "url", "domain", "label", "brand", "comment", "reporter", "created_at", "phishing_votes",
                 "legitimate_votes", "status", "scan_id")


def report_out(row: dict) -> dict:
    return {k: row.get(k) for k in REPORT_FIELDS}


def get_report(rid: int) -> dict | None:
    r = db.query_one("SELECT * FROM reports WHERE id = ?", (rid,))
    return report_out(r) if r else None


def status_for(phishing_votes: int, legitimate_votes: int) -> str:
    margin = phishing_votes - legitimate_votes
    return "verified" if margin >= VERIFY_MARGIN else "rejected" if margin <= -VERIFY_MARGIN else "pending"


def recompute(rid: int) -> tuple[str, str]:
    """Recount votes and update status. Returns (old_status, new_status)."""
    row = db.query_one("SELECT status FROM reports WHERE id = ?", (rid,))
    old = row["status"] if row else "pending"
    pv = db.scalar("SELECT COUNT(*) FROM votes WHERE report_id = ? AND vote = 'phishing'", (rid,), 0)
    lv = db.scalar("SELECT COUNT(*) FROM votes WHERE report_id = ? AND vote = 'legitimate'", (rid,), 0)
    status = status_for(pv, lv)
    db.update("reports", rid, {"phishing_votes": pv, "legitimate_votes": lv, "status": status})
    return old, status


async def _scan_for_report(rid: int, url: str) -> None:
    try:
        res = await perform_scan(url, source="community", event_meta={"report_id": rid})
        db.update("reports", rid, {"scan_id": res["id"]})
    except Exception:
        log.exception("report scan failed")


def create_report(url: str, label: str, brand: str | None = None, comment: str | None = None,
                  reporter: str | None = None, scan: bool = True, created_at: str | None = None,
                  log_it: bool = True) -> dict:
    _, normalized, host = normalize_url(url)
    reporter = (reporter or "").strip() or "anonymous"
    t = created_at or db.now_iso()
    rid = db.insert("reports", {"url": normalized, "domain": host, "label": label, "brand": brand, "comment": comment,
                                "reporter": reporter, "created_at": t, "phishing_votes": 0, "legitimate_votes": 0,
                                "status": "pending", "scan_id": None})
    db.insert("votes", {"report_id": rid, "vote": label, "voter": reporter, "created_at": t})  # reporter = 1st vote
    recompute(rid)
    if log_it:
        log_event("report", f"Community report: {host} as {label}",
                  {"report_id": rid, "url": normalized, "label": label, "brand": brand},
                  entity_type="report", entity_id=rid, domain=host)
    if scan:
        task = asyncio.get_running_loop().create_task(_scan_for_report(rid, normalized))
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
    return get_report(rid)


def vote(rid: int, vote_: str, voter: str | None = None, log_it: bool = True,
         created_at: str | None = None) -> dict | None:
    row = db.query_one("SELECT * FROM reports WHERE id = ?", (rid,))
    if not row:
        return None
    voter = (voter or "").strip() or None
    t = created_at or db.now_iso()
    named = bool(voter) and voter.lower() not in ("anonymous", "anon")
    prev = db.query_one("SELECT id FROM votes WHERE report_id = ? AND voter = ?", (rid, voter)) if named else None
    if prev:
        db.update("votes", prev["id"], {"vote": vote_, "created_at": t})
    else:
        db.insert("votes", {"report_id": rid, "vote": vote_, "voter": voter, "created_at": t})
    old, status = recompute(rid)
    rep = db.query_one("SELECT * FROM reports WHERE id = ?", (rid,))
    if log_it:
        log_event("vote", f"Vote '{vote_}' on report #{rid} ({row['domain']})",
                  {"report_id": rid, "vote": vote_, "voter": voter, "status": status},
                  entity_type="report", entity_id=rid, domain=row["domain"], scan_id=row["scan_id"])
        if status != old and status in ("verified", "rejected"):
            create_alert("community_" + status, "critical" if status == "verified" else "info",
                         f"Community {status} report: {row['domain']}",
                         f"{rep['phishing_votes']} phishing vs {rep['legitimate_votes']} legitimate votes",
                         scan_id=row["scan_id"], domain=row["domain"])
    return get_report(rid)
