"""Bulk scan jobs: background asyncio workers with bounded concurrency, progress tracked in DB."""
from __future__ import annotations

import asyncio
import csv
import io
import logging

from app import db
from app.services.events import create_alert, log_event
from app.services.scanner import InvalidURL, SUMMARY_COLS, perform_scan, row_to_summary

log = logging.getLogger("phishguard.bulk")
CONCURRENCY = 5
MAX_URLS = 500
_tasks: set[asyncio.Task] = set()


def parse_upload(content: bytes, filename: str | None) -> list[str]:
    text = content.decode("utf-8-sig", errors="replace")
    name = (filename or "").lower()
    urls: list[str] = []
    first = text.strip().splitlines()[0] if text.strip() else ""
    looks_csv = name.endswith(".csv") or (not name.endswith(".txt") and "," in first)
    if looks_csv:
        rows = list(csv.reader(io.StringIO(text)))
        if not rows:
            return []
        header = [h.strip().lower() for h in rows[0]]
        col = 0
        start = 0
        if "url" in header:
            col = header.index("url")
            start = 1
        elif header and header[0] and "." not in header[0]:
            start = 1  # header row without a url column -> use first column
        for r in rows[start:]:
            if len(r) > col and r[col].strip():
                urls.append(r[col].strip())
    else:
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line.split()[0])
    return dedupe(urls)


def dedupe(urls: list[str]) -> list[str]:
    seen, out = set(), []
    for u in urls:
        u = (u or "").strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def create_job(urls: list[str], name: str | None = None) -> int:
    urls = dedupe(urls)[:MAX_URLS]
    job_id = db.insert("bulk_jobs", {"name": name or f"Bulk scan ({len(urls)} URLs)", "status": "queued",
                                     "total": len(urls), "done": 0, "created_at": db.now_iso()})
    conn = db.get_conn()
    conn.executemany("INSERT INTO bulk_items(job_id, url, status) VALUES(?, ?, 'pending')",
                     [(job_id, u) for u in urls])
    log_event("bulk", f"Bulk job #{job_id} created with {len(urls)} URLs", {"job_id": job_id, "total": len(urls),
                                                                           "name": name})
    start_job(job_id)
    return job_id


def start_job(job_id: int) -> None:
    t = asyncio.get_running_loop().create_task(run_job(job_id))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)


async def run_job(job_id: int) -> None:
    db.update("bulk_jobs", job_id, {"status": "running"})
    items = db.query("SELECT id, url FROM bulk_items WHERE job_id = ? AND status = 'pending' ORDER BY id", (job_id,))
    sem = asyncio.Semaphore(CONCURRENCY)

    async def work(item: dict) -> None:
        async with sem:
            try:
                res = await perform_scan(item["url"], source="bulk", event_type="bulk_scan",
                                         event_meta={"job_id": job_id})
                db.update("bulk_items", item["id"], {"status": "done", "scan_id": res["id"]})
            except InvalidURL as e:
                db.update("bulk_items", item["id"], {"status": "error", "error": str(e)})
            except Exception as e:  # pragma: no cover
                log.exception("bulk item failed")
                db.update("bulk_items", item["id"], {"status": "error", "error": f"scan failed: {e}"})
            db.execute("UPDATE bulk_jobs SET done = (SELECT COUNT(*) FROM bulk_items WHERE job_id = ? AND status != 'pending') "
                       "WHERE id = ?", (job_id, job_id))

    try:
        await asyncio.gather(*(work(i) for i in items))
        db.update("bulk_jobs", job_id, {"status": "completed", "finished_at": db.now_iso()})
        counts = verdict_counts(job_id)
        job = db.query_one("SELECT * FROM bulk_jobs WHERE id = ?", (job_id,))
        log_event("bulk", f"Bulk job #{job_id} completed: {counts.get('phishing', 0)} phishing of {job['total']}",
                  {"job_id": job_id, "verdict_counts": counts, "status": "completed"})
        if counts.get("phishing"):
            n = counts["phishing"]
            create_alert("bulk_complete", "warning", f"Bulk job '{job['name']}' found {n} phishing URL{'s' if n != 1 else ''}",
                         f"{job['total']} URLs scanned; {counts.get('suspicious', 0)} suspicious.", log=True)
    except asyncio.CancelledError:
        db.update("bulk_jobs", job_id, {"status": "queued"})
        raise
    except Exception as e:
        db.update("bulk_jobs", job_id, {"status": "failed", "finished_at": db.now_iso()})
        log_event("bulk", f"Bulk job #{job_id} failed: {e}", {"job_id": job_id, "status": "failed"})


def verdict_counts(job_id: int) -> dict:
    out = {"legitimate": 0, "suspicious": 0, "phishing": 0, "error": 0}
    for r in db.query("SELECT s.verdict v, COUNT(*) c FROM bulk_items b JOIN scans s ON s.id = b.scan_id "
                      "WHERE b.job_id = ? GROUP BY s.verdict", (job_id,)):
        out[r["v"]] = r["c"]
    out["error"] = db.scalar("SELECT COUNT(*) FROM bulk_items WHERE job_id = ? AND status = 'error'", (job_id,), 0)
    return out


def job_out(row: dict) -> dict:
    total = row["total"] or 0
    return {"id": row["id"], "name": row["name"], "status": row["status"], "total": total, "done": row["done"],
            "progress": round((row["done"] or 0) / total, 3) if total else 1.0,
            "created_at": row["created_at"], "finished_at": row.get("finished_at"),
            "verdict_counts": verdict_counts(row["id"])}


def job_detail(job_id: int) -> dict | None:
    row = db.query_one("SELECT * FROM bulk_jobs WHERE id = ?", (job_id,))
    if not row:
        return None
    out = job_out(row)
    cols = ", ".join(f"s.{c.strip()}" for c in SUMMARY_COLS.split(","))
    rows = db.query(f"SELECT {cols} FROM bulk_items b JOIN scans s ON s.id = b.scan_id WHERE b.job_id = ? ORDER BY b.id",
                    (job_id,))
    out["results"] = [row_to_summary(r) for r in rows]
    out["items"] = [{"url": r["url"], "status": r["status"], "scan_id": r["scan_id"], "error": r["error"]}
                    for r in db.query("SELECT url, status, scan_id, error FROM bulk_items WHERE job_id = ? ORDER BY id",
                                      (job_id,))]
    return out


def resume_unfinished() -> None:
    for r in db.query("SELECT id FROM bulk_jobs WHERE status IN ('queued', 'running')"):
        start_job(r["id"])


def cancel_all() -> None:
    for t in list(_tasks):
        t.cancel()
