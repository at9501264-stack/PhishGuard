#!/usr/bin/env python3
"""Build the cloud snapshot: deploy/seed.db (+ deploy/feeds/*.gz) used by the Vercel function on cold start.

    backend/.venv/bin/python deploy/build_cloud_seed.py            # backend/data/phishguard.db -> deploy/seed.db
    backend/.venv/bin/python deploy/build_cloud_seed.py --src other.db --max-dom-kb 0 --no-feeds

What it does (stdlib only, never modifies the source DB or the feed files):
1. online copy with the sqlite3 backup API from a read-only connection (safe while the local API is running
   and writing in WAL mode - the snapshot is transactionally consistent);
2. optionally applies the app's own idempotent schema migration (app.db.SCHEMA + migrate()) so the cold start
   does not need to ALTER TABLE (skipped with a warning if backend/app does not import right now);
3. cleans it for a public demo: removes secrets from `settings` (VirusTotal / Safe Browsing keys etc.),
   marks unfinished bulk jobs as failed (otherwise every cold start would resume them), drops stored DOM
   snapshots above --max-dom-kb per scan (keeps the file small);
4. journal_mode=DELETE + VACUUM -> one self-contained, compact file; prints a summary;
5. packs backend/data/feeds/* into deploy/feeds/*.gz (31 MB -> ~8 MB). The raw feeds are excluded from the
   upload by .vercelignore (Hobby CLI limit: 100 MB of source files); deploy/cloud_app.py unpacks them into
   /tmp on cold start (~0.1 s).
"""
from __future__ import annotations

import argparse
import gzip
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
DEFAULT_SRC = BACKEND / "data" / "phishguard.db"
DEFAULT_DST = ROOT / "deploy" / "seed.db"
FEEDS_SRC = BACKEND / "data" / "feeds"
FEEDS_DST = ROOT / "deploy" / "feeds"
SECRET_HINTS = ("api_key", "apikey", "secret", "token", "password", "webhook")


def pack_feeds(src: Path = FEEDS_SRC, dst: Path = FEEDS_DST) -> dict:
    """gzip every feed file (index.json copied as-is); stale packed files are removed."""
    if not src.is_dir():
        return {"status": f"skipped: {src} not found"}
    dst.mkdir(parents=True, exist_ok=True)
    keep: set[str] = set()
    raw = packed = 0
    for f in sorted(src.iterdir()):
        if not f.is_file() or f.name.startswith(".") or f.name.endswith(".tmp"):
            continue
        if f.suffix == ".json":
            shutil.copyfile(f, dst / f.name)
            keep.add(f.name)
            continue
        out = dst / (f.name + ".gz")
        tmp = out.with_name(out.name + ".building")
        with open(f, "rb") as fi, open(tmp, "wb") as fraw:
            with gzip.GzipFile(filename=f.name, mode="wb", fileobj=fraw, compresslevel=9,
                               mtime=int(f.stat().st_mtime)) as fo:
                shutil.copyfileobj(fi, fo, 1024 * 1024)
        os.replace(tmp, out)
        keep.add(out.name)
        raw += f.stat().st_size
        packed += out.stat().st_size
    for f in dst.iterdir():
        if f.name not in keep:
            f.unlink()
    return {"status": "ok", "files": len(keep), "raw_mb": round(raw / 2**20, 1), "packed_mb": round(packed / 2**20, 1)}


def build_feed_index(dst: Path = ROOT / "deploy" / "feeds_index.pkl.gz") -> str:
    """Pickle the backend's parsed feed sets (see deploy/feedindex.py); needs backend/.venv (httpx, tldextract)."""
    code = ("import sys; from pathlib import Path; sys.path[:0] = [sys.argv[1], sys.argv[2]]; "
            "from app.analysis import feeds as fm; from deploy import feedindex; "
            "print(feedindex.dump(fm, Path(fm.__file__), Path(fm.FEED_DIR), Path(sys.argv[3])))")
    import subprocess
    r = subprocess.run([sys.executable, "-c", code, str(BACKEND), str(ROOT), str(dst)], capture_output=True,
                       text=True, timeout=300)
    if r.returncode != 0:
        dst.unlink(missing_ok=True)  # a stale index would only be ignored, but do not ship it
        return "skipped (" + (r.stderr.strip().splitlines() or ["?"])[-1][:200] + ")"
    return r.stdout.strip().splitlines()[-1]


def _tables(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in _tables(conn)}


def _migrate_with_app(dst: Path) -> str:
    """Run backend app.db.init_db() against the snapshot (same code the API runs at startup)."""
    code = ("import os, sys; sys.path.insert(0, sys.argv[1]); os.environ['PHISHGUARD_DB_PATH'] = sys.argv[2]; "
            "from app import db; db.init_db(); print(db.SCHEMA_VERSION)")
    import subprocess
    r = subprocess.run([sys.executable, "-c", code, str(BACKEND), str(dst)], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return "skipped (app.db failed to import/migrate: " + (r.stderr.strip().splitlines() or ["?"])[-1][:200] + ")"
    return f"ok (schema v{r.stdout.strip()})"


def build(src: Path, dst: Path, migrate: bool, keep_secrets: bool, max_dom_kb: int) -> dict:
    if not src.exists():
        raise SystemExit(f"source DB not found: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".building")
    for p in (tmp, Path(str(tmp) + "-wal"), Path(str(tmp) + "-shm"), Path(str(tmp) + "-journal")):
        p.unlink(missing_ok=True)

    t0 = time.time()
    src_conn = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
    dst_conn = sqlite3.connect(str(tmp))
    with dst_conn:
        src_conn.backup(dst_conn)
    src_conn.close()
    dst_conn.execute("PRAGMA journal_mode=DELETE")
    dst_conn.close()

    report: dict = {"src": str(src), "src_bytes": src.stat().st_size}
    report["migration"] = _migrate_with_app(tmp) if migrate else "not requested"

    conn = sqlite3.connect(str(tmp), isolation_level=None)
    conn.execute("PRAGMA journal_mode=DELETE")
    tables = set(_tables(conn))
    removed_settings: list[str] = []
    if "settings" in tables and not keep_secrets:
        for (key,) in conn.execute("SELECT key FROM settings").fetchall():
            if any(h in key.lower() for h in SECRET_HINTS):
                conn.execute("DELETE FROM settings WHERE key = ?", (key,))
                removed_settings.append(key)
    report["removed_settings"] = removed_settings

    if "bulk_jobs" in tables and "status" in _columns(conn, "bulk_jobs"):
        cur = conn.execute("UPDATE bulk_jobs SET status = 'failed', finished_at = COALESCE(finished_at, "
                           "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) WHERE status IN ('queued', 'running')")
        report["unfinished_bulk_jobs_closed"] = cur.rowcount
        if "bulk_items" in tables:
            conn.execute("UPDATE bulk_items SET status = 'error', error = 'not finished when the cloud snapshot "
                         "was taken' WHERE status = 'pending'")

    if "scan_dom" in tables and max_dom_kb >= 0 and "html_gz" in _columns(conn, "scan_dom"):
        cur = conn.execute("DELETE FROM scan_dom WHERE length(html_gz) > ?", (max_dom_kb * 1024,))
        report["dom_snapshots_dropped"] = cur.rowcount

    conn.execute("VACUUM")
    report["integrity"] = conn.execute("PRAGMA integrity_check").fetchone()[0]
    report["counts"] = _counts(conn)
    report["scan_dates"] = conn.execute("SELECT MIN(created_at), MAX(created_at) FROM scans").fetchone() \
        if "scans" in tables else None
    conn.close()

    os.replace(tmp, dst)
    report["dst"] = str(dst)
    report["dst_bytes"] = dst.stat().st_size
    report["seconds"] = round(time.time() - t0, 2)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", type=Path, default=DEFAULT_SRC)
    ap.add_argument("--dst", type=Path, default=DEFAULT_DST)
    ap.add_argument("--no-migrate", action="store_true", help="do not run app.db.init_db() on the snapshot")
    ap.add_argument("--keep-secrets", action="store_true", help="keep API keys stored in the settings table")
    ap.add_argument("--max-dom-kb", type=int, default=200,
                    help="drop stored DOM snapshots larger than this (gzipped KB per scan); -1 keeps all")
    ap.add_argument("--no-feeds", action="store_true", help="do not (re)pack backend/data/feeds into deploy/feeds")
    a = ap.parse_args()
    if not a.no_feeds:
        f = pack_feeds()
        print(f"threat feeds packed into {FEEDS_DST}: {f}")
        print(f"feed lookup index deploy/feeds_index.pkl.gz: {build_feed_index()}")
    r = build(a.src.resolve(), a.dst.resolve(), migrate=not a.no_migrate, keep_secrets=a.keep_secrets,
              max_dom_kb=a.max_dom_kb)
    print(f"seed DB written: {r['dst']}  ({r['dst_bytes'] / 1024:.0f} KB, source {r['src_bytes'] / 1024:.0f} KB, "
          f"{r['seconds']} s)")
    print(f"  migration: {r['migration']}   integrity: {r['integrity']}")
    print(f"  removed settings: {', '.join(r['removed_settings']) or '-'}   "
          f"closed bulk jobs: {r.get('unfinished_bulk_jobs_closed', 0)}   "
          f"dropped DOM snapshots: {r.get('dom_snapshots_dropped', 0)}")
    print(f"  scans dated {r['scan_dates'][0]} .. {r['scan_dates'][1]}" if r.get("scan_dates") else "  no scans table")
    print("  rows: " + ", ".join(f"{k}={v}" for k, v in r["counts"].items() if v))
    if r["counts"].get("scans", 0) == 0:
        print("WARNING: the snapshot has no scans - the cloud dashboard will start empty.")


if __name__ == "__main__":
    main()
