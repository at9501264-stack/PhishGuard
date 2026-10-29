"""PhishGuard cloud bootstrap for Vercel "demo mode" (imported by api/index.py).

Prepares the read-only, serverless environment and THEN imports the unmodified FastAPI app from
backend/app/main.py. Nothing in backend/ is edited; everything here is a cloud-only wrapper:

* env flags (os.environ.setdefault, so Vercel project env vars win):
  PHISHGUARD_CLOUD=1, PHISHGUARD_DB_PATH=/tmp/phishguard.db, PHISHGUARD_NO_SEED=1, PHISHGUARD_NO_SCHEDULER=1
  (+ suggested PHISHGUARD_DATA_DIR / PHISHGUARD_FEEDS_DIR / PHISHGUARD_SCREENSHOT_DIR, cache dirs in /tmp)
* cold start: copies the bundled snapshot deploy/seed.db to /tmp/phishguard.db (data resets on every cold
  start) and optionally shifts the demo timestamps so "last 24h / 7d / 30d" charts never go empty
* writable paths: backend/data is mirrored into /tmp/phishguard/data (real dirs + symlinked files, so reads hit
  the bundle and refresh/replace writes land in /tmp); app.db, feeds and popularity path constants point there
* Tranco popularity index preloaded from the bundled .npz (the 22 MB top-1m.csv is not deployed)
* fallbacks that retire themselves once backend/app handles the flags: watcher.scheduler_loop and the
  startup seed / feed download are disabled while PHISHGUARD_NO_SCHEDULER / PHISHGUARD_NO_SEED are set
* background warm-up (ML models, threat-feed sets, Tranco) so the first scan is not slowed by cold loads
* cloud-only routes (not in the OpenAPI schema):
    GET /api/_diag  - runtime diagnostics (python, /tmp, whois, DNS, TCP 443/43, RSS, cold-start timings, ...)
    GET /api/_cron  - one watchlist re-scan + data-retention tick for Vercel Cron (Authorization: Bearer
                      $CRON_SECRET when CRON_SECRET is set)
If backend/app fails to import (e.g. a half-finished edit), a fallback app still serves /api/_diag and
answers every other path with 503 + the import error, so the failure is visible instead of a crash loop.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import shutil
import socket
import sqlite3
import sys
import threading
import time
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

T0 = time.perf_counter()
STARTED_AT = time.time()

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
SEED_DB = Path(__file__).resolve().parent / "seed.db"
TMP = Path(os.environ.get("PHISHGUARD_TMP_ROOT") or "/tmp")
DATA_SHADOW = TMP / "phishguard" / "data"

log = logging.getLogger("phishguard.cloud")
STATE: dict = {"patches": [], "errors": {}, "timings_ms": {}, "warmup": {"started": False, "done": False}}


def _ms(t: float) -> float:
    return round((time.perf_counter() - t) * 1000, 1)


def _flag(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


# ----------------------------------------------------------------------------------------------- env
def _env_defaults() -> None:
    defaults = {
        "PHISHGUARD_CLOUD": "1",
        "PHISHGUARD_DB_PATH": str(TMP / "phishguard.db"),
        "PHISHGUARD_NO_SEED": "1",
        "PHISHGUARD_NO_SCHEDULER": "1",
        # suggested names for backend support (see docs/DEPLOY_NOTES.md); the wrapper also patches the modules
        "PHISHGUARD_DATA_DIR": str(DATA_SHADOW),
        "PHISHGUARD_FEEDS_DIR": str(DATA_SHADOW / "feeds"),
        "PHISHGUARD_SCREENSHOT_DIR": str(DATA_SHADOW / "screenshots"),
        "PHISHGUARD_SEED_SHIFT_DATES": "1",
        "PHISHGUARD_WARMUP": "1",
        # libraries that like to write caches into $HOME
        "TLDEXTRACT_CACHE": str(TMP / ".cache" / "tldextract"),
        "XDG_CACHE_HOME": str(TMP / ".cache"),
        "JOBLIB_TEMP_FOLDER": str(TMP),
        "MPLCONFIGDIR": str(TMP / ".cache" / "matplotlib"),
        # 1 vCPU functions: no BLAS/OpenMP thread fan-out (less RSS, no oversubscription)
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
    }
    for k, v in defaults.items():
        os.environ.setdefault(k, v)


# ------------------------------------------------------------------------------------- seed database
TS_COLUMNS = {"created_at", "t", "last_checked", "finished_at", "first_seen", "matched_at", "resolved_at",
              "updated_at", "last_used", "revoked_at", "last_match_at", "ct_last_run"}
_ISO_GLOB = "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]*"


def _shift_dates(path: Path) -> dict:
    """Move every ISO timestamp column by (now - newest scan - 10 min) so the demo data looks recent."""
    conn = sqlite3.connect(str(path), isolation_level=None)
    try:
        newest = conn.execute("SELECT MAX(created_at) FROM scans").fetchone()[0]
        if not newest:
            return {"applied": False, "reason": "no scans"}
        dt = datetime.strptime(newest[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        secs = int((datetime.now(timezone.utc) - dt).total_seconds()) - 600
        if secs < 6 * 3600:
            return {"applied": False, "reason": "snapshot is recent", "newest_scan": newest}
        changed = 0
        conn.execute("BEGIN")
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' "
                                              "AND name NOT LIKE 'sqlite_%'")]
        for table in tables:
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            for col in sorted(cols & TS_COLUMNS):
                cur = conn.execute(f"UPDATE {table} SET {col} = strftime('%Y-%m-%dT%H:%M:%SZ', {col}, ?) "
                                   f"WHERE {col} GLOB ?", (f"+{secs} seconds", _ISO_GLOB))
                changed += cur.rowcount
            if table == "api_key_usage" and "day" in cols:
                conn.execute("UPDATE api_key_usage SET day = date(day, ?) WHERE day GLOB "
                             "'[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'", (f"+{secs} seconds",))
        conn.execute("COMMIT")
        return {"applied": True, "shift_days": round(secs / 86400, 2), "rows_updated": changed,
                "newest_scan_before": newest}
    except Exception as e:  # never block the cold start on this cosmetic step
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return {"applied": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        conn.close()


def _prepare_db() -> dict:
    t = time.perf_counter()
    path = Path(os.environ["PHISHGUARD_DB_PATH"]).expanduser()
    info: dict = {"path": str(path), "existed": path.exists(), "seed_available": SEED_DB.exists(),
                  "seed_bytes": SEED_DB.stat().st_size if SEED_DB.exists() else None}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            if SEED_DB.exists():
                tmp = path.with_name(path.name + ".copying")
                shutil.copyfile(SEED_DB, tmp)
                for suffix in ("-wal", "-shm", "-journal"):
                    Path(str(path) + suffix).unlink(missing_ok=True)
                os.replace(tmp, path)
                info["seeded_from"] = "deploy/seed.db"
                if _flag("PHISHGUARD_SEED_SHIFT_DATES"):
                    info["date_shift"] = _shift_dates(path)
            else:
                info["seeded_from"] = None  # backend creates an empty schema; dashboard starts empty
    except Exception as e:
        STATE["errors"]["db_prepare"] = f"{type(e).__name__}: {e}"
    info["ms"] = _ms(t)
    return info


# ------------------------------------------------------------------------------ writable data mirror
def _skip_data(rel: Path) -> bool:
    name = rel.name
    return (name.startswith("phishguard.db") or name in ("screenshots", "__pycache__", ".DS_Store")
            or name.endswith((".tmp", ".building", ".copying")))


def _mirror_tree(src: Path, dst: Path) -> int:
    """Real directories + symlinked files: reads hit the read-only bundle, os.replace() writes land in /tmp."""
    n = 0
    if not src.is_dir():
        return 0
    for dirpath, dirnames, filenames in os.walk(src):
        rel = Path(dirpath).relative_to(src)
        dirnames[:] = [d for d in dirnames if not _skip_data(rel / d)]
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for f in filenames:
            r = rel / f
            if _skip_data(r):
                continue
            target = dst / r
            if target.exists() or target.is_symlink():
                continue
            try:
                os.symlink(Path(dirpath) / f, target)
            except OSError:
                shutil.copy2(Path(dirpath) / f, target)
            n += 1
    return n


def _unpack_feeds(src: Path, dst: Path) -> dict:
    """deploy/feeds/*.gz (packed by build_cloud_seed.py) -> /tmp mirror; raw bundled feeds win if present."""
    if not src.is_dir():
        return {"status": "no packed feeds"}
    t = time.perf_counter()
    import gzip
    dst.mkdir(parents=True, exist_ok=True)
    n = 0
    for f in sorted(src.iterdir()):
        name = f.name[:-3] if f.name.endswith(".gz") else f.name
        target = dst / name
        if target.exists() or target.is_symlink() or name.startswith("."):
            continue
        tmp = target.with_name(target.name + ".copying")
        if f.name.endswith(".gz"):
            with gzip.open(f, "rb") as fi, open(tmp, "wb") as fo:
                shutil.copyfileobj(fi, fo, 1024 * 1024)
        else:
            shutil.copyfile(f, tmp)
        os.replace(tmp, target)
        n += 1
    return {"status": "ok", "files_unpacked": n, "ms": _ms(t)}


def _patch_attr(mod, name: str, value) -> None:
    if hasattr(mod, name):
        old = getattr(mod, name)
        if str(old) != str(value):
            setattr(mod, name, value)
            STATE["patches"].append(f"{mod.__name__}.{name}: {old} -> {value}")


def _patch_paths() -> None:
    t = time.perf_counter()
    try:
        STATE["data_mirror_files"] = _mirror_tree(BACKEND / "data", DATA_SHADOW)
        (DATA_SHADOW / "screenshots").mkdir(parents=True, exist_ok=True)
    except Exception as e:
        STATE["errors"]["data_mirror"] = f"{type(e).__name__}: {e}"
    try:
        STATE["feeds_unpack"] = _unpack_feeds(Path(__file__).resolve().parent / "feeds", DATA_SHADOW / "feeds")
    except Exception as e:
        STATE["errors"]["feeds_unpack"] = f"{type(e).__name__}: {e}"
    try:
        from app import db as appdb
        _patch_attr(appdb, "DB_PATH", Path(os.environ["PHISHGUARD_DB_PATH"]).expanduser())
        _patch_attr(appdb, "DATA_DIR", DATA_SHADOW)
        _patch_attr(appdb, "SCREENSHOT_DIR", DATA_SHADOW / "screenshots")
    except Exception as e:
        STATE["errors"]["patch_db"] = f"{type(e).__name__}: {e}"
    try:
        from app.analysis import feeds as fm
        _patch_attr(fm, "FEED_DIR", DATA_SHADOW / "feeds")
        _patch_attr(fm, "INDEX_FILE", DATA_SHADOW / "feeds" / "index.json")
    except Exception as e:
        STATE["errors"]["patch_feeds"] = f"{type(e).__name__}: {e}"
    try:
        from app.analysis import popularity as pop
        tr = DATA_SHADOW / "tranco"
        tr.mkdir(parents=True, exist_ok=True)
        _patch_attr(pop, "DATA_DIR", tr)
        _patch_attr(pop, "LOCAL_COPY", tr / "top-1m.csv")
        _patch_attr(pop, "INDEX_FILE", tr / "tranco_index.npz")
        _patch_attr(pop, "META_FILE", tr / "tranco_index.json")
        STATE["tranco"] = _preload_tranco(pop)
    except Exception as e:
        STATE["errors"]["patch_popularity"] = f"{type(e).__name__}: {e}"
    STATE["timings_ms"]["patch_paths"] = _ms(t)


def _preload_tranco(pop) -> dict:
    """Load the bundled index (sorted mmh3 hashes + ranks) so popularity.rank() never needs the CSV."""
    npz = BACKEND / "data" / "tranco" / "tranco_index.npz"
    if not npz.exists():
        return {"status": "no bundled index (popularity falls back to downloading Tranco into /tmp)"}
    if not all(hasattr(pop, a) for a in ("_hashes", "_ranks", "_meta")):
        return {"status": "popularity internals changed - not preloaded (falls back to download)"}
    if pop._hashes is not None:
        return {"status": "already loaded", "entries": int(len(pop._hashes))}
    t = time.perf_counter()
    import numpy as np
    with np.load(npz) as z:
        h, r = z["h"], z["r"]
    meta: dict = {}
    try:
        meta = json.loads((npz.parent / "tranco_index.json").read_text())
    except Exception:
        pass
    meta = {**meta, "source": "bundled tranco_index.npz (cloud preload)"}
    pop._hashes, pop._ranks, pop._meta = h, r, meta
    return {"status": "preloaded", "entries": int(len(h)), "list_date": meta.get("list_date"), "ms": _ms(t)}


# ------------------------------------------------------------------------- backend flag fallbacks
_SRC_CACHE: str | None = None


def _backend_mentions(token: str) -> bool:
    """True if backend/app source already references `token` (=> backend supports the flag itself)."""
    global _SRC_CACHE
    if _SRC_CACHE is None:
        parts = []
        for p in (BACKEND / "app").rglob("*.py"):
            try:
                parts.append(p.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                pass
        _SRC_CACHE = "\n".join(parts)
    return token in _SRC_CACHE


def _apply_flag_fallbacks(main_mod) -> None:
    if _flag("PHISHGUARD_NO_SCHEDULER") and not _backend_mentions("PHISHGUARD_NO_SCHEDULER"):
        try:
            from app.services import watcher
            if hasattr(watcher, "scheduler_loop"):
                async def _scheduler_disabled(*_a, **_k):
                    log.info("cloud: watcher scheduler loop disabled (PHISHGUARD_NO_SCHEDULER) - use /api/_cron")
                watcher.scheduler_loop = _scheduler_disabled
                STATE["patches"].append("app.services.watcher.scheduler_loop -> no-op (fallback for "
                                        "PHISHGUARD_NO_SCHEDULER)")
        except Exception as e:
            STATE["errors"]["patch_scheduler"] = f"{type(e).__name__}: {e}"
    if _flag("PHISHGUARD_NO_SEED") and not _backend_mentions("PHISHGUARD_NO_SEED") and main_mod is not None:
        if hasattr(main_mod, "_startup_background"):
            async def _startup_disabled(*_a, **_k):
                log.info("cloud: startup auto-seed / feed download skipped (PHISHGUARD_NO_SEED)")
            main_mod._startup_background = _startup_disabled
            STATE["patches"].append("app.main._startup_background -> no-op (fallback for PHISHGUARD_NO_SEED: "
                                    "no auto-seed, no feed download at cold start)")


# --------------------------------------------------------------------------------------- warm-up
def _warmup() -> None:
    w = STATE["warmup"]
    w["started"] = True
    t_all = time.perf_counter()
    for name, fn in (("feeds", _warm_feeds), ("model", _warm_model), ("tranco", _warm_tranco)):
        t = time.perf_counter()
        try:
            fn()
            w[f"{name}_ms"] = _ms(t)
        except Exception as e:
            w[f"{name}_error"] = f"{type(e).__name__}: {e}"[:300]
    w["total_ms"] = _ms(t_all)
    w["done"] = True


def _warm_model() -> None:
    from ml import predictor
    predictor.model_info()


def _warm_feeds() -> None:
    from app.analysis import feeds
    try:  # pre-built index (deploy/feeds_index.pkl.gz, deploy/feedindex.py): ~0.3 s instead of ~5.7 s parsing
        from deploy import feedindex
        STATE["warmup"]["feeds_index"] = feedindex.inject(
            feeds, Path(feeds.__file__), Path(feeds.FEED_DIR), Path(__file__).resolve().parent / "feeds_index.pkl.gz")
    except Exception as e:  # fall back to the backend's own parser below
        STATE["warmup"]["feeds_index"] = {"status": f"error: {type(e).__name__}: {e}"[:300]}
    feeds.lookup("http://warmup.phishguard.invalid/")


def _warm_tranco() -> None:
    from app.analysis import popularity
    popularity.rank("google.com")


# ------------------------------------------------------------------------------------ diagnostics
def _rss_mb() -> dict:
    out: dict = {}
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                out["rss_mb" if line.startswith("VmRSS") else "peak_rss_mb"] = round(int(line.split()[1]) / 1024, 1)
    except OSError:
        pass
    if "peak_rss_mb" not in out:
        try:
            import resource
            peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            out["peak_rss_mb"] = round(peak / (1024 * 1024 if sys.platform == "darwin" else 1024), 1)
        except Exception:
            pass
    try:
        for line in Path("/proc/meminfo").read_text().splitlines()[:3]:
            k, v = line.split(":", 1)
            out[f"host_{k.strip().lower()}_mb"] = round(int(v.split()[0]) / 1024)
    except OSError:
        pass
    return out


def _tmp_check() -> dict:
    t = time.perf_counter()
    p = TMP / f".pg_write_test_{os.getpid()}"
    try:
        p.write_bytes(b"x" * 1024 * 1024)
        ok = p.read_bytes()[:1] == b"x"
        p.unlink()
        du = shutil.disk_usage(str(TMP))
        return {"path": str(TMP), "writable": ok, "free_mb": round(du.free / 2**20), "total_mb": round(du.total / 2**20),
                "write_1mb_ms": _ms(t)}
    except Exception as e:
        return {"path": str(TMP), "writable": False, "error": f"{type(e).__name__}: {e}"}


def _dns_check(domain: str) -> dict:
    t = time.perf_counter()
    try:
        import dns.resolver
        r = dns.resolver.Resolver()
        ans = r.resolve(domain, "A", lifetime=4)
        return {"domain": domain, "ok": True, "answers": sorted(a.to_text() for a in ans)[:6], "ms": _ms(t),
                "nameservers": list(r.nameservers)[:4]}
    except Exception as e:
        return {"domain": domain, "ok": False, "error": f"{type(e).__name__}: {e}"[:300], "ms": _ms(t)}


def _tcp_check(host: str, port: int) -> dict:
    t = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=5):
            return {"host": host, "port": port, "ok": True, "ms": _ms(t)}
    except Exception as e:
        return {"host": host, "port": port, "ok": False, "error": f"{type(e).__name__}: {e}"[:200], "ms": _ms(t)}


def _https_check(url: str) -> dict:
    t = time.perf_counter()
    try:
        import httpx
        r = httpx.get(url, timeout=8, follow_redirects=True)
        return {"url": url, "ok": r.status_code < 500, "status": r.status_code, "ms": _ms(t)}
    except Exception as e:
        return {"url": url, "ok": False, "error": f"{type(e).__name__}: {e}"[:200], "ms": _ms(t)}


def _whois_check(domain: str) -> dict:
    t = time.perf_counter()
    try:
        import whois
        w = whois.whois(domain, quiet=True, timeout=6)
        reg = w.get("registrar") if w else None
        return {"domain": domain, "ok": bool(w and (reg or w.get("creation_date"))), "registrar": str(reg)[:80] if reg else None,
                "ms": _ms(t)}
    except Exception as e:
        return {"domain": domain, "ok": False, "error": f"{type(e).__name__}: {e}"[:200], "ms": _ms(t)}


def _model_state() -> dict:
    try:
        from ml import predictor
        st = getattr(predictor, "_STATE", None)
        if st is None:
            return {"loaded": False}
        return {"loaded": True, "best": st.get("best"), "models": list((st.get("models") or {}).keys()),
                "version": (st.get("metrics") or {}).get("version")}
    except Exception as e:
        return {"loaded": False, "error": f"{type(e).__name__}: {e}"[:200]}


def _feeds_state() -> dict:
    out: dict = {}
    try:
        from app.analysis import feeds
        out["dir"] = str(getattr(feeds, "FEED_DIR", "?"))
        out["loaded_in_memory"] = bool(getattr(feeds, "_loaded", False))
        ents = getattr(feeds, "_entries", None)
        if isinstance(ents, dict):
            out["entries_loaded"] = sum(len(v) for v in ents.values())
            out["by_feed"] = {k: len(v) for k, v in ents.items()}
        out["entries_index"] = int((feeds.stats() or {}).get("total_entries") or 0)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"[:200]
    return out


def _db_state() -> dict:
    path = Path(os.environ.get("PHISHGUARD_DB_PATH", ""))
    out: dict = {"path": str(path), **{k: v for k, v in (STATE.get("db") or {}).items() if k != "path"}}
    try:
        out["size_kb"] = round(path.stat().st_size / 1024)
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        out["scans"] = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        out["newest_scan"] = c.execute("SELECT MAX(created_at) FROM scans").fetchone()[0]
        c.close()
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"[:200]
    return out


def _bench() -> dict:
    """CPU-bound costs measured inside a request (CPU is only fully available while a request is in flight)."""
    out: dict = {}
    t = time.perf_counter()
    sum(i * i for i in range(2_000_000))
    out["py_loop_2m_ms"] = _ms(t)
    try:
        from app.analysis import feeds
        t = time.perf_counter()
        feeds._ensure_loaded(force=True)
        out["feeds_parse_ms"] = _ms(t)
    except Exception as e:
        out["feeds_error"] = f"{type(e).__name__}: {e}"[:200]
    try:
        import joblib
        from ml import predictor
        t = time.perf_counter()
        for f in sorted(Path(predictor.ART).glob("*.joblib")):
            joblib.load(f)
        out["models_joblib_load_ms"] = _ms(t)
    except Exception as e:
        out["models_error"] = f"{type(e).__name__}: {e}"[:200]
    return out


async def diag(domain: str = "example.com", net: bool = True, whois_test: bool = True, bench: bool = False):
    t = time.perf_counter()
    out: dict = {
        "ok": STATE.get("app_import") == "ok" and not STATE.get("lifespan_error"),
        "python": sys.version.split()[0], "python_full": sys.version, "platform": platform.platform(),
        "executable": sys.executable, "cwd": os.getcwd(), "pid": os.getpid(), "cpu_count": os.cpu_count(),
        "vercel": {k: os.environ.get(k) for k in ("VERCEL", "VERCEL_ENV", "VERCEL_REGION", "VERCEL_URL")},
        "flags": {k: os.environ.get(k) for k in sorted(os.environ) if k.startswith("PHISHGUARD_")},
        "cold_start": {"bootstrap_ms": STATE["timings_ms"].get("bootstrap_total"),
                       "import_backend_ms": STATE["timings_ms"].get("import_backend"),
                       "timings_ms": STATE["timings_ms"],
                       "instance_started_at": datetime.fromtimestamp(STARTED_AT, timezone.utc).strftime(
                           "%Y-%m-%dT%H:%M:%SZ"),
                       "instance_age_s": round(time.time() - STARTED_AT, 1)},
        "warmup": STATE["warmup"],
        "tmp": _tmp_check(),
        "whois_binary": shutil.which("whois"),
        "memory": _rss_mb(),
        "db": _db_state(),
        "feeds": {**(await asyncio.to_thread(_feeds_state)), "unpack": STATE.get("feeds_unpack"),
                  "data_mirror_files": STATE.get("data_mirror_files")},
        "model": _model_state(),
        "tranco": STATE.get("tranco"),
        "app_import": STATE.get("app_import"),
        "app_import_error": STATE.get("app_import_error"),
        "lifespan": STATE.get("lifespan"),
        "lifespan_error": STATE.get("lifespan_error"),
        "patches": STATE["patches"],
        "errors": STATE["errors"],
    }
    if net:
        checks = [asyncio.to_thread(_dns_check, domain), asyncio.to_thread(_tcp_check, domain, 443),
                  asyncio.to_thread(_tcp_check, "whois.iana.org", 43), asyncio.to_thread(_https_check, f"https://{domain}/")]
        if whois_test:
            checks.append(asyncio.to_thread(_whois_check, "example.com"))
        res = await asyncio.gather(*checks, return_exceptions=True)
        names = ["dns", "tcp443", "tcp43_whois", "https", "python_whois"]
        out["network"] = {n: (r if not isinstance(r, BaseException) else {"ok": False, "error": repr(r)})
                          for n, r in zip(names, res)}
    if bench:
        out["bench"] = await asyncio.to_thread(_bench)
    out["diag_ms"] = _ms(t)
    return out


# ------------------------------------------------------------------------------------------- cron
async def _phase(results: dict, name: str, coro_fn, deadline: float, cap_s: float) -> None:
    left = deadline - time.monotonic()
    if left <= 5:
        results[name] = {"skipped": "time budget exhausted"}
        return
    t = time.perf_counter()
    try:
        res = await asyncio.wait_for(coro_fn(), timeout=min(cap_s, left))
        results[name] = {"ok": True, "result": res, "ms": _ms(t)}
    except asyncio.TimeoutError:
        results[name] = {"ok": False, "error": "timeout", "ms": _ms(t)}
    except Exception as e:
        results[name] = {"ok": False, "error": f"{type(e).__name__}: {e}"[:300], "ms": _ms(t)}


async def cron(request_headers: dict, budget_s: float = 240, max_watch: int = 5, feeds: bool = False) -> tuple[int, dict]:
    secret = os.environ.get("CRON_SECRET")
    auth = request_headers.get("authorization", "")
    ua = request_headers.get("user-agent", "")
    if secret:
        if auth != f"Bearer {secret}":
            return 401, {"detail": "unauthorized (expects Authorization: Bearer $CRON_SECRET)"}
    elif not ua.startswith("vercel-cron") and not _flag("PHISHGUARD_CRON_OPEN"):
        return 401, {"detail": "set CRON_SECRET (recommended) or PHISHGUARD_CRON_OPEN=1 to call this manually"}
    deadline = time.monotonic() + max(10.0, min(float(budget_s), 280.0))
    results: dict = {"started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}

    async def watch_phase():
        from app.services import watcher
        done = []
        for row in watcher.due_items()[:max(0, int(max_watch))]:
            if deadline - time.monotonic() < 20:
                break
            r = await asyncio.wait_for(watcher.check_watch(row["id"]), timeout=min(120, deadline - time.monotonic()))
            done.append({"id": row["id"], "target": row.get("target"),
                         "verdict": (r or {}).get("last_verdict"), "risk": (r or {}).get("last_risk")})
        return done

    async def retention_phase():
        from app.services import watcher
        return await asyncio.to_thread(watcher.apply_retention) if hasattr(watcher, "apply_retention") else "n/a"

    async def feeds_phase():
        from app.services import feeds_service
        await feeds_service._do_refresh("cron") if hasattr(feeds_service, "_do_refresh") else None
        return {"total_entries": feeds_service.total_entries()}

    await _phase(results, "watchlist", watch_phase, deadline, 200)
    await _phase(results, "retention", retention_phase, deadline, 30)
    if feeds:
        await _phase(results, "feeds", feeds_phase, deadline, 150)
    results["note"] = ("demo mode: SQLite lives in /tmp of this instance - results last until the next cold start")
    return 200, json.loads(json.dumps(results, default=str))


# ------------------------------------------------------------------------------ app construction
def _fallback_app(err: str):
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    fb = FastAPI(title="PhishGuard API (cloud fallback)", docs_url=None, redoc_url=None, openapi_url=None)

    @fb.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    async def _unavailable(path: str):
        return JSONResponse({"detail": "PhishGuard backend failed to import in the cloud function",
                             "error": err.strip().splitlines()[-1] if err else None, "diag": "/api/_diag"},
                            status_code=503)
    return fb


def _install_routes(app) -> None:
    from fastapi import Request
    from fastapi.responses import JSONResponse

    async def _diag_ep(domain: str = "example.com", net: bool = True, whois: bool = True, bench: bool = False):
        return JSONResponse(await diag(domain, net, whois, bench), headers={"Cache-Control": "no-store"})

    async def _cron_ep(request: Request, budget_s: float = 240, max_watch: int = 5, feeds: bool = False):
        status, body = await cron(dict(request.headers), budget_s, max_watch, feeds)
        return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})

    # this module uses `from __future__ import annotations`; FastAPI cannot resolve the string "Request" of a
    # locally imported name (it would expect a required ?request= query param -> 422), so pin the real class
    _cron_ep.__annotations__["request"] = Request
    app.add_api_route("/api/_diag", _diag_ep, methods=["GET"], include_in_schema=False)
    app.add_api_route("/api/_cron", _cron_ep, methods=["GET", "POST"], include_in_schema=False)
    routes = app.router.routes
    mine = [r for r in routes if getattr(r, "path", None) in ("/api/_diag", "/api/_cron")]
    for r in mine:
        routes.remove(r)
    routes[0:0] = mine  # before any catch-all route of the backend / fallback app


def _wrap_lifespan(app) -> None:
    """Run the backend lifespan, but never let a startup failure take the whole function down."""
    router = app.router
    orig = getattr(router, "lifespan_context", None)
    if orig is None:
        return

    @asynccontextmanager
    async def _safe_lifespan(a):
        t = time.perf_counter()
        cm = orig(a)
        entered = False
        state = None
        try:
            state = await cm.__aenter__()
            entered = True
            STATE["lifespan"] = {"startup": "ok", "ms": _ms(t)}
        except Exception as e:
            STATE["lifespan_error"] = f"{type(e).__name__}: {e}"[:500]
            STATE["lifespan"] = {"startup": "failed", "ms": _ms(t)}
            log.exception("backend lifespan startup failed (serving degraded)")
        try:
            yield state
        finally:
            if entered:
                try:
                    await cm.__aexit__(None, None, None)
                except Exception:
                    log.exception("backend lifespan shutdown failed")

    router.lifespan_context = _safe_lifespan


def _build():
    _env_defaults()
    for p in (str(ROOT), str(BACKEND)):
        if p in sys.path:
            sys.path.remove(p)
        sys.path.insert(0, p)
    STATE["db"] = _prepare_db()
    _patch_paths()

    t = time.perf_counter()
    main_mod = None
    try:
        import app.main as main_mod  # noqa: F811 - the real PhishGuard API (backend/app/main.py)
        application = main_mod.app
        STATE["app_import"] = "ok"
    except Exception:
        err = traceback.format_exc()
        STATE["app_import"] = "failed"
        STATE["app_import_error"] = err[-4000:]
        log.error("PhishGuard backend import failed:\n%s", err)
        application = _fallback_app(err)
    STATE["timings_ms"]["import_backend"] = _ms(t)

    _apply_flag_fallbacks(main_mod)
    if main_mod is not None:
        t = time.perf_counter()
        try:  # schema + idempotent v2 migration, even if the platform never runs the ASGI lifespan
            from app import db as appdb
            appdb.init_db()
            STATE["timings_ms"]["init_db"] = _ms(t)
        except Exception as e:
            STATE["errors"]["init_db"] = f"{type(e).__name__}: {e}"[:300]
    _install_routes(application)
    _wrap_lifespan(application)
    if main_mod is not None and _flag("PHISHGUARD_WARMUP"):
        threading.Thread(target=_warmup, name="phishguard-warmup", daemon=True).start()
    STATE["timings_ms"]["bootstrap_total"] = _ms(T0)
    log.info("PhishGuard cloud bootstrap ready in %.0f ms (backend import %s)",
             STATE["timings_ms"]["bootstrap_total"], STATE["app_import"])
    return application


app = _build()
