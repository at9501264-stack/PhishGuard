"""Pre-built threat-feed index for the cloud function (shared by build_cloud_seed.py and cloud_app.py).

Parsing the 31 MB of feed text into lookup sets costs ~1.3 s locally but ~5.7 s on a Vercel function
(measured), which is most of a cold scan. At build time we run the backend's own loader
(app.analysis.feeds._ensure_loaded) and pickle the resulting in-memory state; on cold start the state is
injected in ~0.3 s. Safety net: the pickle carries a fingerprint (sha256 of feeds.py + feed file sizes) and is
only injected when the deployed feeds.py and feed files match it exactly - otherwise the backend parses the
feeds itself as usual.
"""
from __future__ import annotations

import gzip
import hashlib
import pickle
import time
from pathlib import Path

FORMAT = 1
STATE_ATTRS = ("_url_sets", "_host_sets", "_entries", "_pt_targets")


def fingerprint(fm, feeds_py: Path, feed_dir: Path) -> dict:
    files = {}
    for name, cfg in sorted(getattr(fm, "FEEDS", {}).items()):
        p = feed_dir / cfg["file"]
        files[cfg["file"]] = p.stat().st_size if p.exists() else None
    return {"format": FORMAT, "feeds_py_sha256": hashlib.sha256(feeds_py.read_bytes()).hexdigest(), "files": files,
            "attrs": [a for a in STATE_ATTRS if hasattr(fm, a)]}


def dump(fm, feeds_py: Path, feed_dir: Path, dst: Path) -> dict:
    """Build time: load the feeds with the backend's own code and pickle the in-memory state."""
    t = time.perf_counter()
    fm._ensure_loaded()
    state = {a: getattr(fm, a) for a in STATE_ATTRS if hasattr(fm, a)}
    payload = {"fingerprint": fingerprint(fm, feeds_py, feed_dir), "state": state}
    tmp = dst.with_name(dst.name + ".building")
    with gzip.open(tmp, "wb", compresslevel=6) as f:
        pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)
    tmp.replace(dst)
    entries = sum(len(v) for v in (state.get("_entries") or {}).values())
    return {"status": "ok", "entries": entries, "mb": round(dst.stat().st_size / 2**20, 1),
            "s": round(time.perf_counter() - t, 2)}


def inject(fm, feeds_py: Path, feed_dir: Path, src: Path) -> dict:
    """Cold start: install the pickled state into app.analysis.feeds if the fingerprint matches.

    Holds the module's own lock for the whole (fast) load, so a scan arriving meanwhile waits ~0.3 s for the
    index instead of starting its own ~5.7 s parse, and an already-loaded module is never overwritten."""
    if not src.exists():
        return {"status": "no index"}
    t = time.perf_counter()
    lock = getattr(fm, "_lock", None)
    if lock is not None:
        lock.acquire()
    try:
        if getattr(fm, "_loaded", False):
            return {"status": "already loaded"}
        with gzip.open(src, "rb") as f:
            payload = pickle.load(f)
        want = payload.get("fingerprint") or {}
        have = fingerprint(fm, feeds_py, feed_dir)
        if want != have:
            diff = [k for k in set(want) | set(have) if want.get(k) != have.get(k)]
            return {"status": "stale (feeds.py or feed files changed since build_cloud_seed.py) - backend parses "
                              "feeds itself", "mismatch": sorted(diff)}
        for attr, value in (payload.get("state") or {}).items():
            cur = getattr(fm, attr, None)
            if isinstance(cur, dict):
                cur.clear()
                cur.update(value)
            else:
                setattr(fm, attr, value)
        fm._loaded = True
    finally:
        if lock is not None:
            lock.release()
    entries = sum(len(v) for v in (getattr(fm, "_entries", None) or {}).values())
    return {"status": "injected", "entries": entries, "ms": round((time.perf_counter() - t) * 1000, 1)}
