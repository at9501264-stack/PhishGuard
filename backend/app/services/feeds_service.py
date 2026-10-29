"""Wrapper around app.analysis.feeds with background refresh management."""
from __future__ import annotations

import asyncio
import logging

from app.services.events import log_event

log = logging.getLogger("phishguard.feeds")
_refresh_task: asyncio.Task | None = None


def feeds_mod():
    from app.analysis import feeds
    return feeds


def safe_status() -> list[dict]:
    try:
        return feeds_mod().feed_status() or []
    except Exception as e:
        log.warning("feed_status failed: %s", e)
        return []


def safe_stats() -> dict:
    try:
        return feeds_mod().stats() or {}
    except Exception as e:
        log.warning("feeds stats failed: %s", e)
        return {"total_entries": 0, "by_feed": {}, "top_domains_tlds": [], "top_targets": []}


def total_entries() -> int:
    try:
        return int(safe_stats().get("total_entries") or 0)
    except Exception:
        return 0


async def _do_refresh(reason: str) -> dict:
    try:
        res = await asyncio.to_thread(feeds_mod().refresh_feeds)
    except Exception as e:
        log.exception("feed refresh failed")
        log_event("feed_refresh", f"Feed refresh failed: {e}", {"reason": reason, "error": str(e)})
        raise
    log_event("feed_refresh", f"Threat feeds refreshed ({total_entries()} entries)",
              {"reason": reason, "total_entries": total_entries()})
    return res if isinstance(res, dict) else {"result": res}


def refresh_in_background(reason: str = "manual") -> asyncio.Task:
    global _refresh_task
    if _refresh_task is None or _refresh_task.done():
        _refresh_task = asyncio.get_running_loop().create_task(_do_refresh(reason))
        _refresh_task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
    return _refresh_task


def is_refreshing() -> bool:
    return _refresh_task is not None and not _refresh_task.done()


async def wait_for_refresh(timeout: float) -> bool:
    if not is_refreshing():
        return True
    try:
        await asyncio.wait_for(asyncio.shield(_refresh_task), timeout=timeout)
        return True
    except Exception:
        return False
