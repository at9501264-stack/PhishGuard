"""PhishGuard API — FastAPI application entry point.

Environment:
  PHISHGUARD_DB_PATH       SQLite file (default backend/data/phishguard.db)
  PHISHGUARD_NO_SEED=1     do not auto-seed demo data into an empty database
  PHISHGUARD_NO_SCHEDULER=1  do not start the watchlist / retention scheduler
  PHISHGUARD_CLOUD=1       hosted demo (e.g. Vercel): GET /api/health returns cloud=true, the UI shows a banner
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import db
from app.routers import bulk, community, insights, misc, scans, tools, watchlist
from app.services import bulk as bulk_service
from app.services import events, feeds_service, scanner, seed, watcher

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("phishguard")


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


TAGS = [
    {"name": "Scans", "description": "Scan URLs (ML + 60-signal analysis engine), browse history, rescan, tag, "
                                     "compare and export results."},
    {"name": "Domains", "description": "Per-domain intelligence across all scans."},
    {"name": "Bulk", "description": "Batch scanning of up to 500 URLs (JSON list or CSV/TXT upload)."},
    {"name": "Tools", "description": "URL extraction from email/SMS text and typosquat (lookalike domain) discovery."},
    {"name": "Community", "description": "PhishTank-style community reports and voting."},
    {"name": "Watchlist", "description": "CheckPhish-style continuous monitoring of URLs/domains and typosquats."},
    {"name": "Alerts", "description": "Alerts raised by scans, watchlist changes and community verification."},
    {"name": "Threat Feeds", "description": "Local threat-intelligence blocklists (OpenPhish, PhishTank, URLhaus, ...)."},
    {"name": "Analytics", "description": "Aggregated statistics for the dashboard. `range` = 24h|7d|30d|90d|all."},
    {"name": "Activity Log", "description": "Audit trail of every action."},
    {"name": "Settings", "description": "Scoring thresholds, network checks and optional VirusTotal / Safe Browsing keys."},
    {"name": "insights", "description": "v2: relationship graph, similar scans (same IP/ASN/registrar), detection funnel."},
    {"name": "System", "description": "Health and live statistics."},
    {"name": "Admin", "description": "Demo data seeding and reset."},
]

_bg: set[asyncio.Task] = set()


def _spawn(coro) -> None:
    t = asyncio.get_running_loop().create_task(coro)
    _bg.add(t)
    t.add_done_callback(_bg.discard)


async def _startup_background() -> None:
    try:  # v1 -> v2: fill trust_score/tier/threat_type/... and event entities for rows written before v2
        await asyncio.to_thread(scanner.backfill_v2)
        await asyncio.to_thread(events.backfill_entities)
    except Exception:
        log.exception("v2 backfill failed")
    try:
        if await asyncio.to_thread(feeds_service.total_entries) == 0:
            log.info("Threat feeds empty: refreshing in background")
            feeds_service.refresh_in_background("startup")
    except Exception:
        log.exception("feed bootstrap failed")
    try:
        if not env_flag("PHISHGUARD_NO_SEED") and db.scalar("SELECT COUNT(*) FROM scans", (), 0) == 0:
            log.info("Empty database: seeding demo data in background")
            await seed.run_seed()
    except Exception:
        log.exception("demo seed failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    _spawn(_startup_background())
    if not env_flag("PHISHGUARD_NO_SCHEDULER"):
        _spawn(watcher.scheduler_loop())
    try:
        bulk_service.resume_unfinished()
    except Exception:
        log.exception("bulk resume failed")
    yield
    for t in list(_bg):
        t.cancel()
    bulk_service.cancel_all()


app = FastAPI(
    title="PhishGuard API",
    version="2.0.0",
    description=(
        "**AI-Based Phishing Website Detection and Risk Analysis System Using Machine Learning.**\n\n"
        "Combines a machine-learning URL classifier (4 models, explainable features) with a multi-signal analysis "
        "engine (WHOIS, DNS, SSL, HTTP/content, brand impersonation, threat-feed reputation) and community intelligence "
        "into a 0-100 risk score: `risk = 0.6 x ML probability x 100 + 0.4 x heuristic score`, raised to >= 90 on a "
        "blacklist hit and >= 85 for a verified community report.\n\nAll timestamps are ISO-8601 UTC."
    ),
    openapi_tags=TAGS,
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"],
                   allow_headers=["*"], expose_headers=["Content-Disposition"])

for r in (scans.router, scans.domains_router, insights.router, bulk.router, tools.router, community.router,
          watchlist.router, misc.alerts_router, misc.feeds_router, misc.analytics_router, misc.events_router,
          misc.settings_router, misc.system_router, misc.admin_router):
    app.include_router(r)


@app.get("/", include_in_schema=False)
async def root():
    return {"name": "PhishGuard API", "docs": "/docs", "health": "/api/health"}
