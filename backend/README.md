# PhishGuard backend (FastAPI + SQLite + scikit-learn)

B.Tech mini-project demo: AI-based phishing website detection and risk analysis.

```bash
cd backend
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --port 8100      # API docs at http://localhost:8100/docs
```

## Environment

| Variable | Default | Effect |
|---|---|---|
| `PHISHGUARD_DB_PATH` | `backend/data/phishguard.db` | SQLite file (created + migrated on startup) |
| `PHISHGUARD_NO_SEED` | unset | `1` = do not auto-seed demo data into an empty DB |
| `PHISHGUARD_NO_SCHEDULER` | unset | `1` = do not start the watchlist / retention scheduler |
| `PHISHGUARD_CLOUD` | unset | `1` = hosted demo; `GET /api/health` returns `cloud: true` (UI shows a demo banner) |

## Scoring

- v1: `risk = round(0.6 * ML probability * 100 + 0.4 * heuristic score)`; blacklist hit -> risk >= 90,
  verified community report -> risk >= 85. Popular (Tranco top-10k) / official brand domain with no feed hit -> capped at 30.
- v2 (`app/scoring.py::finalize`): `trust_score = 100 - risk`; `tier` = Trusted [0,15) / Favorable [15,S) /
  Neutral [S,(S+P)/2) / Questionable [(S+P)/2,P) / Untrusted [P,100] (S/P = suspicious/phishing thresholds from settings);
  `tested_depth` full|lexical; `threat_type` malware > social_engineering > unwanted_software > none;
  `factors {positive, negative}`; 2-4 sentence `summary`; "PhishGuard ML" appended to `reputation.engines` and
  `engine_ratio` recomputed.

## Storage notes

- v2 columns on `scans` (`ip, asn, registrar, threat_type, trust_score, tier, category, tested_depth`) and on `events`
  (`entity_type, entity_id, scan_id, domain`) are added by an idempotent migration (`db.migrate`, PRAGMA-guarded).
  Rows from before v2 are backfilled at startup.
- The page HTML (`dom_html`) is stored gzipped in `scan_dom` (max 500 KB), never in the scan JSON; scans expose `has_dom`.

## v2 endpoints (owned here)

- `GET /api/scans` and `/api/scans/export`: pivot filters `ip, asn, registrar, category, threat_type, tier` (+ v1 filters).
- `GET /api/scans/{id}/dom` -> `{html, size, truncated, source}` (404 when there is no snapshot).
- `GET /api/scans/{id}/timeline` -> events for the scan and its domain, newest first.
- `GET /api/events?entity_type=&entity_id=`.
- Graph, similar scans and funnel live in `app/routers/insights.py`.
