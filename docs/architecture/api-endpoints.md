# REST API endpoints

The PhishGuard API (FastAPI, version 2.0.0) has **48 endpoints in 14 routers**. All of them are under `/api`, take
and return JSON, and use ISO-8601 UTC timestamps. There is no authentication, because this is a local / demo
academic project, and CORS allows every origin.

| | Local | Live demo |
|---|---|---|
| API base | `http://localhost:8000/api` | <https://phishguard-mini-project.vercel.app/api> |
| Swagger UI | <http://localhost:8000/docs> | <https://phishguard-mini-project.vercel.app/docs> |
| ReDoc | <http://localhost:8000/redoc> | <https://phishguard-mini-project.vercel.app/redoc> |
| OpenAPI schema | <http://localhost:8000/openapi.json> | <https://phishguard-mini-project.vercel.app/openapi.json> |

Related pages: [diagrams.md](diagrams.md) (the scan pipeline behind `POST /api/scan` is diagram 2) and
[tech-stack.md](tech-stack.md).

**How this list was checked (2026-10-25).** The tables below come from `backend/app/routers/*.py` and the
`include_router` loop in `backend/app/main.py`. They were checked against the OpenAPI schema of the imported app
(48 operations) and against the live site's `/openapi.json` (also 48). FastAPI 0.162 wraps included routers, so
`app.routes` lists only the built-in docs routes. Read the schema instead:

```bash
cd backend
PHISHGUARD_NO_SEED=1 PHISHGUARD_NO_SCHEDULER=1 .venv/bin/python -c "
from app.main import app
for path, ops in app.openapi()['paths'].items():
    for method in ops:
        print(method.upper(), path)"
```

## Routers at a glance

The routers are mounted in this order in `backend/app/main.py`:

| # | Router | Source (`backend/app/routers/`) | Prefix | Swagger tag | Endpoints |
|---|---|---|---|---|---|
| 1 | [Scans](#1-scans) | `scans.py`: `router` | `/api` | Scans | 10 |
| 2 | [Domains](#2-domains) | `scans.py`: `domains_router` | `/api` | Domains | 1 |
| 3 | [Insights](#3-insights) | `insights.py`: `router` | `/api` | insights | 3 |
| 4 | [Bulk](#4-bulk) | `bulk.py`: `router` | `/api/bulk` | Bulk | 4 |
| 5 | [Tools](#5-tools) | `tools.py`: `router` | `/api` | Tools | 2 |
| 6 | [Community](#6-community) | `community.py`: `router` | `/api/reports` | Community | 4 |
| 7 | [Watchlist](#7-watchlist) | `watchlist.py`: `router` | `/api/watchlist` | Watchlist | 5 |
| 8 | [Alerts](#8-alerts) | `misc.py`: `alerts_router` | `/api/alerts` | Alerts | 3 |
| 9 | [Threat Feeds](#9-threat-feeds) | `misc.py`: `feeds_router` | `/api/feeds` | Threat Feeds | 3 |
| 10 | [Analytics](#10-analytics) | `misc.py`: `analytics_router` | `/api/analytics` | Analytics | 5 |
| 11 | [Activity Log](#11-activity-log) | `misc.py`: `events_router` | `/api/events` | Activity Log | 1 |
| 12 | [Settings](#12-settings) | `misc.py`: `settings_router` | `/api/settings` | Settings | 2 |
| 13 | [System](#13-system) | `misc.py`: `system_router` | `/api` | System | 2 |
| 14 | [Admin](#14-admin) | `misc.py`: `admin_router` | `/api/admin` | Admin | 3 |
| | **Total** | | | | **48** |

Several analytics endpoints take a `range` query parameter: `24h`, `7d`, `30d` (default), `90d` or `all`.

---

## 1. Scans

`scans.py`, `router`, prefix `/api`

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/scan` | Scan one URL. Body: `{"url": "...", "deep": true, "source": "web"}`. The ML model and the analysis engine run at the same time, then the risk score and verdict are computed and the full `ScanResult` is stored and returned. With `deep: false`, only the URL-based checks and the ML model run (`tested_depth = lexical`). |
| `GET` | `/api/scans` | Scan history as a paginated list of `ScanSummary` rows. Filters: `q`, `verdict`, `source`, `tld`, `brand`, `min_risk`, `max_risk`, `date_from`, `date_to`, `tag`, `domain`, `blacklisted`. Pivots: `ip`, `asn`, `registrar`, `category`, `threat_type`, `tier`. `verdict`, `source`, `tld`, `category`, `threat_type`, `tier`, `ip` and `asn` accept comma-separated lists. Sorting: `sort` (`created_at`, `risk_score`, `domain`, `duration_ms`, `confidence`, `trust_score`) and `order`. Paging: `page`, `page_size` (default 25). |
| `GET` | `/api/scans/export` | Downloads the scans that match the same filters, up to 10,000 rows. `format=csv` gives the summary columns, protected against spreadsheet formula injection. `format=json` gives the full `ScanResult` objects. |
| `GET` | `/api/scans/{scan_id}` | The full `ScanResult` of one scan. |
| `PATCH` | `/api/scans/{scan_id}` | Updates the tags and notes. Body: `{"tags": ["..."], "notes": "..."}`. |
| `DELETE` | `/api/scans/{scan_id}` | Deletes a scan. |
| `POST` | `/api/scans/{scan_id}/rescan` | Runs the full pipeline again on the same URL (`deep=true` by default). It creates and returns a **new** scan with the tags carried over, so the two scans can be compared. |
| `GET` | `/api/scans/{scan_id}/compare/{other_id}` | Compares two scans. Returns both results and a `diff` list of the fields, check statuses and listed reputation sources that changed. |
| `GET` | `/api/scans/{scan_id}/dom` | The stored HTML of the final page (kept gzipped in `scan_dom`, at most 500 KB). Returns 404 when the scan has no snapshot. |
| `GET` | `/api/scans/{scan_id}/timeline` | Activity-log events for this scan and its domain, newest first. `limit` defaults to 200 (maximum 1000). |

## 2. Domains

`scans.py`, `domains_router`, prefix `/api`

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/domains/{domain}` | Domain intelligence: every scan of a host or registered domain, with its risk trend and the latest full result. |

## 3. Insights

`insights.py`, `router`, prefix `/api`

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/graph` | Relationship graph of domains, URLs, IPs, ASNs, name servers, registrars, brands, redirects and countries. Pass `scan_id` or `domain` to centre it (`depth` default 1, `limit` default 150). With no parameters it returns a global graph of about 50 recent or high-risk domains. |
| `GET` | `/api/scans/{scan_id}/similar` | The newest scans of other domains that share this scan's IP, ASN or registrar, up to 20 per list. |
| `GET` | `/api/analytics/funnel` | Detection funnel: how many scans reached each stage (Scanned, Reachable, Login/password form, Brand impersonation, Feed listed, Phishing verdict). Takes `range`. It lives in the insights router, even though its path is under `/api/analytics`. |

## 4. Bulk

`bulk.py`, `router`, prefix `/api/bulk`

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/bulk` | Creates a bulk job from a JSON list: `{"urls": ["..."], "name": "..."}`, at most 500 URLs. The URLs are scanned in the background, 5 at a time, with `source = bulk`. |
| `POST` | `/api/bulk/upload` | Creates a bulk job from an uploaded CSV file (the `url` column, or the first column) or TXT file (one URL per line), at most 5 MB. Only the first 500 URLs are used, and the response then says `truncated: true`. |
| `GET` | `/api/bulk` | Lists the bulk jobs. |
| `GET` | `/api/bulk/{job_id}` | A job's progress and per-URL results. The dashboard polls it every 2 s while the job runs. |

## 5. Tools

`tools.py`, `router`, prefix `/api`

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/extract` | Finds the URLs in pasted email or SMS text (`{"text": "..."}`), including defanged forms such as `hxxp://` and `example[.]com`. |
| `GET` | `/api/typosquat` | Generates dnstwist-style look-alike permutations of `domain` (`limit` default 60) and checks which of them resolve in DNS. |

## 6. Community

`community.py`, `router`, prefix `/api/reports`

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/reports` | Submits a community report: `{"url": "...", "label": "phishing" or "legitimate", "brand", "comment", "reporter"}`. The reporter's label counts as the first vote. A background scan starts, and `scan_id` is filled in when it finishes. |
| `GET` | `/api/reports` | Lists the reports (`status`, `q`, `page`, `page_size`). |
| `GET` | `/api/reports/{report_id}` | One report. |
| `POST` | `/api/reports/{report_id}/vote` | Votes `phishing` or `legitimate` (`{"vote": "...", "voter": "..."}`). A report is **verified** when phishing votes minus legitimate votes reach 3, and **rejected** at -3. A named voter can change their vote, while anonymous votes always add. |

## 7. Watchlist

`watchlist.py`, `router`, prefix `/api/watchlist`

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/watchlist` | Starts watching a URL or domain: `{"target": "...", "interval_minutes": 60, "monitor_typosquats": false, "label": "..."}`. The interval can be 1 minute to 7 days. The first check runs in the background scheduler within about 60 s. |
| `GET` | `/api/watchlist` | Lists the watched targets with their latest risk score and verdict. |
| `DELETE` | `/api/watchlist/{watch_id}` | Stops watching a target. |
| `POST` | `/api/watchlist/{watch_id}/run` | Runs a check now. It rescans the target (and its typosquats, if enabled) and returns the updated item. |
| `GET` | `/api/watchlist/{watch_id}/history` | The target's past checks: risk score, verdict and typosquats found. |

## 8. Alerts

`misc.py`, `alerts_router`, prefix `/api/alerts`

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/alerts` | Alerts raised by high-risk scans, watchlist changes and community verification (`unread`, `severity`, `limit` default 200). |
| `POST` | `/api/alerts/read-all` | Marks all alerts as read. |
| `POST` | `/api/alerts/{alert_id}/read` | Marks one alert as read. |

## 9. Threat Feeds

`misc.py`, `feeds_router`, prefix `/api/feeds`

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/feeds` | Status of the five local blocklists (OpenPhish, PhishTank, URLhaus, Phishing.Database, Phishing Army): entries, last update and errors, plus totals. |
| `POST` | `/api/feeds/refresh` | Downloads every feed again in a worker thread. It waits up to 120 s. If the download is still going, it returns `status: running` and finishes in the background. |
| `GET` | `/api/feeds/search` | Searches the feed entries (`q`, `limit` default 100). |

## 10. Analytics

`misc.py`, `analytics_router`, prefix `/api/analytics`. Every endpoint except `model` takes `range`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/analytics/overview` | The KPI cards: total scans; phishing, suspicious and legitimate counts; detection rate = (phishing + suspicious) / total × 100; average risk and scan time; unique domains; blocklist hits; brands impersonated. Each comes with the % change against the previous period of the same length. |
| `GET` | `/api/analytics/timeseries` | Scans over time, split by verdict, in `hour` or `day` buckets (`bucket`). |
| `GET` | `/api/analytics/distribution` | Distributions: verdicts, risk histogram, TLDs, countries, brands, sources, impersonation techniques, most-failed checks, top domains, a weekday × hour heatmap (UTC), SSL status, domain age, threat types, tiers and categories. |
| `GET` | `/api/analytics/model` | Data for the Model Lab page. From `metrics.json`: the dataset summary and each model's metrics, curves and feature importance. Live figures: predictions made, average probability, how often the other models agree with the Random Forest, and accuracy against decided community reports. |
| `GET` | `/api/analytics/performance` | Scan speed: p50, p95, p99, maximum and average duration, throughput per hour, errors and per-check error rates. |

## 11. Activity Log

`misc.py`, `events_router`, prefix `/api/events`

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/events` | The audit trail of every action, paginated. Filters: `type` (comma-separated), `q`, `entity_type` (`scan`, `domain`, `report`, `watch`, `bulk`, `settings`) and `entity_id`. Paging: `page`, `page_size` (default 50). |

## 12. Settings

`misc.py`, `settings_router`, prefix `/api/settings`

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/settings` | The current settings. The optional VirusTotal and Google Safe Browsing keys are masked (`****abcd`). |
| `PUT` | `/api/settings` | Partial update of: verdict thresholds (suspicious 35 and phishing 65 by default), network checks, screenshots (thum.io), timeout (0.5 to 60 s), retention days, DNSBL, RDAP, and the optional VirusTotal and Google Safe Browsing keys. Sending a masked key value keeps the stored key, and an empty string clears it. |

## 13. System

`misc.py`, `system_router`, prefix `/api`

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Health check: status, whether the model is loaded and its version, database state, uptime, feed entry count, a seeding flag, and `cloud`. `cloud` is true on the Vercel demo and makes the dashboard show a demo banner. |
| `GET` | `/api/stats/live` | Live stats for the Overview page, polled every 5 s: the last 10 scans, scans in the last minute and the last hour, unread alerts and the server time. |

## 14. Admin

`misc.py`, `admin_router`, prefix `/api/admin`

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/admin/seed` | Loads the demo data in the background. It does nothing if demo data is already there, unless `force=true`. A dozen well-known sites get full network scans. The rest get URL-only (lexical) + ML scans unless `deep=true`. Phishing URLs are never fetched. |
| `GET` | `/api/admin/seed` | Seed status: whether it is running, the last run and the number of demo scans. |
| `POST` | `/api/admin/reset` | Deletes scans, reports, votes, watchlist items, alerts, events and bulk jobs, but keeps the settings. `reseed=true` loads the demo data again afterwards. |

---

## Routes outside the 48

These are not counted above, because they are not part of the PhishGuard API schema:

| Method | Path | Where | Purpose |
|---|---|---|---|
| `GET` | `/docs`, `/redoc`, `/openapi.json` | Everywhere | FastAPI's built-in Swagger UI, ReDoc and the OpenAPI schema. |
| `GET` | `/` | Local backend only (port 8000) | Small JSON index that links to `/docs` and `/api/health`. On Vercel, `/` is the dashboard. |
| `GET` | `/api/_diag` | Vercel only (`deploy/cloud_app.py`) | Runtime diagnostics: Python version, cold-start timings, warm-up state, `/tmp`, memory, the seeded database. |
| `GET`, `POST` | `/api/_cron` | Vercel only (`deploy/cloud_app.py`) | Daily Vercel Cron job (02:30 UTC): up to 5 watchlist re-checks plus data retention. When `CRON_SECRET` is set, it requires `Authorization: Bearer $CRON_SECRET`. |

## Errors

| Status | When |
|---|---|
| `404` | Unknown scan, report, alert, bulk job or watchlist item, or a scan without a DOM snapshot. |
| `413` | `POST /api/bulk/upload` file larger than 5 MB. |
| `422` | Validation errors: a URL that is not http/https or has no valid host and TLD, an empty or oversized bulk list, invalid settings (for example a suspicious threshold that is not below the phishing threshold), or bad body fields. |

## Example

```bash
curl -s -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "http://paypal-login-verify.secure-account.xyz/update", "deep": true}' \
  | jq '{verdict, risk_score, trust_score, tier, threat_type, summary}'
```

For the live demo, replace `http://localhost:8000` with `https://phishguard-mini-project.vercel.app`.
