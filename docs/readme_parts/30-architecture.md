## 🏗️ Architecture

PhishGuard is a three-tier web application: two browser clients (the **React dashboard** and a **Chrome extension**), one **FastAPI REST API** with a shared scan pipeline (**ML predictor** + **analysis engine** + **risk scoring**), and a single **SQLite** database. The same code runs locally (Uvicorn + Vite) and on Vercel (one Python serverless function in demo mode plus the static frontend).

The seven diagrams below were drawn from the source code, and the file and function names in their labels point to the code behind each step. GitHub renders the Mermaid blocks inline; a static PNG of each diagram is linked underneath for viewers without Mermaid support.

| # | Diagram | What it answers |
|---|---|---|
| 1 | [High-level system architecture](#1-high-level-system-architecture) | Which parts exist and how they talk to each other |
| 2 | [Scan pipeline](#2-scan-pipeline-post-apiscan) | What happens, step by step, when a URL is scanned |
| 3 | [ML training and inference pipeline](#3-ml-training-and-inference-pipeline) | How the dataset is built, the models trained and the best one used at scan time |
| 4 | [Risk scoring decision flow](#4-risk-scoring-decision-flow) | How the ML probability, the checks, the feeds and community votes become one score |
| 5 | [Database ER diagram](#5-database-er-diagram) | The 11 SQLite tables and their relations |
| 6 | [Deployment: local vs Vercel](#6-deployment-local-vs-vercel) | How the local run and the hosted demo differ |
| 7 | [Frontend route map](#7-frontend-route-map) | Every dashboard page and the API endpoints it calls |

<!-- ARCHITECTURE_DIAGRAMS -->

### Components

**Backend API** ([`backend/app/main.py`](backend/app/main.py)): creates the FastAPI app (Swagger UI at `/docs`, ReDoc at `/redoc`, CORS open for the extension) and registers the routers. On startup it creates and migrates the SQLite schema, back-fills newer fields on old rows, downloads the threat feeds if none are loaded, seeds demo data into an empty database (unless `PHISHGUARD_NO_SEED=1`), starts the watchlist scheduler (unless `PHISHGUARD_NO_SCHEDULER=1`) and resumes unfinished bulk jobs.

| Router file | Prefix | What it serves |
|---|---|---|
| [`routers/scans.py`](backend/app/routers/scans.py) | `/api` | `POST /scan`; history with filters and pivots; export (CSV/JSON); get, tag/annotate, delete, rescan and compare scans; stored HTML (`/dom`); timeline; per-domain intelligence (`/domains/{domain}`) |
| [`routers/insights.py`](backend/app/routers/insights.py) | `/api` | Relationship graph, similar scans (same IP / ASN / registrar), detection funnel |
| [`routers/bulk.py`](backend/app/routers/bulk.py) | `/api/bulk` | Bulk jobs of up to 500 URLs from a JSON list or a CSV/TXT upload |
| [`routers/tools.py`](backend/app/routers/tools.py) | `/api` | URL extraction from email/SMS text, typosquat (look-alike domain) finder |
| [`routers/community.py`](backend/app/routers/community.py) | `/api/reports` | Community reports and voting |
| [`routers/watchlist.py`](backend/app/routers/watchlist.py) | `/api/watchlist` | Monitored URLs/domains, run-now and check history |
| [`routers/misc.py`](backend/app/routers/misc.py) | `/api/...` | Alerts, threat feeds (status, refresh, search), activity log, settings, analytics, health, live stats, demo-data admin |

| Service | Responsibility |
|---|---|
| [`services/scanner.py`](backend/app/services/scanner.py) | The scan pipeline: normalise the URL, run ML + engine + feed lookup concurrently, score, save the scan and its HTML snapshot, log the event, raise an alert for high-risk results |
| [`services/bulk.py`](backend/app/services/bulk.py) | Background asyncio workers, 5 scans at a time per job, progress stored in the database |
| [`services/watcher.py`](backend/app/services/watcher.py) | 60-second scheduler: due watchlist re-checks, typosquat monitoring, change alerts, data retention |
| [`services/community.py`](backend/app/services/community.py) | Reports and votes; a report is verified at a net score of +3 and rejected at -3 |
| [`services/analytics.py`](backend/app/services/analytics.py) | KPIs, time series, distributions, model statistics, performance and funnel for the dashboard |
| [`services/graph.py`](backend/app/services/graph.py) · [`similar.py`](backend/app/services/similar.py) | Relationship graph from stored scans; other domains on the same IP, ASN or registrar |
| [`services/events.py`](backend/app/services/events.py) | Activity log and alerts, each event linked to its scan or domain |
| [`services/filters.py`](backend/app/services/filters.py) · [`settings_service.py`](backend/app/services/settings_service.py) · [`feeds_service.py`](backend/app/services/feeds_service.py) · [`seed.py`](backend/app/services/seed.py) | Shared history/export filters; settings stored in the database (keys masked); background feed refresh; demo data (about 67 scans over 30 days, reports, votes, 3 watchlist items, alerts) |

**Analysis engine** ([`backend/app/analysis/`](backend/app/analysis)): `engine.py` `run_checks()` produces the evidence and the heuristic score. Each lookup has its own timeout, and a failure becomes an `error` check instead of failing the scan.

| Module | What it does |
|---|---|
| [`engine.py`](backend/app/analysis/engine.py) | URL parsing, DNS (dnspython), WHOIS (python-whois), GeoIP (ip-api.com, then ipwho.is), TLS handshake and certificate parsing, HTTP probe and HTML analysis (forms, links, iframes, scripts, meta refresh, security headers), optional Google Safe Browsing / VirusTotal lookups, the check list and the heuristic score |
| [`net_safety.py`](backend/app/analysis/net_safety.py) | SSRF guard: every connection to the scanned site, on every redirect hop, must resolve to a public IP on port 80, 443, 8080 or 8443 |
| [`rdap.py`](backend/app/analysis/rdap.py) | RDAP fallback when the `whois` binary is missing or fails (as on Vercel) |
| [`feeds.py`](backend/app/analysis/feeds.py) · [`dnsbl.py`](backend/app/analysis/dnsbl.py) | Local blocklists (OpenPhish, PhishTank, URLhaus, Phishing.Database, Phishing Army); DNS blocklists (Spamhaus DBL/ZEN, SURBL, URIBL, SpamCop) |
| [`popularity.py`](backend/app/analysis/popularity.py) | Tranco top-1M rank from a hashed local index |
| [`brands.py`](backend/app/analysis/brands.py) | Brand impersonation: typosquat, homoglyph, combosquat, subdomain, punycode, path and content techniques |
| [`content.py`](backend/app/analysis/content.py) | Page category, language (with translate link), parked-domain detection, resources, contacted domains, trackers |
| [`typosquat.py`](backend/app/analysis/typosquat.py) · [`text_extract.py`](backend/app/analysis/text_extract.py) | dnstwist-style permutations with async DNS resolution; URL extraction from email/SMS text (including defanged links) |

**Risk scoring** ([`backend/app/scoring.py`](backend/app/scoring.py)): `risk = round(0.6 × ML probability × 100 + 0.4 × heuristic score)`, raised to at least 90 on a blocklist hit and to at least 85 for a verified community report; 35 and 65 (editable in Settings) separate Legitimate, Suspicious and Phishing. It also caps popular and official brand domains when nothing lists them, and sets the trust score (100 − risk), the tier, the threat type, the positive and negative factors and the plain-English summary.

**Machine learning** ([`backend/ml/`](backend/ml)): [`features.py`](backend/ml/features.py) extracts lexical URL features with the same code at training and prediction time; [`train.py`](backend/ml/train.py) builds the dataset, trains Logistic Regression, Decision Tree, Random Forest and SVM, evaluates them and writes [`artifacts/`](backend/ml/artifacts) (`*.joblib` + `metrics.json`); [`predictor.py`](backend/ml/predictor.py) loads the models once, predicts with the best one (Random Forest), returns all four probabilities and the top feature impacts; [`collect_legit.py`](backend/ml/collect_legit.py) optionally samples real legitimate deep links from public sitemaps.

**Database** ([`backend/app/db.py`](backend/app/db.py)): SQLite in WAL mode with tables `scans`, `scan_dom` (gzipped HTML snapshots), `reports`, `votes`, `watchlist`, `watch_checks`, `alerts`, `events`, `bulk_jobs`, `bulk_items` and `settings`.

**Frontend** ([`frontend/src/`](frontend/src)): React 19 + TypeScript, built with Vite and styled with Tailwind CSS. [`App.tsx`](frontend/src/App.tsx) lazy-loads one chunk per page inside a shared [`Layout`](frontend/src/layout/Layout.tsx) (sidebar, quick-scan box, alerts bell, light/dark/system theme, API health dot, demo-mode banner). Data comes through [`api/client.ts`](frontend/src/api/client.ts) and [`api/client_v2.ts`](frontend/src/api/client_v2.ts) with TanStack Query.

| Route | Page | Route | Page |
|---|---|---|---|
| `/` | Overview | `/graph` | Relationship graph |
| `/scan` | Scan (URL, email/SMS text, QR code) | `/model` | Model Lab |
| `/scans/:id` | Scan report (15 tabs) | `/watchlist` | Watchlist |
| `/history` | History | `/typosquat` | Typosquat finder |
| `/domains/:domain` | Domain intelligence | `/community` | Community reports |
| `/bulk`, `/bulk/:id` | Bulk scan | `/feeds` | Threat feeds |
| `/analytics` | Analytics | `/alerts` · `/activity` | Alerts · Activity log |
| `/settings` | Settings | `/api-guide` | API guide |

The report page ([`pages/Report.tsx`](frontend/src/pages/Report.tsx) + [`pages/report/`](frontend/src/pages/report)) has 15 tabs: Summary, ML Explanation, Domain, Geo & Hosting, SSL, HTTP, Content, Resources, Brand, Reputation, Screenshot (a thum.io page image, when enabled in Settings), Source, Graph, Timeline and Raw JSON. Shared components in [`components/`](frontend/src/components) include `RiskGauge`, `VerdictBadge`, `Kpi` (with sparklines), `ChartCard`, `DataTable` (with pagination), `ForceGraph` (d3-force), `Tabs`, `Modal`/`Drawer`, `Toast`, `Skeleton`, `EmptyState` and `RangeSelect`.

**Chrome extension** ([`extension/`](extension)): plain JavaScript, Manifest V3. The service worker quick-scans pages as you browse (cached for 30 minutes), colours the toolbar badge, notifies you when a page is flagged as phishing and adds a "Scan link with PhishGuard" context-menu item; for flagged pages it can inject a warning banner (`content/banner.js`); the popup runs a deep scan of the current tab and links to the full report; the options page sets the backend and dashboard URLs and the auto-scan and banner toggles.

**Vercel deployment** ([`api/index.py`](api/index.py), [`deploy/`](deploy), [`vercel.json`](vercel.json)): the static frontend plus one Python function that copies a bundled demo-data snapshot into `/tmp`, runs with `PHISHGUARD_CLOUD=1` (the UI shows a demo banner) and uses a daily Vercel Cron job for watchlist checks.
