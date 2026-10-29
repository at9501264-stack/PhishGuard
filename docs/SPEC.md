# PhishGuard — Shared Build Spec (contract for all agents)

Project: "AI-Based Phishing Website Detection and Risk Analysis System Using Machine Learning"
(B.Tech mini project, Ayushi Tiwari). Full-stack analytics dashboard that merges the features of
VirusTotal, urlscan.io, Google Safe Browsing, PhishTank, OpenPhish, URLVoid, CheckPhish (Bolster),
Sucuri SiteCheck, ScamAdviser, IPQualityScore, Norton Safe Web, Cisco Talos.

Root: `/Users/lalamansingh/Desktop/Ayushi Wrok 2/phishguard/`
- `backend/` — Python 3.12, FastAPI, SQLite. venv at `backend/.venv` (already created; install extra
  deps with `uv pip install --python backend/.venv/bin/python <pkg>`). Installed: fastapi, uvicorn,
  scikit-learn, pandas, numpy, joblib, httpx, dnspython, python-whois, tldextract, beautifulsoup4,
  python-multipart.
- `frontend/` — Vite + React + TypeScript + Tailwind + Recharts + react-router + lucide-react.
- Backend runs on `http://localhost:8000`, frontend dev server on `http://localhost:5173` with Vite proxy `/api` → 8000.
- Run backend from `backend/`: `.venv/bin/uvicorn app.main:app --port 8000`. Python imports are rooted at `backend/` (`app.*`, `ml.*`).

## Ownership (do NOT edit files you don't own; other agents work in parallel)
| Agent | Owns |
|---|---|
| ML | `backend/ml/**` (features.py, train.py, predictor.py, artifacts/, data download under `backend/ml/data/`) |
| Engine | `backend/app/analysis/**` |
| API | `backend/app/main.py`, `backend/app/db.py`, `backend/app/scoring.py`, `backend/app/routers/**`, `backend/app/services/**`, `backend/requirements.txt` |
| Frontend | `frontend/**` |
| Research | `docs/FEATURES.md` |

Stub files with the exact signatures already exist; owners replace the stubs with real code but keep signatures.

---
## 1. ML module contract (`backend/ml/`)
Only URL/lexical features (no network) so prediction is instant.
```python
# ml/features.py
FEATURE_LABELS: dict[str, str]          # feature_name -> human label, e.g. "url_length": "URL length"
def extract_features(url: str) -> dict[str, float]   # deterministic, never raises

# ml/predictor.py
def predict(url: str) -> dict
# returns {
#   "model_name": "Random Forest", "model_version": "2026.10.24-1",
#   "probability_phishing": 0.0-1.0,
#   "per_model": [{"name": "Logistic Regression", "probability": 0.8}, ...],   # all 4 models
#   "explanations": [{"feature": "num_subdomains", "label": "Number of subdomains", "value": 4,
#                     "impact": 0.12, "direction": "risk"|"safe"}],   # top ~10 by |impact|, signed
#   "features": {feature_name: value}
# }
def model_info() -> dict   # contents of artifacts/metrics.json (see below)
```
`backend/ml/artifacts/metrics.json`:
```json
{ "version": "...", "trained_at": "ISO",
  "dataset": {"name","source","total","phishing","legitimate","train_size","test_size"},
  "best_model": "Random Forest",
  "models": [{"name","accuracy","precision","recall","f1","roc_auc","train_time_s","predict_time_ms",
              "cv_f1_mean","cv_f1_std","confusion_matrix":[[tn,fp],[fn,tp]],
              "roc_curve":{"fpr":[...],"tpr":[...]}, "pr_curve":{"precision":[...],"recall":[...]}}],
  "feature_importance": [{"feature","label","importance"}],
  "feature_stats": [{"feature","label","mean_phishing","mean_legitimate"}] }
```
Curves downsampled to ≤100 points.

## 2. Analysis engine contract (`backend/app/analysis/`)
```python
# app/analysis/engine.py
async def run_checks(url: str, settings: dict) -> dict
# settings keys: enable_network_checks: bool, enable_screenshots: bool, timeout_s: float,
#                virustotal_api_key: str|None, google_safe_browsing_api_key: str|None
# returns {
#   "domain_info": {...}, "ssl": {...}, "http": {...}, "brand": {...},
#   "reputation": {"blacklisted": bool, "sources": [{"name","listed","detail"}]},
#   "screenshot_url": str|None,
#   "checks": [Check], "heuristic_score": 0-100
# }
# must never raise; each sub-check failure -> status "error" and continue. Overall budget ~10s.

# app/analysis/feeds.py   (local threat-intel blocklists: OpenPhish, PhishTank, URLhaus, etc.)
def refresh_feeds() -> dict          # downloads, stores in backend/data/feeds/, returns feed_status()
def feed_status() -> list[dict]      # [{"name","url","entries","last_updated","status"}]
def lookup(url: str) -> list[dict]   # [{"name","listed":True,"detail"}] for feeds containing url/domain
def search_entries(q: str, limit: int = 100) -> list[dict]  # [{"url","domain","feed","target"}]
def stats() -> dict                  # {"total_entries", "by_feed": {...}, "top_domains_tlds": [...], "top_targets": [...]}

# app/analysis/typosquat.py
def generate_permutations(domain: str) -> list[dict]   # [{"domain","technique"}] dnstwist-style
async def check_permutations(domain: str, limit: int = 60) -> list[dict]  # + "resolves": bool, "ip": str|None

# app/analysis/text_extract.py
def extract_urls(text: str) -> list[str]   # from email/SMS text, handles defanged hxxp / [.]
```
Check object: `{"id": "ssl_valid", "category": "lexical|domain|network|ssl|content|reputation|brand",
"name": "Valid SSL certificate", "status": "pass|warn|fail|info|error", "detail": "...", "weight": 0-10}`

Sub-objects:
- `domain_info`: `{domain, registered_domain, subdomain, tld, is_ip, punycode, whois: {registrar, creation_date, expiry_date, updated_date, age_days, days_to_expiry, privacy_protected, country}, dns: {a:[],aaaa:[],mx:[],ns:[],txt:[]}, ip, geo: {country, country_code, city, asn, org, isp, lat, lon, hosting}}`
- `ssl`: `{enabled, valid, issuer, subject, san:[], not_before, not_after, days_left, age_days, protocol, self_signed, error}`
- `http`: `{reachable, final_url, status_code, response_ms, redirect_chain:[{url,status}], server, title, security_headers: {hsts, csp, x_frame_options, x_content_type_options, referrer_policy, permissions_policy} (bool each), technologies:[], forms: {count, password_fields, external_actions, login_form}, links: {internal, external, null_links, external_ratio}, iframes, external_scripts, meta_refresh, page_size_kb, favicon_external, suspicious_js: [..], error}`
- `brand`: `{impersonated_brand: str|None, similarity: 0-1, technique: "typosquat|homoglyph|combosquat|subdomain|punycode|path|content"|None, details}`

## 3. Scoring (API agent, `app/scoring.py`)
`risk_score = round(0.6 * ml_prob*100 + 0.4 * heuristic_score)`; blacklist hit → max(risk, 90);
verified community phishing report → max(risk, 85). Verdict thresholds from settings
(`suspicious_threshold` default 35, `phishing_threshold` default 65). `confidence` = distance from
nearest threshold normalised 0-1. Also `score_breakdown: [{component, score, weight}]`.
If network checks disabled, heuristic is lexical-only from engine.

## 4. REST API (prefix `/api`, JSON, ISO-8601 UTC timestamps)
ScanResult (full) =
```
{ id, url, normalized_url, domain, registered_domain, tld, created_at, duration_ms, source,
  verdict: "legitimate"|"suspicious"|"phishing", risk_score, confidence,
  ml: {model_name, model_version, probability_phishing, per_model, explanations},
  features: {...}, checks: [Check], domain_info, ssl, http, brand,
  reputation: {blacklisted, sources, community: {reports, phishing_votes, legitimate_votes, status}},
  screenshot_url, score_breakdown, tags: [str], notes: str|null }
```
ScanSummary = `{id, url, domain, tld, created_at, verdict, risk_score, confidence, source, brand: impersonated_brand, country_code, blacklisted, duration_ms}`

Endpoints:
- `GET /api/health` → `{status, model_loaded, model_version, db, uptime_s, feeds_entries}`
- `POST /api/scan` body `{url, deep?: true, source?: "web"|"api"|"bulk"|"text"|"qr"|"watch"|"extension"}` → ScanResult. 422 for invalid URL (adds http:// if scheme missing).
- `GET /api/scans?q=&verdict=&source=&tld=&brand=&min_risk=&max_risk=&date_from=&date_to=&sort=created_at|risk_score&order=desc&page=1&page_size=25` → `{items: ScanSummary[], total, page, page_size}`
- `GET /api/scans/{id}` → ScanResult · `DELETE /api/scans/{id}` · `POST /api/scans/{id}/rescan` → ScanResult
- `PATCH /api/scans/{id}` body `{tags?, notes?}` → ScanResult
- `GET /api/scans/{id}/compare/{other_id}` → `{a: ScanResult, b: ScanResult, diff: [{field, a, b}]}`
- `GET /api/scans/export?format=csv|json&<same filters>` → file download
- `GET /api/domains/{domain}` → `{domain, scans: ScanSummary[], first_seen, last_seen, scan_count, avg_risk, latest: ScanResult|null, risk_trend: [{t, risk}]}`
- `POST /api/bulk` body `{urls: string[], name?}` (≤500) → `{job_id}`; `GET /api/bulk` → jobs list `[{id,name,status,total,done,created_at,verdict_counts}]`; `GET /api/bulk/{id}` → job + `results: ScanSummary[]`; `POST /api/bulk/upload` multipart CSV/TXT file → `{job_id}`
- `POST /api/extract` body `{text}` → `{urls: string[]}`
- `GET /api/typosquat?domain=` → `{domain, total_generated, results: [{domain, technique, resolves, ip}]}`
- Community (PhishTank-style): `POST /api/reports` `{url, label: "phishing"|"legitimate", brand?, comment?, reporter?}` → Report; `GET /api/reports?status=pending|verified|rejected&page=` → `{items, total}`; `POST /api/reports/{id}/vote` `{vote: "phishing"|"legitimate", voter?}` → Report. Report = `{id, url, domain, label, brand, comment, reporter, created_at, phishing_votes, legitimate_votes, status, scan_id}`. Status verified when phishing_votes - legitimate_votes ≥ 3, rejected when ≤ -3. Creating a report triggers a scan.
- Watchlist (CheckPhish-style monitoring): `POST /api/watchlist` `{target: url-or-domain, interval_minutes: 60, monitor_typosquats: bool, label?}`; `GET /api/watchlist` → `[{id, target, label, interval_minutes, monitor_typosquats, created_at, last_checked, last_risk, last_verdict, change: "up"|"down"|"same"|null, alerts}]`; `DELETE /api/watchlist/{id}`; `POST /api/watchlist/{id}/run`; `GET /api/watchlist/{id}/history` → `{checks: [{t, risk_score, verdict, scan_id}], typosquats: [...]}`. A background asyncio loop re-checks due items every 60s and creates alerts on verdict change / new resolving typosquat.
- Alerts: `GET /api/alerts?unread=` → `[{id, type, severity: "info|warning|critical", title, detail, created_at, read, scan_id, watch_id}]`; `POST /api/alerts/{id}/read`; `POST /api/alerts/read-all`
- Feeds: `GET /api/feeds` → `{feeds: feed_status(), stats: stats()}`; `POST /api/feeds/refresh`; `GET /api/feeds/search?q=`
- Analytics (`range=24h|7d|30d|90d|all`, default 30d):
  - `GET /api/analytics/overview` → `{total_scans, phishing, suspicious, legitimate, detection_rate, avg_risk, avg_duration_ms, unique_domains, blacklisted_hits, brands_impersonated, reports_total, reports_verified, watch_count, unread_alerts, delta: {total_scans, phishing, avg_risk} (percent vs previous equal period)}`
  - `GET /api/analytics/timeseries?range=&bucket=hour|day` → `[{t, total, phishing, suspicious, legitimate, avg_risk}]`
  - `GET /api/analytics/distribution?range=` → `{verdicts:[{name,value}], risk_histogram:[{bucket:"0-10",count}], tlds:[{name,value}], countries:[{code,name,value}], brands:[{name,value}], sources:[{name,value}], techniques:[{name,value}], checks_failed:[{id,name,count}], top_domains:[{domain,count,avg_risk}], heatmap:[{weekday:0-6,hour:0-23,count}], ssl:[{name,value}], domain_age:[{bucket,count}]}`
  - `GET /api/analytics/model` → metrics.json + `{live: {predictions, avg_probability, agreement_rate (models agreeing with best), feedback_accuracy (vs verified reports)}}`
  - `GET /api/analytics/performance?range=` → `{p50_ms, p95_ms, p99_ms, max_ms, throughput_per_hour:[{t,count}], errors, check_error_rates:[{id,rate}]}`
- Activity log: `GET /api/events?type=&page=&page_size=` → `{items: [{id, type, message, meta, created_at}], total}` — every scan, rescan, delete, report, vote, bulk job, watch change, settings change, feed refresh, export is logged.
- Settings: `GET /api/settings` / `PUT /api/settings` → `{suspicious_threshold, phishing_threshold, enable_network_checks, enable_screenshots, timeout_s, virustotal_api_key (masked "****abcd" on GET), google_safe_browsing_api_key (masked), retention_days}`
- `GET /api/stats/live` → `{last_scans: ScanSummary[10], scans_last_minute, scans_last_hour}` (frontend polls every 5s).

DB: SQLite at `backend/data/phishguard.db`. CORS allow all. Seed: on first run if DB empty, API agent may run a demo seed script `app/services/seed.py` that scans ~60 known URLs (mix of legit top sites and feed phishing URLs) with timestamps spread over the last 30 days so the dashboard isn't empty (mark tag "demo").

## 5. Frontend pages (minimal, analytical design; light + dark)
Sidebar nav: Overview · Scan · History · Bulk Scan · Analytics · Model Lab · Watchlist · Typosquat · Community · Threat Feeds · Alerts · Activity Log · Settings · API Docs (link to `/docs` on backend).
Scan report page `/scans/:id` with tabs: Summary (gauge, verdict, breakdown, checks), ML Explanation, Domain & WHOIS & DNS, Geo/Hosting, SSL, HTTP & Content (redirect chain, headers, forms), Brand, Reputation, Screenshot, Raw JSON; actions: rescan, report, vote, tag/notes, export JSON, print/PDF, copy share link, compare with previous scan.
