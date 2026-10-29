# PhishGuard architecture diagrams

These diagrams cover **PhishGuard — AI-Based Phishing Website Detection and Risk Analysis System Using Machine
Learning** (B.Tech mini project). They were drawn from the source code (`backend/app`, `backend/ml`, `frontend/src`,
`deploy/`, `vercel.json`). File and function names in the labels point to the code that does each step.

GitHub renders the Mermaid blocks directly. Each diagram also has a static PNG in [`img/`](img/) (rendered with
Mermaid 11.4.1) for viewers that do not support Mermaid, such as Word, PDF exports or slides.

| # | Diagram | PNG |
|---|---------|-----|
| 1 | [High-level system architecture](#1-high-level-system-architecture) | [system-architecture.png](img/system-architecture.png) |
| 2 | [Scan pipeline (sequence)](#2-scan-pipeline-post-apiscan) | [scan-pipeline-sequence.png](img/scan-pipeline-sequence.png) |
| 3 | [ML training and inference pipeline](#3-ml-training-and-inference-pipeline) | [ml-pipeline.png](img/ml-pipeline.png) |
| 4 | [Risk scoring decision flow](#4-risk-scoring-decision-flow) | [risk-scoring.png](img/risk-scoring.png) |
| 5 | [Database ER diagram](#5-database-er-diagram) | [database-er.png](img/database-er.png) |
| 6 | [Deployment: local vs Vercel](#6-deployment-local-vs-vercel) | [deployment.png](img/deployment.png) |
| 7 | [Frontend route map](#7-frontend-route-map) | [frontend-routes.png](img/frontend-routes.png) |

Related references: [tech-stack.md](tech-stack.md) (libraries and versions) and [api-endpoints.md](api-endpoints.md)
(all 48 REST endpoints).

---

## 1. High-level system architecture

PhishGuard is a three-tier web application. There are two browser clients: the React dashboard and a Manifest V3
Chrome extension. Both call one FastAPI REST API (48 endpoints in 14 routers). Every scan goes through the same
`perform_scan()` pipeline, whether it comes from the dashboard, the extension, a bulk job, the watchlist scheduler
or a community report. That pipeline runs the ML predictor and the analysis engine side by side. Only the engine
talks to the internet. Live probes of the scanned site (HTTP and TLS) go through the SSRF guard, while DNS,
WHOIS/RDAP, DNSBL and geo-IP are third-party lookups. Threat feeds and the Tranco list are local files, and all
state is kept in one SQLite database.

<!-- diagram: system-architecture -->
```mermaid
flowchart TB
    subgraph clients["Clients (browser)"]
        uiDash["React dashboard<br/>Vite SPA, 19 routes"]
        uiExt["Chrome extension<br/>Manifest V3: popup,<br/>context menu, banner"]
    end

    subgraph apiLayer["REST API"]
        apiRouters["FastAPI app.main<br/>14 routers, 48 endpoints<br/>Swagger UI at /docs"]
    end

    subgraph services["Services"]
        direction LR
        svcBulk["Bulk jobs<br/>max 500 URLs,<br/>5 at a time"]
        svcWatch["Watcher<br/>60 s scheduler<br/>+ retention"]
        svcCommunity["Community<br/>reports + votes"]
        svcAnalytics["Analytics, graph,<br/>similar scans"]
        svcScanner["Scanner<br/>perform_scan()"]
        svcEvents["Events + alerts"]
        svcBulk --> svcScanner
        svcWatch --> svcScanner
        svcCommunity --> svcScanner
        svcScanner --> svcEvents
    end

    subgraph core["Detection core"]
        mlPredictor["ML predictor<br/>4 models,<br/>Random Forest decides"]
        engine["Analysis engine<br/>run_checks(),<br/>about 60 checks"]
        guard["SSRF guard<br/>net_safety.py"]
    end

    subgraph localData["Local data files"]
        direction LR
        artifacts["Model artifacts<br/>4 x .joblib + metrics.json"]
        feeds["Threat feeds: OpenPhish,<br/>PhishTank, URLhaus,<br/>Phishing.Database,<br/>Phishing Army"]
        tranco["Tranco top-1M index"]
    end

    subgraph internet["Third-party lookups"]
        direction LR
        extDns["DNS resolvers"]
        extWhois["WHOIS / RDAP"]
        extDnsbl["DNSBL: Spamhaus,<br/>SURBL, URIBL, SpamCop"]
        extGeo["Geo-IP: ip-api.com,<br/>ipwho.is"]
        extOptional["Optional: Google Safe<br/>Browsing, VirusTotal"]
    end

    extTarget["Scanned website<br/>HTTP pages +<br/>TLS certificate"]
    db[("SQLite, WAL mode<br/>backend/data/<br/>phishguard.db")]

    clients -->|"JSON over HTTP"| apiLayer
    apiLayer --> services
    services -->|"read / write"| db
    svcScanner -->|"in parallel"| mlPredictor
    svcScanner -->|"in parallel"| engine
    mlPredictor --> artifacts
    engine --> feeds
    engine --> tranco
    engine --> internet
    engine --> guard
    guard -->|"live probes"| extTarget
```

---

## 2. Scan pipeline (`POST /api/scan`)

`perform_scan()` in `services/scanner.py` first checks and normalises the URL. Then it runs three tasks at the same
time with `asyncio.gather`: the ML prediction (in a thread), the analysis engine, and a threat-feed lookup on the
API side. Inside the engine the SSRF guard runs first. If the host resolves to a private address or uses a port
that is not allowed, the TLS and HTTP probes are skipped and a `private_network_host` check is added. The scores
are combined in `app/scoring.py`. The result is stored as indexed columns plus the full JSON document, and an event
(and sometimes a critical alert) is written before the `ScanResult` is returned. With `deep=false`, or with network
checks turned off in Settings, only the URL-based checks and the ML model run, and the result is marked
`tested_depth = lexical`.

<!-- diagram: scan-pipeline-sequence -->
```mermaid
sequenceDiagram
    autonumber
    participant C as Client<br/>(dashboard / extension)
    participant R as API router<br/>routers/scans.py
    participant S as Scanner<br/>services/scanner.py
    participant M as ML predictor<br/>ml/predictor.py
    participant E as Analysis engine<br/>analysis/engine.py
    participant N as Network<br/>(DNS, WHOIS/RDAP, TLS,<br/>HTTP, DNSBL, geo-IP)
    participant K as Scoring<br/>app/scoring.py
    participant D as SQLite

    C->>R: POST /api/scan {url, deep, source}
    R->>S: perform_scan(url, source, deep)
    Note over S: normalize_url(): add http:// if missing,<br/>http/https only, valid host and TLD,<br/>otherwise HTTP 422
    S->>D: get_settings(): thresholds, timeout, toggles
    par ML model (worker thread)
        S->>M: predict(normalized_url)
        Note over M: 44 lexical features,<br/>4 model probabilities,<br/>perturbation explanations
        M-->>S: probability_phishing, per_model, explanations
    and Analysis engine (budget max(25 s, 2 × timeout + 10 s))
        S->>E: run_checks(url, engine_settings)
        E->>N: SSRF guard: resolve host, every IP must be public,<br/>port 80, 443, 8080 or 8443
        par network probes (asyncio.gather)
            E->>N: DNS A/AAAA/MX/NS/TXT, then geo-IP + IP DNSBL
            E->>N: WHOIS, with RDAP fallback
            E->>N: TLS handshake on port 443
            E->>N: HTTP probe, every redirect hop re-checked
            E->>N: domain DNSBL, optional Safe Browsing / VirusTotal
        end
        Note over E: local feeds + Tranco rank,<br/>brand detection, content analysis<br/>(category, language, parked)
        Note over E: build_checks() + score_checks()<br/>= heuristic score 0-100
        E-->>S: checks, domain_info, ssl, http, brand,<br/>reputation, heuristic_score, dom_html
    and Threat-feed lookup (worker thread)
        Note over S: feeds.lookup(normalized_url)<br/>against the local feed sets
    end
    S->>D: community_for(domain, url) from reports
    S->>K: compute_score(ml_prob, heuristic, blacklisted, community_verified)
    K-->>S: risk = round(0.6 × ML × 100 + 0.4 × heuristic),<br/>floors 90 / 85, verdict, confidence
    S->>K: finalize(result, settings)
    K-->>S: popular/official cap 30, trust score, tier,<br/>threat type, factors, summary
    S->>D: INSERT scans (columns + JSON), scan_dom (gzipped HTML)
    S->>D: log_event("scan") into events
    opt verdict is phishing and (risk ≥ 80 or blacklisted), and no alert for this domain in the last hour
        S->>D: create_alert("high_risk_scan", critical)
    end
    S-->>R: ScanResult
    R-->>C: 200 OK with the ScanResult JSON
```

---

## 3. ML training and inference pipeline

Training (`python -m ml.train`, about 100 s) reads only local snapshots under `backend/ml/data/raw/`. After
deduplication and bias fixes, the dataset has 146,364 URLs. It is split by *campaign key* (registered domain, or the
tenant host on free-hosting platforms), so no campaign appears in both train and test. All four models are trained
twice, with and without the `uses_https` feature. The scheme-free variant (44 features) was kept because it is more
robust on a held-out "modern" set of 4,000 URLs. Random Forest has the best test F1 and makes the decision. The other
three models are still shown on every scan report.

<!-- diagram: ml-pipeline -->
```mermaid
flowchart TB
    subgraph sources["Data sources: snapshots in backend/ml/data/raw"]
        srcPhiusiil["PhiUSIIL, UCI dataset 967<br/>45,000 phishing<br/>40,753 legit"]
        srcPhishtank["PhishTank<br/>verified-online<br/>16,000 phishing"]
        srcPhishdb["Phishing.Database<br/>ACTIVE list<br/>12,000 phishing"]
        srcOpenphish["OpenPhish feed<br/>241 phishing"]
        srcTranco["Tranco top-30k<br/>21,825 legit domains<br/>6,448 legit sub-domains"]
        srcSitemaps["Sitemaps of<br/>Tranco sites<br/>4,097 legit deep links"]
    end

    subgraph prep["Cleaning and bias mitigation"]
        direction LR
        prepClean["Normalise: lower-case,<br/>no trailing slash<br/>Dedupe across sources<br/>Max 3 URLs per campaign"]
        prepAugment["Legit hosts augmented:<br/>www toggled, about 40%<br/>get deep-link paths<br/>Host-only feeds get an<br/>imputed scheme and path"]
        prepDataset["Dataset: 146,364 URLs<br/>73,241 phishing<br/>73,123 legitimate"]
        prepClean --> prepAugment --> prepDataset
    end

    featExtract["extract_features() in ml/features.py<br/>45 lexical URL features<br/>scheme-free variant keeps 44"]
    split["StratifiedGroupKFold 80/20<br/>grouped by campaign key<br/>train 117,092 / test 29,272"]

    subgraph models["Four scikit-learn classifiers"]
        mLr["Logistic Regression<br/>test F1 0.8045"]
        mDt["Decision Tree<br/>depth 20<br/>test F1 0.8372"]
        mRf["Random Forest<br/>150 trees<br/>test F1 0.8561<br/>ROC-AUC 0.9449"]
        mSvm["SVM: Nystroem RBF<br/>+ LinearSVC, calibrated<br/>test F1 0.8329"]
    end

    evalTest["Test metrics: accuracy, precision,<br/>recall, F1, ROC-AUC, confusion matrix,<br/>ROC and PR curves, 5-fold group CV<br/>(RF CV F1 0.855 ± 0.002)"]
    evalModern["Held-out modern set, 4,000 URLs:<br/>PhishTank + Phishing.Database +<br/>Tranco ranks 30k-60k deep links<br/>picks the feature variant"]
    best["Best test F1: Random Forest<br/>saved to backend/ml/artifacts:<br/>4 x .joblib + metrics.json<br/>version 2026.10.24-1812"]

    subgraph infer["Inference at scan time: ml/predictor.py"]
        direction LR
        inferPredict["predict(url): artifacts loaded<br/>once, lazy and thread-safe<br/>44 features, 4 probabilities<br/>Random Forest value is used"]
        inferExplain["Explanations: each differing<br/>feature reset to the legit median<br/>change in probability = impact<br/>top 10 returned"]
        inferPredict --> inferExplain
    end

    sources --> prep
    prep --> featExtract --> split --> models
    models --> evalTest
    models --> evalModern
    evalTest --> best
    evalModern -.->|"variant choice"| best
    best --> infer
```

---

## 4. Risk scoring decision flow

The final risk score combines the ML probability (60%) with the engine's heuristic score (40%). A hit on any
blocklist raises the score to at least 90, and a verified community report raises it to at least 85. `finalize()`
then caps the score at 30 for popular or official domains, but only when nothing lists them and there is no malware
evidence. It also derives the trust score, the reputation tier and the threat type, with malware taking precedence
over social engineering and unwanted software. Confidence (not drawn) is the distance from the nearest threshold,
and it is at least 0.9 when a blocklist or verified report decided the score. Note: the popularity cap checks the
`popular_site` check, which passes for any domain that has a Tranco rank. So in practice it applies to every Tranco
top-1M domain, not only the top 10k mentioned in the code's docstring.

<!-- diagram: risk-scoring -->
```mermaid
flowchart LR
    subgraph stHeur["Heuristic score h: engine.py"]
        direction TB
        hRaw["raw = sum of failed-check weights<br/>+ 0.4 × sum of warning weights"]
        hCurve["h = 100 × (1 − e^(−raw / 18))"]
        hFloors["Raise h to a floor:<br/>blacklisted 92<br/>brand + login form 85<br/>password sent off-site 80<br/>brand impersonation 75<br/>malicious JavaScript 60<br/>raw IP host 55<br/>domain under 30 days 55<br/>bad redirects 50, punycode 50<br/>invalid SSL 45, risky TLD 35"]
        hCaps["Then cap h:<br/>official brand domain 15<br/>Tranco top 10k with<br/>no hard fail 20"]
        hRaw --> hCurve --> hFloors --> hCaps
    end

    subgraph stScore["Risk score and verdict: scoring.py"]
        direction TB
        base["risk = round(0.6 × p × 100 + 0.4 × h)<br/>p = ML phishing probability"]
        qBlacklist{"Blacklisted?"}
        fBlacklist["risk = max(risk, 90)"]
        qCommunity{"Verified<br/>community<br/>report?"}
        fCommunity["risk = max(risk, 85)"]
        verdict["Verdict, default thresholds:<br/>65-100 phishing<br/>35-64 suspicious<br/>0-34 legitimate"]
        base --> qBlacklist
        qBlacklist -->|"yes"| fBlacklist --> qCommunity
        qBlacklist -->|"no"| qCommunity
        qCommunity -->|"yes"| fCommunity --> verdict
        qCommunity -->|"no"| verdict
    end

    subgraph stCap["Cap and tier: finalize()"]
        direction TB
        qHard{"Any listing,<br/>verified report or<br/>malware evidence?"}
        qPopular{"Official brand<br/>domain or Tranco-<br/>ranked, not a<br/>hosting platform?"}
        fCap["Risk above 30 is<br/>capped at 30,<br/>verdict re-derived"]
        trust["trust_score = 100 − risk"]
        tier["Tier:<br/>0-14 Trusted<br/>15-34 Favorable<br/>35-49 Neutral<br/>50-64 Questionable<br/>65-100 Untrusted"]
        qHard -->|"yes: no cap"| trust
        qHard -->|"no"| qPopular
        qPopular -->|"yes"| fCap --> trust
        qPopular -->|"no"| trust
        trust --> tier
    end

    subgraph stThreat["Threat type: first match wins"]
        direction TB
        qMalware{"Malware<br/>evidence?"}
        qCapped{"Cap reason<br/>found?"}
        qSocial{"Social-<br/>engineering<br/>evidence?"}
        qUnwanted{"Unwanted-<br/>content<br/>evidence?"}
        tMalware["malware"]
        tSocial["social_engineering"]
        tUnwanted["unwanted_software"]
        tNone["none"]
        qMalware -->|"yes"| tMalware
        qMalware -->|"no"| qCapped
        qCapped -->|"yes"| tNone
        qCapped -->|"no"| qSocial
        qSocial -->|"yes"| tSocial
        qSocial -->|"no"| qUnwanted
        qUnwanted -->|"yes"| tUnwanted
        qUnwanted -->|"no"| tNone
    end

    stHeur --> stScore --> stCap --> stThreat
```

Evidence used by the threat-type step (`malware_evidence`, `social_evidence` and `unwanted_evidence` in
`app/scoring.py`):

| Threat type | Evidence |
|---|---|
| `malware` | Listed as malware by an engine (URLhaus), or the URL path ends in an executable or archive extension (`.exe`, `.apk`, `.zip`, ...) and the verdict is not legitimate |
| `social_engineering` | Listed as phishing by an external engine or feed, impersonates a brand (and is not a defensive redirect), has a login/password form while the verdict is not legitimate, or the verdict is phishing |
| `unwanted_software` | Parked domain, SEO spam or hidden iframe, or a spam-blocklist listing when the verdict is not legitimate |
| `none` | None of the above, or the domain has a popular/official cap reason |

---

## 5. Database ER diagram

There are 11 tables in one SQLite file (stdlib `sqlite3`, WAL mode, one connection per thread). `SCHEMA` in
`app/db.py` creates the v1 tables. `migrate()` adds the v2 columns (marked "v2") and the `scan_dom` table, and it is
safe to run more than once. The relationships are kept by the application code only: SQLite foreign keys are turned
off and no `REFERENCES` clauses are declared. `scans.data` holds the complete `ScanResult` JSON, and the other
`scans` columns are indexed copies used for filters, pivots and analytics.

<!-- diagram: database-er -->
```mermaid
erDiagram
    SCANS {
        INTEGER id PK
        TEXT url
        TEXT normalized_url
        TEXT domain "indexed"
        TEXT registered_domain "indexed"
        TEXT tld
        TEXT created_at "ISO-8601 UTC"
        INTEGER duration_ms
        TEXT source "web, api, bulk, text, qr, watch, extension"
        TEXT verdict "legitimate, suspicious, phishing"
        INTEGER risk_score "0-100"
        REAL confidence
        REAL ml_prob
        REAL heuristic_score
        TEXT brand
        TEXT country_code
        INTEGER blacklisted "0 or 1"
        TEXT tags "JSON list"
        TEXT notes
        TEXT data "full ScanResult JSON"
        TEXT ip "v2"
        TEXT asn "v2"
        TEXT registrar "v2"
        INTEGER trust_score "v2"
        TEXT tier "v2"
        TEXT threat_type "v2"
        TEXT category "v2"
        TEXT tested_depth "v2: full or lexical"
    }
    SCAN_DOM {
        INTEGER scan_id PK, FK
        BLOB html_gz "gzip, max 500 KB"
        INTEGER size
        INTEGER truncated
        TEXT source
        TEXT created_at
    }
    REPORTS {
        INTEGER id PK
        TEXT url
        TEXT domain
        TEXT label "phishing or legitimate"
        TEXT brand
        TEXT comment
        TEXT reporter
        INTEGER phishing_votes
        INTEGER legitimate_votes
        TEXT status "pending, verified, rejected"
        INTEGER scan_id FK
        TEXT created_at
    }
    VOTES {
        INTEGER id PK
        INTEGER report_id FK
        TEXT vote
        TEXT voter
        TEXT created_at
    }
    WATCHLIST {
        INTEGER id PK
        TEXT target
        TEXT label
        INTEGER interval_minutes
        INTEGER monitor_typosquats
        TEXT last_checked
        INTEGER last_risk
        TEXT last_verdict
        INTEGER prev_risk
        INTEGER last_scan_id FK
        TEXT known_typosquats "JSON list"
    }
    WATCH_CHECKS {
        INTEGER id PK
        INTEGER watch_id FK
        TEXT t
        INTEGER risk_score
        TEXT verdict
        INTEGER scan_id FK
        TEXT typosquats "JSON"
    }
    ALERTS {
        INTEGER id PK
        TEXT type
        TEXT severity
        TEXT title
        TEXT detail
        TEXT created_at
        INTEGER read
        INTEGER scan_id FK
        INTEGER watch_id FK
    }
    EVENTS {
        INTEGER id PK
        TEXT type
        TEXT message
        TEXT meta "JSON"
        TEXT created_at
        TEXT entity_type "v2"
        TEXT entity_id "v2"
        INTEGER scan_id FK "v2"
        TEXT domain "v2"
    }
    BULK_JOBS {
        INTEGER id PK
        TEXT name
        TEXT status "queued, running, completed, failed"
        INTEGER total
        INTEGER done
        TEXT created_at
        TEXT finished_at
    }
    BULK_ITEMS {
        INTEGER id PK
        INTEGER job_id FK
        TEXT url
        TEXT status "pending, done, error"
        INTEGER scan_id FK
        TEXT error
    }
    SETTINGS {
        TEXT key PK
        TEXT value "JSON-encoded"
    }

    SCANS ||--o| SCAN_DOM : "DOM snapshot"
    SCANS |o--o{ REPORTS : "scan_id"
    REPORTS ||--o{ VOTES : "report_id"
    WATCHLIST ||--o{ WATCH_CHECKS : "watch_id"
    SCANS |o--o{ WATCH_CHECKS : "scan_id"
    SCANS |o--o{ WATCHLIST : "last_scan_id"
    SCANS |o--o{ ALERTS : "scan_id"
    WATCHLIST |o--o{ ALERTS : "watch_id"
    SCANS |o--o{ EVENTS : "scan_id"
    BULK_JOBS ||--o{ BULK_ITEMS : "job_id"
    SCANS |o--o{ BULK_ITEMS : "scan_id"
```

---

## 6. Deployment: local vs Vercel

On a laptop, `./start.sh` starts two processes. The first is `uvicorn` on port 8000, which runs the API, the 60 s
watchlist scheduler and the startup demo seed. The second is the Vite dev server on port 5173, which proxies the API
paths to port 8000. The Chrome extension talks to port 8000 directly. The hosted demo (Vercel project
`phishguard-mini-project`, region `bom1`) serves the built SPA from the CDN and runs the *unchanged* FastAPI app
inside one Python function through `deploy/cloud_app.py`. On a cold start, that wrapper copies the bundled
`deploy/seed.db` to `/tmp`, so demo data resets on every cold start. The scheduler is off in the cloud, and a daily
Vercel Cron call to `/api/_cron` does the watchlist re-checks and data retention instead.

<!-- diagram: deployment -->
```mermaid
flowchart TB
    subgraph local["Local development: ./start.sh"]
        startSh["start.sh: creates backend/.venv (uv or venv),<br/>npm install, trains the model if metrics.json is missing"]
        viteDev["Vite dev server on :5173<br/>React SPA with hot reload"]
        uvicornApi["uvicorn app.main:app on :8000<br/>FastAPI + 60 s scheduler + demo seed"]
        localDb[("backend/data/phishguard.db<br/>SQLite, WAL mode")]
        localFeeds["backend/data/feeds/<br/>downloaded on startup if empty"]
        chromeExt["Chrome extension<br/>calls localhost:8000"]
        devBrowser["Browser on localhost:5173"]
        startSh --> viteDev
        startSh --> uvicornApi
        devBrowser --> viteDev
        viteDev -->|"proxy /api/, /docs, /redoc, /openapi.json,<br/>/static, /screenshots"| uvicornApi
        chromeExt --> uvicornApi
        uvicornApi --> localDb
        uvicornApi --> localFeeds
    end

    release["Release steps<br/>deploy/build_cloud_seed.py (seed.db + feeds/*.gz),<br/>deploy/preflight.py, vercel deploy --prod"]

    subgraph vercel["Vercel: project phishguard-mini-project, region bom1"]
        vBuild["Build: npm ci --prefix frontend,<br/>cd frontend && npm run build"]
        vCdn["Static frontend/dist on the CDN<br/>/assets/* cached for 1 year"]
        vRewrites{"vercel.json rewrites"}
        vFunction["Python function api/index.py<br/>deploy/cloud_app.py wraps the unchanged app.main<br/>root requirements.txt, maxDuration 300 s"]
        vCold["Cold start: seed.db copied to /tmp/phishguard.db,<br/>feeds/*.gz unpacked, feeds_index.pkl.gz injected,<br/>Tranco .npz preloaded, models warmed up"]
        vTmpDb[("/tmp/phishguard.db<br/>per instance, reset on cold start")]
        vCron["Vercel Cron 30 2 * * * (02:30 UTC)<br/>/api/_cron: up to 5 watchlist checks + retention"]
        visitor["Visitor's browser"]
        vBuild --> vCdn
        visitor --> vRewrites
        vRewrites -->|"/api/*, /docs, /redoc, /openapi.json"| vFunction
        vRewrites -->|"other paths: SPA fallback to index.html"| vCdn
        vFunction --> vCold --> vTmpDb
        vCron --> vFunction
    end

    localDb -.->|"snapshot"| release
    release -.->|"upload"| vBuild
```

---

## 7. Frontend route map

`App.tsx` lazy-loads one chunk per page inside a shared `Layout`, which has the sidebar and the header. The sidebar
lists 14 pages, plus the API Guide link at the bottom. Three detail routes are opened from tables and links. The
labels show the backend endpoints each page calls (all under `/api`), taken from the `api` / `apiV2` calls in
`frontend/src/pages`. Data fetching uses TanStack Query. Live views poll: Overview live stats every 5 s, a running
bulk job every 2 s, the header alert bell every 20 s and health every 30 s.

<!-- diagram: frontend-routes -->
```mermaid
flowchart LR
    appRouter["App.tsx router<br/>Layout: sidebar + header"]
    header["Header on every page<br/>GET health (demo banner)<br/>GET alerts (bell icon)<br/>POST alerts/read-all<br/>POST scan (quick scan box)"]
    pgNotFound["NotFound  *"]

    subgraph sidebar["Sidebar pages, in menu order"]
        pgOverview["Overview  /<br/>analytics/overview,<br/>timeseries, distribution,<br/>analytics/model, stats/live,<br/>alerts, health"]
        pgScan["Scan  /scan<br/>POST scan, POST extract<br/>QR decoded in browser"]
        pgHistory["History  /history<br/>GET scans, scans/export<br/>DELETE scans/{id}"]
        pgBulk["Bulk Scan  /bulk<br/>POST bulk, bulk/upload<br/>GET bulk"]
        pgAnalytics["Analytics  /analytics<br/>timeseries, distribution,<br/>performance, funnel"]
        pgGraph["Graph  /graph<br/>GET graph"]
        pgModel["Model Lab  /model<br/>GET analytics/model"]
        pgWatch["Watchlist  /watchlist<br/>list, add, delete,<br/>run, history"]
        pgTypo["Typosquat  /typosquat<br/>GET typosquat<br/>POST scan"]
        pgCommunity["Community  /community<br/>reports list + create<br/>reports/{id}/vote"]
        pgFeeds["Threat Feeds  /feeds<br/>feeds, feeds/refresh,<br/>feeds/search"]
        pgAlerts["Alerts  /alerts<br/>alerts, alerts/{id}/read,<br/>alerts/read-all"]
        pgActivity["Activity Log  /activity<br/>GET events"]
        pgSettings["Settings  /settings<br/>GET + PUT settings"]
        pgApiGuide["API Guide  /api-guide<br/>static examples,<br/>link to /docs"]
        pgOverview ~~~ pgScan ~~~ pgHistory
        pgBulk ~~~ pgAnalytics ~~~ pgGraph
        pgModel ~~~ pgWatch ~~~ pgTypo
        pgCommunity ~~~ pgFeeds ~~~ pgAlerts
        pgActivity ~~~ pgSettings ~~~ pgApiGuide
    end

    pgBulkJob["Bulk job  /bulk/:id<br/>GET bulk/{id}<br/>polled every 2 s while running"]
    pgReport["Report  /scans/:id<br/>scans/{id}, rescan, PATCH,<br/>DELETE, compare, dom,<br/>similar, timeline, graph,<br/>domains, reports, settings"]
    pgDomain["Domain  /domains/:domain<br/>domains/{domain}<br/>POST scan, POST watchlist"]

    appRouter --> header
    appRouter --> pgNotFound
    appRouter --> sidebar
    pgGraph ~~~ pgBulkJob
    pgBulk -->|"open job"| pgBulkJob
    pgScan -->|"after scan"| pgReport
    pgHistory -->|"row click"| pgReport
    pgBulkJob -->|"row click"| pgReport
    pgReport -->|"domain link"| pgDomain
```
