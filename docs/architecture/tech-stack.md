# Tech stack

PhishGuard has three tiers. The clients are a React single-page dashboard and a Chrome extension. In the middle is
a FastAPI REST API that runs a machine-learning URL classifier next to a network analysis engine. All data is kept in
one SQLite database. This page lists every library and external service the project uses, the version that is
actually installed, and why it is there.

**Where the versions come from (checked 2026-10-25).**
Frontend: `frontend/node_modules/<package>/package.json`, which matches `frontend/package-lock.json` (Vercel runs
`npm ci` on that lockfile).
Backend: the packages installed in `backend/.venv` (Python 3.12.13).
The root [`requirements.txt`](../../requirements.txt) pins the same Python versions for the Vercel function, because
the scikit-learn models have to be loaded by the version that trained them.
[`backend/requirements.txt`](../../backend/requirements.txt) only sets minimum versions (`>=`) for a fresh local
install.

Related pages: [diagrams.md](diagrams.md) (7 architecture diagrams) and [api-endpoints.md](api-endpoints.md) (all
48 REST endpoints).

**Layers:** [Frontend](#frontend) · [Backend](#backend) · [Machine learning](#machine-learning) ·
[Analysis / network](#analysis--network) · [Data sources](#data-sources) · [Deployment](#deployment) ·
[Tooling](#tooling)

---

## Frontend

`frontend/` is a Vite + React + TypeScript single-page app. It has 19 routes and lazy-loads one chunk per page.

| Library | Version | Why it is used |
|---|---|---|
| [React](https://react.dev) | 19.3.1 | UI library for the dashboard: pages, the scan report and its tabs, tables and forms. |
| React DOM (`react-dom`) | 19.3.1 | Renders the React component tree in the browser. |
| [React Router](https://reactrouter.com) (`react-router-dom`) | 7.18.4 | Client-side routing inside one shared layout (sidebar + header): `/scan`, `/history`, `/scans/:id`, `/domains/:domain`, `/bulk/:id` and the other pages. |
| [TanStack Query](https://tanstack.com/query) (`@tanstack/react-query`) | 5.104.5 | Fetches and caches API data and refetches it when needed. It also handles polling: live stats every 5 s, a running bulk job every 2 s, the alert bell every 20 s and health every 30 s. |
| [Recharts](https://recharts.org) | 3.10.1 | Area, bar, line and pie charts on Overview, Analytics, Model Lab, Domain, Bulk, Watchlist, Typosquat, Threat Feeds and in the scan report. |
| [d3-force](https://d3js.org/d3-force) | 3.0.0 | Force-directed layout for the relationship graph (domain, URL, IP, ASN, name-server, registrar, brand and country nodes). It is drawn by `components/ForceGraph.tsx` on the Graph page and the report's Graph tab. |
| `@types/d3-force` | 3.0.10 | TypeScript types for d3-force. |
| [lucide-react](https://lucide.dev) | 1.61.0 | SVG icons for the sidebar, buttons, check results and report tabs. |
| [jsQR](https://github.com/cozmo/jsQR) | 1.4.0 | Reads a QR code from an image the user picks on the Scan page, so the URL inside it can be scanned. Decoding happens in the browser and only the decoded URL is sent to the API. |
| [Tailwind CSS](https://tailwindcss.com) | 4.3.3 | Utility-first styling for the light and dark themes and the responsive layout that also works on phones. |
| `@tailwindcss/vite` | 4.3.3 | Runs Tailwind 4 as a Vite plugin, so no PostCSS or `tailwind.config.js` is needed. |
| [Vite](https://vite.dev) | 8.3.5 | Dev server on port 5173 with hot reload, which proxies `/api/`, `/docs`, `/redoc` and `/openapi.json` to the backend. Also the production bundler (`npm run build` builds into `frontend/dist`). |
| Inter and JetBrains Mono ([Google Fonts](https://fonts.google.com)) | n/a | Inter is the UI typeface. JetBrains Mono is the monospace typeface for URLs, JSON and code samples. |
| Chrome extension, Manifest V3 (`extension/`) | 1.0.0 | The second client. It has a "Scan this page" popup, a quick auto-scan with the risk score on the badge, desktop notifications, an optional warning banner and a "Scan link with PhishGuard" context-menu entry. It is plain JavaScript on the `chrome.*` APIs, with no build step. |

## Backend

`backend/app/` contains the API, the services (scanner, bulk jobs, watcher, community, analytics) and the database
layer.

| Library | Version | Why it is used |
|---|---|---|
| [Python](https://www.python.org) | 3.12.13 (local), 3.12.14 (Vercel) | Language of the API, the analysis engine and the ML code. |
| [FastAPI](https://fastapi.tiangolo.com) | 0.162.0 | The REST API: 48 endpoints in 14 routers, request validation, dependency injection for the shared history filters, and an auto-generated OpenAPI schema with Swagger UI (`/docs`) and ReDoc (`/redoc`). |
| [Starlette](https://www.starlette.io) | 1.10.0 | The ASGI toolkit under FastAPI. It provides routing, the CORS middleware and the lifespan hook that starts the background tasks. |
| [Pydantic](https://docs.pydantic.dev) | 2.14.1 | Request models (`ScanRequest`, `BulkRequest`, `ReportRequest`, `WatchRequest`, `SettingsBody` and others) and the HTTP 422 validation errors. |
| [Uvicorn](https://www.uvicorn.org) (`uvicorn[standard]`) | 0.54.0 | Local ASGI server on port 8000 (`uvicorn app.main:app`). The standard extras add uvloop 0.23.0 (event loop), httptools 0.9.0 (HTTP parser) and watchfiles 1.3.0 (`--reload`). It is not used on Vercel, which brings its own server. |
| python-multipart | 0.0.32 | Parses the multipart CSV/TXT file upload of `POST /api/bulk/upload`. |
| SQLite (standard-library `sqlite3`) | 3.53.1 | The only database: 11 tables in `backend/data/phishguard.db`, WAL mode, one connection per thread, plain SQL with no ORM. |
| asyncio (standard library) | Python 3.12 | Runs the ML model, the analysis engine and the threat-feed lookup at the same time (`asyncio.gather`, `asyncio.to_thread`). It also runs the background work: bulk jobs (5 URLs at a time), the 60-second watchlist scheduler and feed refreshes. |

## Machine learning

`backend/ml/` holds training (`python -m ml.train`) and inference (`ml/predictor.py`). On the test set of 29,272
URLs, the Random Forest scores F1 0.8561 and ROC-AUC 0.9449. All numbers are in
[`backend/ml/artifacts/metrics.json`](../../backend/ml/artifacts/metrics.json).

| Library | Version | Why it is used |
|---|---|---|
| [scikit-learn](https://scikit-learn.org) | 1.9.1 | The four classifiers: Logistic Regression (with `StandardScaler`), Decision Tree (depth 20), Random Forest (150 trees, the model that decides) and an SVM (Nystroem RBF features + `LinearSVC`, wrapped in `CalibratedClassifierCV` to get probabilities). It also provides the `StratifiedGroupKFold` split by campaign, 5-fold cross-validation and every metric (accuracy, precision, recall, F1, ROC-AUC, ROC and PR curves, confusion matrix). |
| [NumPy](https://numpy.org) | 2.5.4 | Feature vectors, the perturbation-based explanations (each feature is reset to the legitimate median and the change in probability is measured) and the compact Tranco index (`tranco_index.npz`). |
| [pandas](https://pandas.pydata.org) | 3.1.0 | Loads, cleans and joins the training CSVs (PhiUSIIL, PhishTank, Tranco, sitemap links). The predictor passes a DataFrame to models that were fitted on DataFrames. |
| [SciPy](https://scipy.org) | 1.18.1 | Numerical backend of scikit-learn. It has to be installed for the models to unpickle, so it is pinned in the root `requirements.txt`. |
| [joblib](https://joblib.readthedocs.io) | 1.6.0 | Saves and loads the four trained models (`backend/ml/artifacts/*.joblib`, next to `metrics.json`). |
| [tldextract](https://github.com/john-kurkowski/tldextract) | 5.4.0 | Splits a host into sub-domain, domain and public suffix using the Public Suffix List. It is used for the URL features, for the campaign key that keeps each campaign entirely in train or entirely in test, and for the registered domain throughout the engine. |

## Analysis / network

`backend/app/analysis/` is the engine behind the roughly 60 checks of a deep scan. Live requests to the scanned site
go through the SSRF guard in `net_safety.py` first.

| Library | Version | Why it is used |
|---|---|---|
| [httpx](https://www.python-httpx.org) | 0.28.1 | Async HTTP client. It fetches the scanned page (re-checking every redirect hop) and calls RDAP, geo-IP, Safe Browsing and VirusTotal. It also downloads the threat feeds and the Tranco list. |
| httpcore | 1.0.9 | The transport layer under httpx. `net_safety.py` plugs in a guarded network backend that connects only to the public IP that was already checked, so a DNS-rebinding trick cannot redirect the request to an internal address. |
| [dnspython](https://www.dnspython.org) | 2.9.0 | DNS records (A, AAAA, MX, NS, TXT), DNSBL queries, and checking which typosquat permutations resolve (`dns.asyncresolver`). |
| [python-whois](https://github.com/richardpenman/whois) | 0.9.6 | WHOIS lookups for domain age, registrar and expiry date. RDAP is the fallback. |
| [Beautiful Soup 4](https://www.crummy.com/software/BeautifulSoup/) (`beautifulsoup4`) | 4.15.0 | Parses the fetched HTML with `html.parser`. Inputs for the checks: forms, password fields, form actions that post to another site, links, hidden iframes, external scripts and the page title. It also feeds the content analysis (category, parked page, trackers, third-party resources). |
| [langdetect](https://github.com/Mimino666/langdetect) | 1.0.9 | Detects the page language. It is seeded, so the result is the same on every run. |
| [mmh3](https://github.com/hajimes/mmh3) | 5.3.1 | 64-bit MurmurHash3 of each of the 1,000,000 Tranco domains. The hashes and ranks are stored as a NumPy index of about 12 MB for fast popularity lookups. |
| `ssl`, `socket`, `ipaddress` (standard library) | Python 3.12 | TLS handshake on port 443 and the certificate checks (HTTPS available, valid, not self-signed, certificate age, expiry). Private, loopback and reserved address detection for the SSRF guard. |
| Project code (no library) | n/a | `typosquat.py` (dnstwist-style look-alike permutations), `text_extract.py` (URLs found in email or SMS text, including defanged `hxxp://` and `example[.]com`), `brands.py` (brand keywords and official domains), `dnsbl.py` (blocklist return codes and hourly test-point checks) and `app/scoring.py` (risk score, tier, threat type). |

## Data sources

The training code reads only frozen snapshots under `backend/ml/data/raw/` and never the live feeds. At scan time
the threat feeds are local files in `backend/data/feeds/`. They are downloaded on first start (when the folder is
empty) and again on `POST /api/feeds/refresh`. The live demo uses a snapshot of them.

| Data source | Version / snapshot | Why it is used |
|---|---|---|
| [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (UCI #967) | CSV release of 2024-03-04 | **Training only:** 45,000 phishing URLs and 40,753 augmented legitimate homepages. |
| [Tranco](https://tranco-list.eu) top-1M list | List of 2026-10-23 | **Training:** the top-30k domains (21,825 augmented legitimate domains) and 6,448 real sub-domain hosts. Ranks 30,001 to 60,000 are kept apart for the held-out "modern" legitimate set. **Scan time:** popularity rank (`popular_site` check) and the popular-domain cap. |
| Public sitemaps of Tranco sites | Collected by `ml/collect_legit.py` | **Training only:** 4,097 real legitimate deep links. Without them, "URL has a path" would look like a phishing signal. |
| [PhishTank](https://phishtank.org) verified-online feed | Snapshot of 2026-10-24, 57,062 entries | **Training:** 16,000 phishing URLs, plus 1,000 held out. **Scan time:** local blocklist. |
| [OpenPhish](https://openphish.com) public feed | Snapshot of 2026-10-24, 300 entries | **Training:** 241 phishing URLs. **Scan time:** local blocklist. |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) ACTIVE lists | Snapshot of 2026-10-24, 392,174 entries | **Training:** 12,000 phishing hosts, plus 1,000 held out. **Scan time:** local blocklist. |
| [URLhaus](https://urlhaus.abuse.ch) online list (abuse.ch) | Snapshot of 2026-10-24, 55,475 entries. When abuse.ch answers HTTP 410, it comes from the malware-filter mirror | **Scan time only:** malware-distribution URLs. A hit sets the threat type to `malware`. |
| [Phishing Army](https://phishing.army) blocklist | Snapshot of 2026-10-24, 154,182 domains | **Scan time only:** an additional phishing-domain blocklist. |
| DNSBL zones: Spamhaus DBL, SURBL, URIBL (domains); Spamhaus ZEN, SpamCop (IPs) | Live DNS queries, cached for 1 h | Spam and abuse reputation (on by default, Settings → `enable_dnsbl`). Every zone is tested against its official test point once an hour. If a resolver refuses the queries, the result is "not verifiable", never "clean". |
| WHOIS (port 43) and RDAP via [rdap.org](https://rdap.org) | Live | Domain age, registrar and expiry. RDAP is queried when WHOIS returns no creation date (Settings → `enable_rdap`). |
| [ip-api.com](https://ip-api.com) and [ipwho.is](https://ipwho.is) | Live, free tiers | Geo-IP of the server: country, city, ISP, AS number and a hosting flag. ipwho.is is the fallback when ip-api.com rate-limits (45 requests/min). |
| [Google Safe Browsing](https://developers.google.com/safe-browsing) v4 and [VirusTotal](https://www.virustotal.com) API v3 | Optional, needs an API key | Extra reputation engines. They run only when a key is entered in Settings, and they are off on the live demo. |
| [thum.io](https://www.thum.io) | Live image service | Powers the report's **Screenshot** tab. When Settings → `enable_screenshots` is on (it is off by default), the scan saves an `image.thum.io/get/width/1200/crop/800/noanimate/<url>` link. The browser then loads the thumbnail directly from thum.io. |

## Deployment

| Library | Version | Why it is used |
|---|---|---|
| [Vercel](https://vercel.com) | CLI 59.15.0 | Hosts the live demo at <https://phishguard-mini-project.vercel.app> (project `phishguard-mini-project`, region `bom1` in Mumbai). It is deployed from the local folder with `vercel deploy --prod`. |
| Vercel Python Function | Python 3.12.14 runtime | `api/index.py` → `deploy/cloud_app.py` → the unchanged FastAPI app, with `maxDuration` 300 s. On a cold start it copies the demo database `deploy/seed.db` to `/tmp`, unpacks the feed snapshot and warms up the models. |
| Vercel static hosting (CDN) | n/a | Serves the built SPA from `frontend/dist`. `/assets/*` is cached for one year and unknown paths fall back to `index.html`. `vercel.json` sends `/api/*`, `/docs`, `/redoc` and `/openapi.json` to the function. |
| Vercel Cron | `30 2 * * *` | Calls `/api/_cron` once a day at 02:30 UTC for up to 5 watchlist re-checks and the data-retention cleanup. This replaces the 60-second scheduler, which is off in the cloud. |
| Root [`requirements.txt`](../../requirements.txt) | Exact pins | The function's runtime dependencies, pinned to the versions in `backend/.venv` so the scikit-learn pickles load. |
| `deploy/build_cloud_seed.py` and `deploy/preflight.py` | Project scripts | Build the cloud snapshot (`seed.db`, `feeds/*.gz`, `feeds_index.pkl.gz`) and check it before a deploy: upload and bundle size (about 377 MB of the 500 MB limit), requirements against imports, and snapshot freshness. |
| [`start.sh`](../../start.sh) | Project script | Runs the project locally with one command. It creates `backend/.venv` (with uv, or `python3 -m venv`), installs the npm packages, trains the model if `metrics.json` is missing, then starts Uvicorn on port 8000 and Vite on port 5173. |
| [GitHub](https://github.com/at9501264-stack/mini-project) | n/a | Source repository. |

## Tooling

| Library | Version | Why it is used |
|---|---|---|
| [Node.js](https://nodejs.org) and npm | 24.18.0 and 11.16.0 | Install, run and build the frontend (`npm ci`, `npm run dev`, `npm run build`). |
| [TypeScript](https://www.typescriptlang.org) | 6.0.3 | Static types for all frontend code. `tsc -b` type-checks the code before every production build. |
| `@vitejs/plugin-react` | 6.1.2 | JSX transform and React Fast Refresh in Vite. |
| `@types/react`, `@types/react-dom`, `@types/node` | 19.3.0, 19.3.0, 24.19.2 | Type definitions for React and for `vite.config.ts`. |
| [oxlint](https://oxc.rs) | 1.89.0 | Fast JavaScript/TypeScript linter (`npm run lint`). |
| [uv](https://docs.astral.sh/uv/) | 0.11.28 | Creates `backend/.venv` and installs the packages quickly in `start.sh`. It is optional: without it the script uses `venv` and `pip`. |
| [Playwright](https://playwright.dev/python/) for Python + Chromium | 1.64.1, Chromium 156 | Used only for the README media. `scripts/capture_media.py` drives the dashboard in a headless browser to take the screenshots and record the demo video. The diagram PNGs in `img/` were rendered the same way. It plays no part in scanning. |
| [Pillow](https://python-pillow.org) | 13.0.0 | Crops and compresses the screenshots and diagram PNGs. It is not a runtime dependency. |
| [FFmpeg](https://ffmpeg.org) | 9.0.2 | Encodes the demo video (`demo.mp4`, H.264) and the GIF preview. |
| [Mermaid](https://mermaid.js.org) | 11.4.1 | The 7 diagrams in [diagrams.md](diagrams.md). GitHub renders them directly, and PNG copies are in [`img/`](img/). |
