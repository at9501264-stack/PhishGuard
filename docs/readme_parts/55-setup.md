## 🚀 Getting started

### Prerequisites

| Tool | Version | Notes |
|---|---|---|
| **Python** | 3.12 | with `venv` and `pip`, or [uv](https://docs.astral.sh/uv/) (used automatically by `start.sh` if installed) |
| **Node.js** | 20+ (20.19+ or 22.12+ for Vite 8) | npm comes with it |
| **git** | any recent version | to clone the repository |
| Internet access | | for the live checks (DNS, WHOIS, SSL, HTTP, geo) and threat-feed refreshes |
| `whois` CLI | optional | without it, WHOIS data comes from the RDAP fallback |

The trained models (`backend/ml/artifacts/`), the threat-feed files and the Tranco index are already in the repository, so you do **not** need to download datasets or train anything to run the app.

### Quick start

```bash
git clone https://github.com/at9501264-stack/mini-project.git
cd mini-project
./start.sh
```

Then open:

- 🖥️ **Dashboard:** <http://localhost:5173>
- 📘 **API docs (Swagger UI):** <http://localhost:8000/docs> (ReDoc at `/redoc`)

What `start.sh` does:

1. **First run only:** creates `backend/.venv` (with `uv venv --python 3.12` if uv is installed, otherwise `python3 -m venv`) and installs `backend/requirements.txt`.
2. Trains the models **only if** `backend/ml/artifacts/metrics.json` is missing. It is included in the repository, so this step is normally skipped.
3. **First run only:** runs `npm install` in `frontend/`.
4. Starts the API (`uvicorn app.main:app --port 8000`) and the dashboard (`npm run dev -- --port 5173`) together. **Ctrl+C stops both.**

> [!TIP]
> Two optional packages turn on the **Tranco popularity rank** (`mmh3`) and **page-language detection** (`langdetect`). Without them those two signals show as unavailable and everything else works. Install them once with `backend/.venv/bin/pip install mmh3 langdetect`.

> [!NOTE]
> On the **first start** the API creates `backend/data/phishguard.db` and fills it with demo data in the background (see [Demo data](#demo-data)). Give it about a minute before the charts fill up. `start.sh` needs bash, so on Windows use the manual steps below or WSL.

### Manual setup - macOS / Linux

**Terminal 1 - backend API**

```bash
cd mini-project/backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install mmh3 langdetect                    # optional: Tranco rank + page language
uvicorn app.main:app --port 8000               # http://localhost:8000/docs
```

With uv instead: `uv venv .venv --python 3.12 && uv pip install --python .venv/bin/python -r requirements.txt`.

**Terminal 2 - dashboard**

```bash
cd mini-project/frontend
npm install
npm run dev                                    # http://localhost:5173
```

The Vite dev server proxies `/api`, `/docs`, `/redoc`, `/openapi.json`, `/static` and `/screenshots` to the backend, so the dashboard and the API share one origin in the browser.

Other frontend commands:

| Command | What it does |
|---|---|
| `npm run build` | TypeScript type-check (`tsc -b`) and production build into `frontend/dist` |
| `npm run preview` | serves the production build (same proxy as `dev`) |
| `npm run lint` | lints the code with oxlint |

### Manual setup - Windows (PowerShell)

**Terminal 1 - backend API**

```powershell
git clone https://github.com/at9501264-stack/mini-project.git
cd mini-project\backend
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install mmh3 langdetect          # optional
python -m uvicorn app.main:app --port 8000
```

**Terminal 2 - dashboard**

```powershell
cd mini-project\frontend
npm install
npm run dev
```

Open <http://localhost:5173>.

> [!TIP]
> If PowerShell refuses to run `Activate.ps1` or `npm` scripts, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once. You can also skip activation and call `.venv\Scripts\python -m uvicorn app.main:app --port 8000` directly.

**Retraining is optional.** The raw training data is not in the repository (`backend/ml/data/raw/` is git-ignored). The files to download (the [PhiUSIIL dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), the [Tranco list](https://tranco-list.eu/) and a feed snapshot) and the two commands are listed in [Retraining the models](#retraining-the-models). On Windows, run `.venv\Scripts\python -m ml.train` from the `backend` folder, then restart the API so it loads the new models.

### Environment variables

All variables are optional. The defaults suit local development.

| Variable | Read by | Default | Purpose |
|---|---|---|---|
| `PHISHGUARD_DB_PATH` | backend (`app/db.py`) | `backend/data/phishguard.db` | SQLite database file, created and migrated on startup |
| `PHISHGUARD_NO_SEED` | backend (`app/main.py`) | unset | `1` = do not load demo data into an empty database |
| `PHISHGUARD_NO_SCHEDULER` | backend (`app/main.py`) | unset | `1` = do not start the 60-second watchlist / data-retention loop |
| `PHISHGUARD_CLOUD` | backend (`routers/misc.py`) | unset | `1` = hosted demo mode: `GET /api/health` returns `cloud: true` and the dashboard shows the demo banner |
| `PHISHGUARD_API` | frontend (`vite.config.ts`) | `http://localhost:8000` | backend origin that the Vite dev/preview server proxies to |
| `CRON_SECRET` | Vercel only (`deploy/cloud_app.py`) | unset | if set, `/api/_cron` requires `Authorization: Bearer <CRON_SECRET>` |

Flags accept `1`, `true`, `yes` or `on`. Example - a second backend on another port with an empty database:

```bash
cd backend
PHISHGUARD_DB_PATH=data/test.db PHISHGUARD_NO_SEED=1 .venv/bin/uvicorn app.main:app --port 8001
cd ../frontend && PHISHGUARD_API=http://localhost:8001 npx vite --port 5174
```

Everything else is configured at runtime on the **Settings** page and stored in the database: verdict thresholds (suspicious 35, phishing 65 by default), network checks on/off, page screenshots on/off (off by default; when on, the report's Screenshot tab shows a thum.io preview), the per-check timeout (8 s), data retention (365 days by default, 0 = keep forever) and the optional VirusTotal / Google Safe Browsing API keys (masked in API responses). DNS-blocklist and RDAP lookups can be switched off through `PUT /api/settings` (`enable_dnsbl`, `enable_rdap`).

### Demo data

So the dashboard is never empty, the API seeds demo data **when it starts with an empty database** (no rows in `scans`), unless `PHISHGUARD_NO_SEED=1` is set:

- About **67 scans spread over the last 30 days**, plus community reports and votes, **3 watchlist items** and alerts.
- Every demo scan goes through the normal scan pipeline, so scores, tiers and threat types are computed exactly like a live scan.
- About a dozen well-known sites (Google, GitHub, Wikipedia, ...) get full network scans. The rest are URL + ML only. **Phishing URLs are never fetched.**
- The threat feeds are downloaded in the background if the feed folder is empty. You can refresh them at any time on the **Threat Feeds** page.

Seeding and resetting are exposed under **Admin** in Swagger UI (<http://localhost:8000/docs>):

| Endpoint | Effect |
|---|---|
| `GET /api/admin/seed` | seed status (running, number of demo scans) |
| `POST /api/admin/seed` | loads demo data in the background (skipped if demo data exists, unless `force=true`; `deep=true` runs full network scans on more sites) |
| `POST /api/admin/reset` | deletes scans, reports, votes, watchlist, alerts, events and bulk jobs (**settings are kept**); `reseed=true` loads fresh demo data afterwards |

```bash
curl -X POST "http://localhost:8000/api/admin/reset?reseed=true"
```

To start completely from scratch, stop the API, delete `backend/data/phishguard.db*` and start it again.

### Chrome extension

The [`extension/`](extension/) folder is a Manifest V3 extension in plain JavaScript (no build step). It calls the same `POST /api/scan` endpoint as the dashboard.

1. Start the backend on `http://localhost:8000` (and the dashboard on `:5173` if you want the "Open full report" links to work).
2. Open `chrome://extensions` in Chrome or any Chromium browser and switch on **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder.
4. Pin **PhishGuard** from the puzzle-piece menu so the badge stays visible.

| Feature | How it works |
|---|---|
| **Popup** | "Scan this page" runs a deep scan of the current tab: risk bar, verdict colour, top 3 failed checks, impersonated brand and an "Open full report" link |
| **Auto-scan** | each page you open gets a quick (URL + ML) scan, cached for 30 minutes; the badge shows the risk score in the verdict colour (`!` = backend unreachable) |
| **Phishing alerts** | a desktop notification (click it to open the report) and, if enabled, a red warning banner inside the page |
| **Context menu** | right-click a link, then **Scan link with PhishGuard** |
| **Options** | backend URL, dashboard URL, auto-scan on/off, warning banner on/off (saved in `chrome.storage.sync`) |

By default the extension can only reach `localhost:8000` / `127.0.0.1:8000`. Turning on the in-page banner or saving another backend URL asks Chrome for that extra permission. More details are in [extension/README.md](extension/README.md).
