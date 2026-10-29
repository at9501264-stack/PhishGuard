# README media (`scripts/capture_media.py`)

Captures the README screenshots (and, separately, the demo video and GIF) in `docs/media/`, then numbers them for the
README and writes two index files:

- `docs/media/screenshots.json`: ordered list of `{file, title, section, explanation}`, one entry per screenshot, in
  README order. The README gallery is built from this file.
- `docs/media/manifest.json`: every media file with its caption, section, route, theme, viewport, size and dimensions,
  plus the entries for `demo.mp4` / `demo.gif`.

The current set has **49 screenshots** (1440x900 viewport at 2x, stored 1600 px wide, each PNG 400 KB or smaller):

| Section | Files |
|---|---|
| Dashboard | `01-overview` |
| Scanning | `02-scan-url`, `03-scan-email-sms`, `04-scan-qr`, `05-scan-progress` |
| Scan report | `06-report-summary` ... `18-report-timeline` (Summary, ML, Domain/WHOIS, Geo, SSL, HTTP, Brand, Reputation, Content, Resources, Source, Graph, Timeline), `19-report-legitimate` |
| History & bulk | `20-history-pivot-filters`, `21-bulk-scan`, `22-bulk-job-detail` |
| Analytics | `23-analytics-trends`, `24-analytics-distributions`, `25-analytics-threat-insights`, `26-analytics-funnel`, `27-analytics-performance` |
| Machine learning | `28-model-lab-comparison`, `29-model-lab-realistic-evaluation`, `30-model-lab-roc-pr`, `31-model-lab-confusion-matrices`, `32-model-lab-feature-importance` |
| Investigation | `33-domain-intelligence`, `34-graph-node-selected`, `35-typosquat-paypal` |
| Monitoring | `36-watchlist`, `37-watchlist-history`, `38-alerts` |
| Community & intel | `39-community`, `40-threat-feeds` |
| Tracking & settings | `41-activity-log`, `42-settings`, `43-api-guide`, `44-swagger-docs` |
| Responsive & themes | `45-dark-overview`, `46-dark-report`, `47-dark-analytics`, `48-mobile-overview`, `49-mobile-report` |

The order, titles, sections and explanations live in the `CURATED` table in the script. Edit them there, then run
`--curate` again: it is idempotent.

## Run it on spare ports (your own 8000 / 5173 stay untouched)

```bash
# 1. copy the database (sqlite backup API, safe while the app is running)
backend/.venv/bin/python -c "import sqlite3; s=sqlite3.connect('backend/data/phishguard.db'); d=sqlite3.connect('/tmp/pg-media.db'); s.backup(d)"

# 2. start a private copy of the app
(cd backend && PHISHGUARD_DB_PATH=/tmp/pg-media.db PHISHGUARD_NO_SEED=1 PHISHGUARD_NO_SCHEDULER=1 .venv/bin/uvicorn app.main:app --port 8096 &)
(cd frontend && PHISHGUARD_API=http://localhost:8096 npx vite --port 5296 --strictPort &)

# 3. optional data for the "History & bulk" and "Monitoring" shots: one finished bulk job and a few watchlist checks
curl -s -X POST localhost:8096/api/bulk -H 'Content-Type: application/json' \
     -d '{"name":"Inbox sweep - reported emails","urls":["https://www.google.com","http://www.indesx-mauve.vercel.app/","https://www.dropbox.com/login"]}'
curl -s -X POST localhost:8096/api/watchlist/1/run

# 4. capture everything into a scratch folder (about 3 min). --display-origin makes page text show http://localhost:5173
backend/.venv/bin/python scripts/capture_media.py --base-url http://localhost:5296 --api-url http://localhost:8096 \
    --out /tmp/pg-shots --skip-video --phishing-scan-id 70 --legit-scan-id 69 --display-origin http://localhost:5173

# 5. review the PNGs, copy the ones you want into docs/media (same file names), then number the set
backend/.venv/bin/python scripts/capture_media.py --curate --out docs/media

# 6. stop the copy
kill $(lsof -ti tcp:8096 -sTCP:LISTEN) $(lsof -ti tcp:5296 -sTCP:LISTEN)
```

Useful options:

- `--only report-phishing,analytics` re-captures only the shots whose names start with those prefixes.
- `--extras-only` captures only the interactive shots and the cropped regions (see below).
- `--curate` captures nothing. It renames the shot names in `--out` to the numbered set, deletes PNGs that are not in
  the set (never `demo.*` / `demo-*`, which the video step owns), and rewrites `screenshots.json` and `manifest.json`.
- `--readme README.md` also rebuilds the gallery between the `MEDIA-GALLERY` markers (featured grid plus a
  collapsible "all screenshots" section).

## How the shots are made

| Shot names (before `--curate`) | How |
|---|---|
| `overview`, `history`, `domain`, `settings`, `feeds`, `api-guide`, `api-docs`, `typosquat` (`?domain=paypal.com`) | full page, height capped (1800 CSS px), long pages cut at a fixed height |
| `scan`, `bulk`, `community`, `watchlist`, `alerts` | cut just below the page content, so there is no empty canvas. The bulk and community forms are filled in but not submitted |
| `report-phishing-*`, `report-legit-summary` | every tab of the phishing report (scan #70, a live phishing kit) and the Summary of a legitimate scan (github.com). Brand comes from a scan that really impersonates a brand (MetaMask) |
| `scan-text`, `scan-qr` | a sample phishing email pasted and its URLs extracted (defanged `hxxp://` / `[.]` included); a QR test image (embedded in the script) decoded in the browser |
| `scan-progress` | one real deep scan through the UI. `POST /api/scan` is held for about 4.7 s so the analysis-pipeline card is captured mid-way, then the request continues and the report opens |
| `history-pivot` | `/history?threat_type=social_engineering&tier=Untrusted`: pivot filters as removable chips |
| `graph-node` | `/graph?domain=<MetaMask phishing domain>&depth=2` with that domain selected (neighbours highlighted, side panel open) |
| `watchlist-history` | the History drawer of the "PayPal brand protection" watch (risk chart, checks, resolving typosquats) |
| `analytics-*`, `model-lab-*` | cropped to the union of named cards (`ANALYTICS_REGIONS`, `MODEL_REGIONS`) instead of scrolled viewports |
| `dark-*`, `mobile-*` | dark theme at 1440x900, and the 390x844 phone layout |

The report's **Screenshot** tab is not in the set: with screenshots enabled, the backend links an
`image.thum.io` render, and thum.io currently answers "Image not authorized. Please sign-up for a paid account".

The demo video (`demo.mp4`, `demo.gif`, `demo-*`) is produced separately (see `scripts/video/`). `--video-only` still
records the older automated walkthrough if needed. Requires Playwright with Chromium and Pillow in `backend/.venv`,
plus `ffmpeg` for the video.
