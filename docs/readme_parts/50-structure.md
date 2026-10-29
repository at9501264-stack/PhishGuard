## 🗂️ Project structure

The repository has three runnable parts: the **FastAPI backend** (detection engine, ML models, REST API), the **React dashboard** and the **Chrome extension**. A small `deploy/` layer runs the same backend on Vercel.

```text
mini-project/
├── api/
│   └── index.py                  # Vercel Python function entry point, imports deploy/cloud_app.py
├── backend/                      # FastAPI service (Python 3.12)
│   ├── app/
│   │   ├── main.py               # FastAPI app, startup tasks (feeds, demo seed, scheduler), router registration
│   │   ├── db.py                 # SQLite schema, idempotent migrations, PHISHGUARD_DB_PATH
│   │   ├── scoring.py            # risk score, verdict, trust score, tier, threat type, factors, summary
│   │   ├── routers/
│   │   │   ├── scans.py          # POST /api/scan, history, rescan, tags, compare, export, DOM, timeline
│   │   │   ├── bulk.py           # bulk jobs (JSON list or CSV/TXT upload, up to 500 URLs)
│   │   │   ├── tools.py          # URL extraction from email/SMS text, typosquat finder
│   │   │   ├── community.py      # community reports and votes
│   │   │   ├── watchlist.py      # monitored URLs/domains, manual checks, check history
│   │   │   ├── insights.py       # relationship graph, similar scans, detection funnel
│   │   │   └── misc.py           # alerts, threat feeds, analytics, activity log, settings, health, admin
│   │   ├── services/             # scanner pipeline, bulk workers, watcher, analytics, graph, similar,
│   │   │                         # community, events (activity log + alerts), feeds, settings, demo seed
│   │   └── analysis/
│   │       ├── engine.py         # the 50+ live checks: DNS, WHOIS/RDAP, SSL, HTTP, content, geo, screenshot URL
│   │       ├── brands.py         # brand impersonation (typosquat, homoglyph, combosquat)
│   │       ├── typosquat.py      # dnstwist-style permutation generator
│   │       ├── feeds.py          # OpenPhish, PhishTank, URLhaus, Phishing.Database, Phishing Army
│   │       ├── dnsbl.py          # DNS blocklists (Spamhaus, SURBL, URIBL, SpamCop)
│   │       ├── popularity.py     # Tranco top-1M rank lookup
│   │       ├── content.py        # page category, language, parked pages, resources and trackers
│   │       ├── rdap.py           # RDAP fallback for WHOIS
│   │       ├── net_safety.py     # SSRF guard: blocks private/loopback targets before any fetch
│   │       └── text_extract.py   # URL extraction (incl. defanged hxxp / [.] links)
│   ├── ml/
│   │   ├── features.py           # lexical URL feature extractor (shared by training and prediction)
│   │   ├── train.py              # dataset build, bias handling, training + evaluation of the 4 models
│   │   ├── predictor.py          # loads the models, predicts, explains each prediction
│   │   ├── collect_legit.py      # optional: collects legitimate deep links from public sitemaps
│   │   ├── data/                 # built datasets (dataset.csv, modern_eval.csv); raw/ is git-ignored
│   │   └── artifacts/            # trained models (*.joblib) + metrics.json (read by the Model Lab)
│   ├── data/                     # runtime data: SQLite DB (git-ignored), threat feeds, Tranco index
│   ├── requirements.txt          # backend dependencies for local development
│   └── README.md
├── frontend/                     # React 19 + TypeScript + Vite dashboard
│   ├── src/
│   │   ├── App.tsx               # client routes (19 routes, 17 pages)
│   │   ├── layout/Layout.tsx     # sidebar, header quick scan, alerts bell, theme toggle, demo banner
│   │   ├── pages/                # Overview, Scan, Report, History, Bulk, Analytics, Graph, Model Lab, ...
│   │   │   └── report/           # report tab components (sections, source, graph, timeline, related scans)
│   │   ├── components/           # cards, charts, data table, force graph, risk gauge, verdict badge, tabs, ...
│   │   ├── api/                  # typed API clients (client.ts, client_v2.ts)
│   │   └── lib/                  # formatting, hooks, theme, v2 helpers
│   ├── vite.config.ts            # dev server on :5173, proxies /api, /docs, /redoc to the backend
│   └── package.json
├── extension/                    # Chrome extension (Manifest V3, plain JS, no build step)
│   ├── manifest.json
│   ├── background.js             # auto-scan, badge, notifications, context menu
│   ├── popup/  options/          # popup UI and settings page
│   ├── content/banner.js         # optional in-page warning banner
│   └── icons/
├── deploy/                       # Vercel demo mode
│   ├── cloud_app.py              # cloud wrapper: env defaults, /tmp DB, feed unpacking, warm-up, /api/_cron
│   ├── build_cloud_seed.py       # builds seed.db + packed feeds from local data
│   ├── preflight.py              # size, dependency and snapshot checks before a deploy
│   ├── feedindex.py              # prebuilt threat-feed index loader
│   ├── seed.db                   # demo database snapshot (70 scans)
│   └── feeds/                    # threat feeds packed as .gz
├── docs/
│   ├── architecture/             # diagrams.md (7 Mermaid diagrams), tech-stack.md, api-endpoints.md, img/*.png
│   ├── media/                    # 49 screenshots + screenshots.json, demo video (demo.mp4, demo-preview.gif,
│   │                             # demo-poster.png, demo.srt)
│   ├── readme_parts/             # the sections this README is assembled from
│   ├── ARCHITECTURE.md           # architecture overview, links to docs/architecture/
│   ├── DEMO_GUIDE.md             # 5-minute viva demo script
│   ├── DEPLOY_NOTES.md           # Vercel deployment notes and troubleshooting
│   ├── FEATURES.md               # research on 12 URL-safety tools
│   ├── SPEC.md, SPEC_V2.md       # build specifications (SPEC_V2 opens with the mini-project scope)
│   └── FE_V2_CONTRACT.md         # frontend data contract
├── scripts/
│   ├── capture_media.py          # screenshot + UI smoke-test generator (Playwright)
│   ├── video/                    # demo video: scenes.json, narration.md, record_demo.py (Playwright + FFmpeg)
│   └── build_readme.py           # joins docs/readme_parts/*.md into README.md with a table of contents
├── requirements.txt              # pinned runtime packages of the Vercel function
├── start.sh                      # one-command local start (API :8000 + dashboard :5173)
├── vercel.json                   # build, rewrites, function settings, daily cron
└── .vercelignore                 # keeps the Vercel upload under 100 MB
```
