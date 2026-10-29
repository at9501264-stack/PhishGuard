# PhishGuard – Vercel deployment notes (demo mode)

**Production URL:** https://phishguard-mini-project.vercel.app
(public, no Vercel login needed; only the per-deployment preview URLs `…-team-pmp.vercel.app` are behind Vercel Authentication)

| | |
|---|---|
| Vercel project | `phishguard-mini-project` (linked in `.vercel/project.json`; never commit `.vercel/`) |
| Region | `bom1` (Mumbai) |
| How it is deployed | Vercel CLI from the local folder. **No Git repository is connected.** |
| Frontend | Vite + React, built by Vercel with `cd frontend && npm run build` (`tsc -b && vite build`) → `frontend/dist` |
| Backend | one Python Function `api/index.py` → `deploy/cloud_app.py` → the unchanged FastAPI app `backend/app/main.py` |
| Data | demo snapshot `deploy/seed.db` (70 demo scans) + threat-feed snapshot `deploy/feeds/*.gz` |

## How the cloud setup works

* `vercel.json` rewrites `/api/*`, `/docs`, `/redoc` and `/openapi.json` to the Python function. All other paths
  go to `index.html`, so client routes like `/analytics` work when opened directly (SPA fallback).
* `deploy/cloud_app.py` is a cloud-only wrapper. It runs only inside the Vercel function, so local runs
  (`start.sh`, `uvicorn` on port 8000, Vite on 5173) behave exactly as before. On a cold start it:
  * sets `PHISHGUARD_CLOUD=1`, `PHISHGUARD_DB_PATH=/tmp/phishguard.db`, `PHISHGUARD_NO_SEED=1` and
    `PHISHGUARD_NO_SCHEDULER=1` (defaults only, so project environment variables win). `/api/health` then returns
    `"cloud": true` and the UI shows the demo banner;
  * copies `deploy/seed.db` to `/tmp/phishguard.db` and moves the demo timestamps forward when the snapshot is older
    than 6 h, so the "last 24 h / 7 d / 30 d" charts are never empty;
  * unpacks `deploy/feeds/*.gz` into `/tmp` and loads the pre-built feed index `deploy/feeds_index.pkl.gz`
    (`deploy/feedindex.py`). This saves a cold scan the ~5–6 s of parsing 657k feed entries. The index is only used
    when `feeds.py` and the feed files match its fingerprint. Otherwise the backend parses the feeds itself;
  * warms up the threat feeds, the ML models and the Tranco index in a background thread;
  * adds two routes that are not in the OpenAPI schema: `GET /api/_diag` (runtime diagnostics such as cold-start
    timings, warm-up, `/tmp`, memory and DB) and `GET /api/_cron` (see limitations).
* The root `requirements.txt` lists the cloud runtime dependencies only. Its versions are pinned to `backend/.venv`
  because the scikit-learn pickles need the same version. Local development still uses `backend/requirements.txt`.
* `.vercelignore` keeps the upload under the Hobby limit of 100 MB of source files by leaving out
  `node_modules`, `.venv`, raw training data, the local DB, `top-1m.csv`, the raw feeds, `extension/` and `scripts/`.
  `deploy/preflight.py` measures the function bundle at about 377 MB of the 500 MB limit.

## Deploy commands

```bash
cd "/Users/lalamansingh/Desktop/Ayushi Wrok 2/phishguard"

# 1. refresh the cloud snapshot from the local demo DB + feeds (never modifies backend/data)
backend/.venv/bin/python deploy/build_cloud_seed.py      # -> deploy/seed.db, deploy/feeds/*.gz, deploy/feeds_index.pkl.gz
# 2. checks: upload size, bundle size, requirements vs imports, snapshot freshness
backend/.venv/bin/python deploy/preflight.py             # must end with "PREFLIGHT OK"
# 3. optional: the same frontend build Vercel runs
(cd frontend && npm run build)
# 4. deploy to production
vercel deploy --prod --yes
```

To test a build first, run `vercel deploy --yes`, which makes a protected preview. Open it with
`vercel curl /api/health --deployment <preview-url>`, then put it live with `vercel deploy --prod --yes`
(or `vercel promote <preview-url> --yes`).
On another machine, run `vercel login` and then `vercel link --yes --project phishguard-mini-project` first.

## Verify (no login needed)

```bash
U=https://phishguard-mini-project.vercel.app
curl -s -o /dev/null -w "%{http_code}\n" $U/            # 200 (HTML)
curl -s -o /dev/null -w "%{http_code}\n" $U/analytics   # 200 (SPA fallback)
curl -s $U/api/health                                   # "status":"ok", "cloud":true
curl -s "$U/api/scans?limit=3"                          # demo scans
curl -s $U/api/analytics/overview
curl -s $U/api/analytics/model
curl -s -H 'content-type: application/json' -d '{"url":"http://paypal-login-verify.secure-account.xyz/update","deep":true}' $U/api/scan
#   -> verdict "phishing", risk_score ~92, tier "Untrusted"
curl -s -H 'content-type: application/json' -d '{"url":"https://github.com","deep":true}' $U/api/scan
#   -> verdict "legitimate", risk_score ~3, tier "Trusted"
curl -s -o /dev/null -w "%{http_code}\n" $U/docs        # 200 (Swagger UI)
```

## Demo-mode limitations

* **Data is temporary and per instance.** SQLite lives in `/tmp` of each function instance. Every cold start (a new
  deploy, a few idle minutes, or a second instance under load) starts again from the bundled snapshot. New scans,
  votes, reports and watchlist changes are kept only until then, and two visitors can briefly see different data.
* **No background scheduler.** Watchlist re-checks and data retention run only through the daily Vercel Cron
  (`/api/_cron`, 02:30 UTC, at most 5 watchlist items per run). The Hobby plan allows one cron a day, and the results
  last only as long as that instance's `/tmp` DB. Without `CRON_SECRET` the endpoint only accepts Vercel's cron
  requests. If `CRON_SECRET` is set in the project env, Vercel sends `Authorization: Bearer $CRON_SECRET`.
* **Threat feeds are a snapshot** from the last `build_cloud_seed.py` run. They are not downloaded at cold start,
  and a manual refresh on the live site lasts only for that instance.
* **WHOIS** uses the RDAP fallback, because the Vercel runtime has no `whois` binary.
* **Optional API keys** (for example the VirusTotal key from local settings) are removed from the snapshot, so
  those optional integrations are off in the demo.
* **Cold start.** The function itself starts in about 1.2 s. Models and feeds then load in the background, so the
  first deep scan on a fresh instance can take a few seconds longer than usual. Typical deep scans take 2–4 s, and
  the function timeout is 300 s.
* This is a B.Tech mini-project demo on demo data, not a production security service.

## Troubleshooting

* `GET /api/_diag` shows cold-start timings, warm-up state (`feeds_index.status` should be `injected`), `/tmp`,
  memory and the seeded DB.
* If `backend/app` fails to import, the function answers `503` with the import error instead of crash-looping.
  `/api/_diag` still works in that case.
* If the production URL ever shows a Vercel login page, open Vercel → project `phishguard-mini-project` → Settings →
  Deployment Protection → Vercel Authentication, set it to "Standard Protection" (previews only) or "Disabled", then Save.
