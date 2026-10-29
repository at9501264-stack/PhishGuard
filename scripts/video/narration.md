# PhishGuard demo video: narration script

Machine-readable source: [`scenes.json`](scenes.json) (same scenes, plus the Playwright actions).
Project: *AI-Based Phishing Website Detection and Risk Analysis System Using Machine Learning*.
B.Tech mini project by Ayushi Tiwari, guide Mr. Vishal Gupta, Lloyd Institute of Engineering & Technology (AKTU).

## Totals

| | |
|---|---|
| Scenes | 20 |
| Narration words | 421 (whitespace-separated; spelled letters such as "A U C" count as separate words) |
| Sum of `min_seconds` | 157 s |
| Recorded with | `scripts/video/record_demo.py`: macOS `say -v Rishi -r 220` (en_IN, about 170 wpm), Playwright Chromium 1440x900 |
| Speech (measured) | 148 s |
| **Final video** | **164.4 s (2 min 44 s)**, `docs/media/demo.mp4` (H.264 + AAC, 9.5 MB), captions in `docs/media/demo.srt` |

Each scene is held for max(narration + 0.5 s, `min_seconds`). Real start times of every scene in the final video
are in [`timeline.json`](timeline.json).

## Script

Duration = estimated scene length in seconds (real lengths: see `timeline.json`). Routes `:latest`, `:phishing` and `:legit` are resolved by the recorder (see notes below).

| # | Scene | Route | Duration (s) | Words | Narration (spoken) | Caption (on screen) |
|---|---|---|---|---|---|---|
| 1 | `intro`<br>PhishGuard | `/` | 8.0 | 20 | This is PhishGuard, an AI-based phishing website detection and risk analysis system by Ayushi Tiwari, guided by Mister Vishal Gupta. | Ayushi Tiwari · Guide: Mr. Vishal Gupta · Lloyd Institute of Engineering & Technology |
| 2 | `problem`<br>The problem | `/` | 8.2 | 22 | Phishing sites copy trusted brands to steal passwords, and many vanish before blocklists catch them. PhishGuard explains the risk of any link. | Phishing pages copy trusted brands and vanish fast; blocklists alone react too late |
| 3 | `how-it-works`<br>How it works | `/` | 8.2 | 22 | Each URL becomes forty-four features for a Random Forest model, while live checks inspect DNS, who-is, SSL, content, brands and threat feeds. | URL → 44 features → Random Forest + live checks → 60% ML + 40% heuristics → risk 0–100 |
| 4 | `overview`<br>Overview dashboard | `/` | 7.1 | 19 | The Overview dashboard shows total scans, detection rate and average trust score, with trends and a live scan feed. | KPIs, scan trends, verdict split and a live feed that refreshes every 5 seconds |
| 5 | `scan`<br>Deep scan a suspicious URL | `/scan` | 10.0 | 21 | Let's deep scan a fake PayPal login link. Eight stages run, from the ML prediction to DNS, who-is, SSL and reputation. | Scanning http://paypal-login-verify.secure-account.xyz/update with an 8-stage deep scan |
| 6 | `verdict`<br>Verdict: phishing | `/scans/:latest` | 7.1 | 19 | The verdict is phishing: risk ninety-two out of a hundred, trust score eight, tier Untrusted, threat type social engineering. | Risk 92/100 · Trust score 8/100 · Tier: Untrusted · Social engineering · ML 98.5% |
| 7 | `explain`<br>Explainable result | `/scans/:latest` | 7.1 | 19 | Every verdict is explained: an AI summary, the factors behind it, and a sixty-forty split between model and checks. | AI summary, negative and positive factors, and the 60% ML + 40% heuristics score breakdown |
| 8 | `ml-brand`<br>ML Explanation & Brand | `/scans/:latest` | 8.0 | 21 | ML Explanation shows the features behind the prediction, like the long hostname, and all four models agree. Brand confirms PayPal impersonation. | Feature contributions, all 4 models agree (95–100%), PayPal impersonated via subdomain |
| 9 | `live-checks`<br>Live checks on a real phishing kit | `/scans/:phishing` | 8.0 | 21 | Next, a live phishing kit on vercel dot app: who-is and DNS records, a mismatched SSL certificate, and its redirect chain. | Live kit on vercel.app: WHOIS & DNS, SSL hostname mismatch, redirect chain & headers |
| 10 | `reputation-content`<br>Reputation & content | `/scans/:phishing` | 7.5 | 20 | Reputation shows three of eleven engines flagging it, including OpenPhish and Phishing Army. Content classifies it as a login page. | 3 of 11 engines flag it (OpenPhish, Phishing Army, PhishGuard ML) · category: login |
| 11 | `resources-source-graph`<br>Resources, source & graph | `/scans/:phishing` | 8.0 | 21 | Resources lists contacted domains, Source keeps the HTML, which hides code sending stolen data to Telegram, and Graph maps the infrastructure. | Contacted domains, stored HTML (Telegram exfiltration code) and the infrastructure graph |
| 12 | `legit`<br>A legitimate site: github.com | `/scans/:legit` | 7.1 | 19 | For contrast, github dot com is legitimate: risk three, trust score ninety-seven, tier Trusted, and no engine flags it. | github.com: legitimate · risk 3/100 · trust score 97/100 · Tier: Trusted · 0/11 engines |
| 13 | `history-bulk`<br>History & bulk scanning | `/history?tier=Untrusted` | 8.0 | 21 | History keeps every scan with export and one-click pivots, like all Untrusted sites. Bulk Scan checks up to five hundred URLs. | Pivot by tier, threat type, IP, ASN or registrar · CSV/JSON export · bulk jobs of 500 URLs |
| 14 | `analytics`<br>Analytics | `/analytics` | 7.1 | 19 | Analytics shows scan trends, an activity heatmap, threat types, trust tiers and a detection funnel from scanned to phishing. | Scan trends, weekday × hour heatmap, threat types, trust tiers and the detection funnel |
| 15 | `model-lab`<br>Model Lab: why Random Forest | `/model` | 13.1 | 35 | The Model Lab compares four classifiers on one hundred forty-six thousand URLs. Random Forest wins on F1, with eighty-six percent accuracy even on unseen domains, and an A U C of zero point nine four. | 146,364 URLs · 4 models · Random Forest: accuracy 86.4%, F1 0.856, ROC-AUC 0.945 |
| 16 | `graph-watchlist-typosquat`<br>Graph, Watchlist & Typosquat | `/graph` | 9.0 | 21 | The Relationship graph links domains by shared IP addresses and registrars. Watchlist re-checks sites automatically, and Typosquat finds live PayPal look-alikes. | Infrastructure graph, scheduled re-checks with alerts, and live look-alikes of paypal.com |
| 17 | `community-feeds`<br>Community & threat feeds | `/community` | 7.0 | 18 | Community reports work like PhishTank, with crowd voting, and Threat Feeds holds six hundred fifty-seven thousand blocklist entries. | PhishTank-style voting (verified at +3 net votes) · 657,124 entries from 5 blocklists |
| 18 | `alerts-activity-settings`<br>Alerts, activity log & settings | `/alerts` | 8.0 | 20 | Alerts flag high-risk detections, the Activity log records every action, Settings tunes the thresholds, and a REST API exposes everything. | Alerts, a full audit trail, adjustable verdict thresholds and a documented REST API |
| 19 | `architecture`<br>Architecture | `/` | 8.6 | 23 | Under the hood: a React dashboard, a Fast API backend with the model and analysis engine, and S Q Lite storage, on Vercel. | React dashboard → FastAPI → ML model + analysis engine → SQLite · deployed on Vercel |
| 20 | `closing`<br>Thank you | `/` | 8.0 | 20 | PhishGuard turns any link into an explainable risk score. The live demo and code links are on screen. Thank you. | Live: phishguard-mini-project.vercel.app · Code: github.com/at9501264-stack/mini-project |

## Notes for the recorder

- **`:latest`**: the scan created in scene `scan`. The Scan page auto-navigates to `/scans/<id>` about 450 ms after the
  scan finishes; take the id from that URL (fallback: newest scan of `http://paypal-login-verify.secure-account.xyz/update`).
  Do not use "newest scan id": the watchlist scheduler creates scans in the background. Scenes `verdict`, `explain` and
  `ml-brand` should not reload when the path already matches.
- **`:phishing`**: newest scan of `http://www.indesx-mauve.vercel.app/`, which is also the first item of
  `GET /api/scans?verdict=phishing&sort=risk_score&order=desc`. The watchlist re-checks it, so the id moves (#70, then #71);
  every scan of it shows risk 97, 3/11 engines, SSL hostname mismatch, a login page and Telegram code in the HTML.
  Scenes `live-checks`, `reputation-content` and `resources-source-graph` describe that scan specifically.
- **`:legit`**: newest scan of `https://github.com` (today #69: risk 3, trust 97, Trusted, 0/11 engines).
- **Report tabs**: buttons inside `[data-report-tabs]`. Each label is a bare text node followed by an optional count badge
  (for example "Reputation2"), so tab clicks use `"scope": "[data-report-tabs]", "match": "prefix"`. Scoping matters:
  "Graph" is also a sidebar link and "Source" is a substring of "Resources".
- **Expected numbers** for the fresh PayPal scan come from a dry run of the real `perform_scan` pipeline on a scratch copy
  of the database: phishing, risk 92, trust 8, tier Untrusted, social engineering, ML 98.5% (Random Forest), PayPal via subdomain.
  Scenes carry an `expect` object; if the live scan differs, update the two spoken numbers in `verdict`.
- Pronunciation: narration spells out tricky terms for TTS ("who-is" for WHOIS, "Fast API", "S Q Lite", "A U C",
  "vercel dot app", "github dot com", "Mister").
- Every number comes from `backend/ml/artifacts/metrics.json`, the running API (`/api/health` feeds_entries = 657,124),
  or the stored scans.
