## 🎬 Demo video

A narrated walkthrough of the whole system, recorded from the running app: a live deep scan, the explained verdict, the report tabs, analytics, the Model Lab and the monitoring tools.

[![Watch the demo video](docs/media/demo-poster.png)](docs/media/demo.mp4)

<video src="https://github.com/at9501264-stack/mini-project/raw/main/docs/media/demo.mp4" controls width="100%"></video>

![Demo preview](docs/media/demo-preview.gif)

▶️ [Download / watch the full narrated demo (MP4, about 2¾ minutes)](docs/media/demo.mp4) · [subtitles](docs/media/demo.srt)

> [!TIP]
> If the embedded player does not load, click the poster image or the link above. The MP4 opens in GitHub's file viewer, and the `.srt` file has the full narration as subtitles.

**What the video walks through** (20 scenes, in order):

| # | Scene | What you see |
|---|---|---|
| 1 | **PhishGuard** | Title card: project name, student and guide |
| 2 | **The problem** | Phishing pages copy trusted brands and disappear fast, so blocklists alone react too late |
| 3 | **How it works** | URL → 44 features → Random Forest + live checks → 60% ML + 40% heuristics → risk 0-100 |
| 4 | **Overview dashboard** | KPIs, scan trends, verdict split and a live feed that refreshes every 5 seconds |
| 5 | **Deep scan a suspicious URL** | `http://paypal-login-verify.secure-account.xyz/update` goes through the 8-stage deep scan |
| 6 | **Verdict: phishing** | Risk 92/100, trust score 8/100, tier *Untrusted*, threat type *social engineering* |
| 7 | **Explainable result** | AI summary, negative and positive factors, and the 60/40 score breakdown |
| 8 | **ML Explanation & Brand** | Feature contributions, all four models agree, PayPal impersonated through a sub-domain |
| 9 | **Live checks on a real phishing kit** | A live kit on `vercel.app`: WHOIS and DNS, SSL hostname mismatch, redirect chain and headers |
| 10 | **Reputation & content** | 3 of 11 engines flag it (OpenPhish, Phishing Army, PhishGuard ML); content category *login* |
| 11 | **Resources, source & graph** | Contacted domains, stored HTML with code that sends stolen data to Telegram, infrastructure graph |
| 12 | **A legitimate site: github.com** | Legitimate, risk 3/100, trust score 97/100, tier *Trusted*, 0 of 11 engines |
| 13 | **History & bulk scanning** | One-click pivots (here: all *Untrusted* sites), CSV/JSON export, bulk jobs of up to 500 URLs |
| 14 | **Analytics** | Scan trends, weekday × hour heatmap, threat types, trust tiers and the detection funnel |
| 15 | **Model Lab: why Random Forest** | 146,364 URLs, 4 models; Random Forest wins with accuracy 86.4%, F1 0.856, ROC-AUC 0.945 |
| 16 | **Graph, Watchlist & Typosquat** | Relationship graph, scheduled re-checks with alerts, live look-alikes of `paypal.com` |
| 17 | **Community & threat feeds** | PhishTank-style voting (verified at +3 net votes) and 657,124 blocklist entries from 5 feeds |
| 18 | **Alerts, activity log & settings** | High-risk alerts, the full audit trail, adjustable verdict thresholds and the REST API |
| 19 | **Architecture** | React dashboard → FastAPI → ML model + analysis engine → SQLite, deployed on Vercel |
| 20 | **Thank you** | Links to the live demo and the source code |

The scene list, narration and on-screen captions are kept in [`scripts/video/scenes.json`](scripts/video/scenes.json) and [`scripts/video/narration.md`](scripts/video/narration.md). `scenes.json` also holds the Playwright browser actions used to record each scene, so the video can be re-recorded after the app changes.
