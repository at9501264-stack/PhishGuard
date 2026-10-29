# PhishGuard: 5-minute viva demo guide

A script for presenting PhishGuard in a viva or project review: what to open, which URLs to scan, what to point at on each report tab, how to explain the ML metrics and the risk formula, and short answers to likely questions.

## Before the viva (5 minutes of preparation)

1. **Start the app.** Locally: `./start.sh` (macOS/Linux), or the two terminals from the README on Windows. Open <http://localhost:5173>. Alternatively use the live demo, <https://phishguard-mini-project.vercel.app> (demo mode: data resets, so do not rely on scans made earlier in the day).
2. **Check the status dot** at the bottom of the sidebar: "API online · model 2026.10.24-1812".
3. **Check that the threat feeds are loaded** on the **Threat Feeds** page (five feeds, about 657,000 entries). On a fresh local install they download in the background during the first minute.
4. **Warm up** with one quick scan, so the models and the Tranco index are already loaded when the examiner watches.
5. **Open these tabs in advance**: Overview, Scan, Model Lab, Threat Feeds.
6. **Copy one live-feed URL** (see Scan 3 below) into a notepad. Never open it in your own browser.
7. **Keep a fallback ready:** if the network or the laptop fails, play the narrated demo video ([`docs/media/demo.mp4`](media/demo.mp4)) or walk through the screenshots in the [README](../README.md#-screenshots).

## The 5-minute script

| Time | Page | What you do and say |
|---|---|---|
| 0:00-0:30 | **Overview** | "PhishGuard classifies a URL as Legitimate, Suspicious or Phishing with a 0-100 risk score. It combines a machine-learning model on the URL with live checks of the website." Point at the KPI cards, the verdict split and the live feed of recent scans. |
| 0:30-1:30 | **Scan 1: phishing-looking URL** | Deep scan of the made-up PayPal URL and a tour of the report tabs (below). |
| 1:30-2:00 | **Scan 2: legitimate URL** | A real login page that is not phishing: shows the model does not panic at the word "login". |
| 2:00-2:45 | **Scan 3: URL from a live feed** | A real, currently listed phishing URL: shows threat intelligence, the blocklist floor and the engine ratio. |
| 2:45-3:45 | **Model Lab** | The dataset, the four models, why Random Forest, the realistic evaluation and the HTTPS-bias fix. |
| 3:45-4:30 | **Report Summary tab** | The risk formula, using the score breakdown of Scan 1. |
| 4:30-5:00 | **History / Graph / Watchlist** | One sentence each, then close with the limitations and future scope. |

### Scan 1: a phishing-looking URL (made up, safe to type)

```text
http://paypal-login-verify.secure-account.xyz/update
```

On the **Scan** page, paste it, keep **Deep scan** on and click **Analyse URL**. Then point out:

- **Header**: the risk gauge, the verdict (Phishing), the trust score (100 - risk), the tier (Untrusted) and the threat type (social engineering).
- **Summary tab**: the plain-English summary, the **score breakdown** (ML part, heuristic part), the negative factors, and every check grouped into lexical, domain, network, SSL, content, brand and reputation.
- **ML Explanation tab**: all four models agree (with the current model, Random Forest gives about 98.5%). The top features are the long hostname (38 characters), the long sub-domain, the hyphens in the host and the URL length. "Each bar is the change in probability when that one feature is reset to the value of a typical legitimate URL."
- **Brand tab**: "paypal" appears outside PayPal's official domains, so it is flagged as impersonation, with the technique.
- **Domain / SSL / HTTP tabs**: a made-up domain usually does not resolve, so DNS, WHOIS, SSL and HTTP show failures or errors. "A failed lookup never crashes the scan; it is just evidence."
- **Lexical signals**: suspicious keywords (login, verify, update, secure, account), an abused TLD (`.xyz`), plain `http`.

### Scan 2: a legitimate URL

```text
https://github.com/login
```

- The ML probability is low (about 26% with the current Random Forest), even though the path says "login".
- **Domain / SSL tabs**: an old domain with a valid certificate. **Reputation tab**: not listed by any engine.
- The verdict is Legitimate. Explain the **popular-site rule**: a Tranco top-10k domain with no blocklist hit is capped at risk 30, so well-known sites are not flagged by mistake. The rule is never applied to hosting platforms such as `vercel.app` or `blogspot.com`, where anyone can publish.

### Scan 3: a URL from a live threat feed

1. Open **Threat Feeds** and copy a recent entry (OpenPhish or PhishTank). For example, the 24 Oct 2026 OpenPhish snapshot contained `https://lnstagrarn-reel-paoa2oajo.vercel.app/`, an Instagram look-alike (`rn` looks like `m`) on free hosting. Feeds change, so if it is gone, use any fresh entry.
2. Scan it on the **Scan** page. **Do not open it in the browser**: PhishGuard fetches it from the server, behind the SSRF guard.
3. Point out:
   - **Reputation tab**: the feed hit, the **detection engines** table and "N of M engines flagged". "A blocklist hit raises the risk to at least 90, whatever the other signals say."
   - **ML Explanation**: the model alone already gives close to 100% (long random sub-domain, free hosting).
   - **Brand tab**: the look-alike technique.
   - **Content / Resources / Source tabs** (if the page is still online): the page category, login forms, trackers, the contacted domains and the stored HTML.
   - **Graph / Timeline tabs**: the IP, ASN, registrar and name servers, and the events for this scan.
4. Optional: in the **Reputation** tab, click the **Phishing** vote button under "Community verdict" to show the community workflow. The vote files a community report for this URL (your label counts as its first vote). Other users vote on it on the **Community** page; at a net +3 phishing votes it is verified, and from then on the URL's risk is at least 85.

## Explaining the ML metrics (Model Lab)

- **Dataset**: 146,364 URLs, balanced (73,241 phishing, 73,123 legitimate) from PhiUSIIL (UCI), PhishTank, Phishing.Database and OpenPhish against Tranco domains, real sitemap deep links and PhiUSIIL legitimate URLs.
- **Split**: 80/20 (117,092 / 29,272), grouped by campaign or domain, so the same phishing campaign is never in both train and test.
- **Features**: 44 lexical features from the URL string only, such as lengths, counts, entropy, sub-domains, suspicious TLDs and keywords, free hosting and brand misuse.
- **Models** on the test split:

  | Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
  |---|---:|---:|---:|---:|---:|
  | Logistic Regression | 82.4% | 90.6% | 72.4% | 80.5% | 0.902 |
  | Decision Tree | 84.9% | 91.2% | 77.4% | 83.7% | 0.921 |
  | **Random Forest** | **86.4%** | 90.8% | **81.0%** | **85.6%** | **0.945** |
  | SVM | 84.6% | 91.0% | 76.8% | 83.3% | 0.933 |

- **Why Random Forest**: the best F1 and ROC-AUC on the test split, a stable 5-fold CV F1 (85.5% ± 0.2), and on the realistic set the highest recall (84.7%), the highest recall on HTTPS phishing (84.8%) and 93.3% of unseen PhishTank URLs caught.
- **Realistic evaluation**: 4,000 URLs never used in training (1,000 PhishTank + 1,000 Phishing.Database from unseen campaigns, 2,000 legitimate deep links from Tranco ranks 30,001-60,000). Random Forest: 86.4% accuracy, 86.2% F1, 11.9% false-positive rate. "Logistic Regression has fewer false positives (4.1%), which is one reason the final score does not rely on the ML model alone."
- **HTTPS-bias fix**: in the training data, 62.7% of phishing URLs use HTTPS against 92.5% of legitimate ones, but 90.3% of the modern phishing URLs do. A model that sees the scheme learns "http = phishing". It scores 93.4% F1 on the test split but only 86.5% on the realistic set, with lower recall on HTTPS phishing. So the scheme feature is dropped (44 instead of 45 features).
- **Metric definitions**, if asked: precision = of the URLs flagged as phishing, how many really are; recall = of all phishing URLs, how many were caught; F1 = their harmonic mean; ROC-AUC = the probability that a random phishing URL scores higher than a random legitimate one.

## Explaining the risk formula

```text
heuristic = 100 x (1 - e^(-raw / 18))      raw = failed-check weights + 0.4 x warning weights
risk      = round(0.6 x ML probability x 100 + 0.4 x heuristic)
```

- Worked example: ML probability 0.985 gives 0.6 x 98.5 = 59.1. A heuristic of 80 gives 0.4 x 80 = 32. The risk is 59.1 + 32 = 91, which is Phishing.
- **Floors**: strong evidence sets a minimum heuristic (blocklist 92, brand impersonation with a login form 85, off-site password form 80, brand impersonation 75, and so on). A blocklist hit puts the final risk at least at 90, a verified community report at least at 85.
- **Caps**: an official brand domain or a Tranco top-10k site with no blocklist hit is capped at 30.
- **Verdicts**: under 35 Legitimate, 35-64 Suspicious, 65 and above Phishing (adjustable in Settings).
- **Tiers**: Trusted (0-14), Favorable (15-34), Neutral (35-49), Questionable (50-64), Untrusted (65-100). Trust score = 100 - risk.

## Likely examiner questions

**Why combine ML with live checks instead of using only the model?**
The model sees only the URL string. Live checks add evidence the URL cannot show: domain age, certificate, login forms, brand look-alikes and blocklists. For example, the lexical model alone gives `www.wikipedia.org` about 48%, but the clean live checks and the popular-site cap make the final verdict Legitimate.

**Why 60% ML and 40% heuristics?**
The synopsis makes ML the core of the project, so it carries the larger weight. The heuristic part adds the live evidence. Both weights are constants in `backend/app/scoring.py` and the breakdown is shown on every report.

**How do you catch a brand-new phishing site that is on no blacklist yet?**
The model and the heuristics need no blacklist: lexical patterns, a young domain, a credential form on a look-alike domain or a brand name on the wrong domain are enough.

**How did you avoid data leakage and bias?**
Phishing URLs are deduplicated and capped at 3 per campaign, the split is grouped by campaign, legitimate homepages were augmented with real deep links, and the HTTPS shortcut was removed. The realistic set uses campaigns and domains that never appear in training.

**Why not deep learning?**
44 interpretable features with a Random Forest train in under 2 seconds, predict in milliseconds and can be explained per feature. Character-level CNN/LSTM models are listed as future scope.

**How does the explanation work?**
Perturbation: each feature that differs from a typical legitimate URL is reset to the legitimate median, and the change in probability is its impact. It is model-agnostic and shown for the 10 largest impacts.

**What if WHOIS or DNS fails?**
The lookup is marked as an error and the scan continues. WHOIS falls back to RDAP when the `whois` command is missing, as on Vercel.

**Is it safe to scan a phishing site?**
The server fetches it, not your browser. The SSRF guard allows only public IP addresses and ports 80, 443, 8080 and 8443, and re-checks every redirect, so a scanned URL cannot be used to reach internal machines.

**What about phishing pages on trusted platforms (Google Sites, Vercel, Blogspot)?**
Free hosting is an ML feature and a lexical check, and the popular-site cap is never applied to hosting or user-content platforms.

**How does the community feature work?**
Like PhishTank: a report plus votes. At a net +3 phishing votes the report is verified and the URL's risk is at least 85. At -3 it is rejected.

**What is different on the hosted demo?**
Demo mode: the data is a bundled snapshot that resets when the serverless function restarts, nothing runs in the background, and a daily cron job runs the watchlist checks.

**What are the limitations?**
It is an educational prototype on demo data. The URL model misses about 15% of phishing URLs on the realistic set, live checks depend on third-party services, and there are no user accounts or rate limits.

**What would you add next?**
From the synopsis: deep-learning URL models, regular retraining on fresh feeds, visual similarity and a mobile app. The extension, content analysis and threat-intelligence integration from the synopsis's future scope are already done.

**Why FastAPI and React instead of Streamlit?**
One REST API serves the dashboard, the Chrome extension, bulk jobs and scripts, and it documents itself at `/docs`.
