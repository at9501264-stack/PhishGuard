## ✨ Features

**At a glance**

| 🤖 **4** ML models compared | 🔢 **44** URL features | 🧪 **146,364** training URLs | 🏆 Random Forest: **F1 0.856** · **ROC-AUC 0.945** |
|---|---|---|---|
| 🔍 **50+** live checks in 7 categories | 🏷️ **92** brands watched for impersonation | 🗂️ **16** content categories | 🔤 **13** typosquat techniques |
| 🛑 **5** threat feeds (~**657k** entries) | 📮 **5** DNS blocklist zones | 📑 **15** report tabs | 🖥️ **17** dashboard pages |

### 🤖 Detection & machine learning

- **Four classifiers** (Logistic Regression, Decision Tree, Random Forest and SVM) trained on 44 lexical URL features. The best model by test F1, **Random Forest**, drives the score, and all four probabilities are shown side by side in every report.
- **Explainable predictions.** The ML Explanation tab lists the features that pushed the phishing probability up or down, with their signed impact (for example a very long hostname or a brand name in a sub-domain).
- **Hybrid risk score.** 60% ML probability + 40% live-check score, with floors for blocklist hits (≥ 90) and verified community reports (≥ 85), and a cap of 30 for popular or official domains that no engine lists.
- **Three verdicts and a full risk picture:** Legitimate / Suspicious / Phishing, a 0-100 risk score, a trust score (100 − risk), five reputation tiers (Trusted → Untrusted), a threat type (social engineering, malware, unwanted software) and a confidence value.
- **Plain-English summary** plus separate **negative and positive factor** lists, so every verdict can be traced back to its causes.
- **Model Lab page** with the dataset composition, the model comparison table, ROC and precision-recall curves, confusion matrices, feature importance, per-class feature averages, the "with / without scheme" comparison and a realistic held-out test on 4,000 URLs from unseen domains.
- **Adjustable thresholds.** The suspicious (35) and phishing (65) cut-offs can be changed in Settings, and tiers and verdicts follow them.

### 🔍 Deep URL analysis

- **50+ checks in 7 categories** (URL/lexical, domain, network, SSL/TLS, HTTP and page content, brand, reputation). Each check has a status (pass, warn, fail, info or error) and a weight, and the slow network checks run in parallel.
- **8-stage deep scan** with live progress: lexical analysis, ML prediction, DNS, WHOIS, SSL/TLS, HTTP and content, brand impersonation, reputation. A quick scan (URL features and model only) is one click away.
- **Domain:** WHOIS registrar, creation and expiry dates and privacy, with an **RDAP fallback** when the `whois` command is missing (as on Vercel). DNS A, AAAA, MX, NS and TXT records with SPF and DMARC checks.
- **Geo & hosting:** IP geolocation, ASN and hosting provider (ip-api.com, with ipwho.is as fallback).
- **SSL/TLS:** issuer, validity window, days left, certificate age, SANs, protocol, hostname mismatch and self-signed detection.
- **HTTP probe:** redirect chain, status, response time, server, security headers, technologies, forms (password fields, forms posting to another domain), links, iframes, external scripts, meta refresh and suspicious JavaScript patterns.
- **Brand impersonation** for 92 brands through typosquatting, homoglyphs, combosquatting, brand-as-sub-domain, punycode, path and page-content techniques.
- **Content:** page category (16 classes such as banking, payment, login, crypto and parked), page language with a one-click translate link, parked-domain detection and tracker IDs (Google Analytics, GTM, Facebook Pixel, AdSense, Hotjar).
- **Resources & source:** every script, stylesheet, image, frame and form the page references, the contacted domains (first or third party), and the stored HTML of the final page (gzipped, up to 500 KB) with line numbers and search.
- **Screenshot tab:** an optional page screenshot from the thum.io service (off by default, turned on in Settings).
- **SSRF guard:** before connecting to a scanned site, every resolved address must be public, and this is checked again on every redirect. Private, loopback, link-local and reserved addresses are refused, and only ports 80, 443, 8080 and 8443 are allowed.

### 🛑 Threat intelligence

- **Local threat feeds:** OpenPhish, PhishTank, URLhaus, Phishing.Database and Phishing Army, about **657,000 entries** in the current snapshot, with search, top targeted brands and top TLDs on the Threat Feeds page.
- **Multi-engine verdict:** every feed, five DNS blocklist zones (Spamhaus DBL and ZEN, SURBL, URIBL, SpamCop) and the PhishGuard ML engine count as engines, and the report shows **"N of M engines flagged"** with a per-engine table.
- **Optional Google Safe Browsing and VirusTotal lookups** when you add your own API keys in Settings.
- **Tranco popularity rank**, used as a strong "safe" signal for well-known sites (never for shared hosting platforms such as `vercel.app` or URL shorteners).
- **Typosquat finder:** dnstwist-style permutations of a domain with 13 techniques (omission, insertion, repetition, transposition, replacement, homoglyph, bitsquatting, vowel swap, hyphenation, addition, sub-domain, TLD swap and dictionary), checked live in DNS to show which look-alikes actually resolve.

### 🔔 Monitoring & alerts

- **Watchlist:** re-check URLs or domains on a schedule (every 15 minutes to weekly in the dashboard, 1 minute to 7 days through the API), optionally watch for newly resolving look-alike domains, and see each item's check history. On the Vercel demo the checks run once a day through Vercel Cron.
- **Alerts** for high-risk scans, verdict changes on watched items, new resolving typosquats, bulk jobs that found phishing and community verification, with an unread counter in the header bell.
- **Activity log:** an audit trail of scans, rescans, deletions, reports, votes, bulk jobs, watchlist and settings changes, feed refreshes and exports. Each event is linked to its scan or domain and feeds the report's **Timeline** tab.

### 👥 Community reporting

- **PhishTank-style reports:** anyone can report a URL as phishing or legitimate, and others vote on it. The reporter's label counts as the first vote.
- A report is **verified** at a net **+3** phishing votes and **rejected** at **−3**. A verified report raises the URL's risk to at least 85, and its status shows up in the report's Reputation tab.

### 📊 Analytics & tracking

- **Overview dashboard:** KPIs (total scans, detection rate, average trust score and more), scans over time, the verdict split, a risk-score histogram, top impersonated brands, top hosting countries, recent alerts, model health and a **live scan feed** that refreshes every 5 seconds.
- **Analytics page** for 24 h, 7 d, 30 d, 90 d or all time: scans and average risk over time, a weekday × hour heatmap, TLDs, scan sources, impersonation techniques, SSL status, domain age, top failing checks, countries, top domains, threat types, reputation tiers, content categories, a **detection funnel** (scanned → reachable → login form → brand impersonation → feed listed → phishing verdict), throughput and check error rates.
- **History:** search, filters, sorting and **CSV / JSON export** (CSV cells are protected against spreadsheet formula injection).
- **Domain page** with every scan of a domain and its risk trend.

### 🕸️ Investigation (graph, pivots)

- **Relationship graph** (Graph page and the report's Graph tab): scanned domains linked through shared IP addresses, ASNs, name servers, registrars, countries, impersonated brands and redirects, drawn as an interactive force-directed graph.
- **One-click pivots:** IP, ASN, registrar, content category, threat type and tier values in a report are links that open History filtered on that value (for example *all Untrusted sites* or *everything on this IP*).
- **Similar scans** on the same IP, ASN or registrar, listed in each report.
- **Compare** any two scans of the same domain side by side, and **rescan** a URL to see how it changed.
- **Timeline** of everything that happened to a scan or domain (scanned, rescanned, reported, voted, watched).

### 🔌 REST API & Chrome extension

- **Documented REST API** under `/api` (JSON, ISO-8601 UTC timestamps) with interactive **Swagger UI at [`/docs`](https://phishguard-mini-project.vercel.app/docs)** and ReDoc at `/redoc`. The in-app **API Guide** page has copy-paste `curl` examples grouped by task.
- **Bulk scanning** of up to 500 URLs per job (JSON list or CSV/TXT upload), processed in the background 5 at a time, with live progress.
- **URL extraction** from email or SMS text, including defanged links such as `hxxp://evil[.]com`. QR codes are decoded right in the browser.
- **Chrome extension** (Manifest V3, plain JavaScript, no build step): scans the current tab, shows the risk score as a coloured toolbar badge, warns with a desktop notification and an optional in-page banner, and adds a **"Scan link with PhishGuard"** item to the right-click menu. See [`extension/README.md`](extension/README.md).

### Feature parity with popular tools

PhishGuard's feature set comes from researching 12 public URL-safety services ([`docs/FEATURES.md`](docs/FEATURES.md)). The matrix lists **only features PhishGuard actually has**, and marks which of the 12 tools offer each one as a user-facing feature (based on that research, Oct 2026). No single tool covers more than 21 of these 38 features. PhishGuard brings all of them together in one free, open-source app.

<details open>
<summary><b>Tool abbreviations</b></summary>

**VT** [VirusTotal](https://www.virustotal.com) · **US** [urlscan.io](https://urlscan.io) · **GSB** [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search) · **PT** [PhishTank](https://phishtank.org) · **OP** [OpenPhish](https://openphish.com) · **UV** [URLVoid](https://www.urlvoid.com) · **CP** [CheckPhish](https://checkphish.bolster.ai) · **SU** [Sucuri SiteCheck](https://sitecheck.sucuri.net) · **SA** [ScamAdviser](https://www.scamadviser.com) · **IQ** [IPQualityScore](https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner) · **NS** [Norton Safe Web](https://safeweb.norton.com) · **TA** [Cisco Talos](https://talosintelligence.com/reputation_center)

</details>

| Feature | VT | US | GSB | PT | OP | UV | CP | SU | SA | IQ | NS | TA | **PhishGuard** | Where in PhishGuard |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|
| URL verdict / risk rating | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Scan page, report header |
| ML classifier with per-feature explanation |  | ✅ |  |  |  |  | ✅ |  |  | ✅ |  |  | ✅ | Report → ML Explanation |
| Trust score with positive and negative factors |  |  |  |  |  |  |  |  | ✅ |  |  |  | ✅ | Report → Summary |
| Reputation tiers (Trusted … Untrusted) |  |  |  |  |  |  |  |  |  |  | ✅ | ✅ | ✅ | Report header, History filter |
| Threat type (social engineering / malware / unwanted) |  |  | ✅ |  |  |  |  |  |  | ✅ |  |  | ✅ | Report header, History filter |
| Plain-English summary of why |  | ✅ | ✅ |  |  |  |  |  |  |  |  |  | ✅ | Report → Summary |
| "N of M engines flagged" with per-engine table | ✅ |  |  |  |  | ✅ |  | ✅ |  |  |  |  | ✅ | Report → Reputation |
| Threat-feed lookup, feed search and top brands |  |  |  | ✅ | ✅ |  |  |  |  |  |  |  | ✅ | Report → Reputation, Threat Feeds |
| DNS blocklists (Spamhaus, SURBL, URIBL, SpamCop) |  |  |  |  |  |  |  | ✅ |  |  |  | ✅ | ✅ | Report → Reputation |
| WHOIS, domain age, registrar, privacy |  |  |  |  |  | ✅ |  |  | ✅ | ✅ |  | ✅ | ✅ | Report → Domain |
| DNS records | ✅ |  |  |  |  |  |  |  |  | ✅ |  |  | ✅ | Report → Domain |
| IP geolocation, ASN, hosting provider | ✅ | ✅ |  |  |  | ✅ | ✅ |  | ✅ |  |  | ✅ | ✅ | Report → Geo & Hosting |
| SSL/TLS certificate details | ✅ | ✅ |  |  |  |  | ✅ |  | ✅ |  |  |  | ✅ | Report → SSL |
| Redirect chain | ✅ | ✅ |  |  |  |  |  |  |  | ✅ |  |  | ✅ | Report → HTTP |
| HTTP security headers and technologies | ✅ | ✅ |  |  |  |  |  | ✅ |  |  |  |  | ✅ | Report → HTTP |
| Login / password-form detection | ✅ | ✅ |  |  |  |  |  |  |  |  |  |  | ✅ | Report → HTTP |
| Suspicious JavaScript and hidden iframes | ✅ |  |  |  |  |  |  | ✅ |  |  |  |  | ✅ | Report → HTTP |
| Brand impersonation detection |  | ✅ |  |  | ✅ |  | ✅ |  |  |  |  |  | ✅ | Report → Brand |
| Content category | ✅ |  |  |  |  |  |  |  |  | ✅ |  | ✅ | ✅ | Report → Content |
| Language detection with translate link |  | ✅ |  |  |  |  |  |  |  |  |  |  | ✅ | Report → Content |
| Parked-domain detection |  |  |  |  |  |  |  |  |  | ✅ |  |  | ✅ | Report → Content |
| Popularity rank (Tranco) |  |  |  |  |  |  |  |  | ✅ |  | ✅ |  | ✅ | Report → Summary |
| Page screenshot (optional, thum.io) | ✅ | ✅ |  |  |  |  | ✅ |  |  |  |  |  | ✅ | Report → Screenshot |
| Stored HTML source viewer | ✅ | ✅ |  |  |  |  | ✅ |  |  |  |  |  | ✅ | Report → Source |
| Page resources and contacted domains | ✅ | ✅ |  |  |  |  |  |  |  |  |  |  | ✅ | Report → Resources |
| Tracker IDs (GA, GTM, Facebook Pixel …) | ✅ |  |  |  |  |  |  |  |  |  |  |  | ✅ | Report → Content |
| Relationship graph | ✅ |  |  |  |  |  |  |  |  |  |  |  | ✅ | Graph page, Report → Graph |
| Pivot search (IP, ASN, registrar, tier …) | ✅ | ✅ |  |  |  |  |  |  |  |  |  |  | ✅ | History |
| Scan history with filters and export | ✅ | ✅ |  |  |  |  |  |  |  |  |  |  | ✅ | History |
| Per-domain timeline and scan compare | ✅ | ✅ |  |  |  |  |  |  |  |  |  |  | ✅ | Domain page, Report → Compare |
| Typosquat / look-alike finder |  |  |  |  |  |  | ✅ |  |  |  |  |  | ✅ | Typosquat |
| Watchlist monitoring with alerts |  | ✅ |  |  |  |  | ✅ |  |  |  |  |  | ✅ | Watchlist, Alerts |
| Community reports with voting | ✅ |  |  | ✅ |  |  |  |  |  |  |  |  | ✅ | Community |
| Bulk scanning | ✅ |  |  |  |  | ✅ |  |  |  | ✅ |  |  | ✅ | Bulk Scan |
| URLs from email / SMS text |  |  |  |  |  |  | ✅ |  |  |  |  |  | ✅ | Scan → Email / SMS text |
| Browser extension |  |  |  |  |  |  |  |  | ✅ | ✅ | ✅ |  | ✅ | `extension/` |
| REST API with docs | ✅ | ✅ | ✅ |  |  | ✅ | ✅ |  | ✅ | ✅ |  |  | ✅ | `/api`, Swagger at `/docs` |
| Global statistics and live scan feed |  | ✅ |  | ✅ | ✅ |  |  |  |  |  |  | ✅ | ✅ | Overview, Analytics |
| **Features covered (of 38)** | **21** | **19** | **4** | **4** | **4** | **6** | **11** | **5** | **8** | **11** | **4** | **7** | **38** | |

Some ideas from these tools were researched but are **not** part of this mini project, for example API keys and rate limits, dispute tickets, star reviews, saved-search hunting rules, certificate-transparency monitoring, rendering pages in a headless browser and takedown requests.
