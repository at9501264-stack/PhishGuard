## 🧭 Usage guide

Open the dashboard (<http://localhost:5173> locally, or the [live demo](https://phishguard-mini-project.vercel.app)). Every page is in the left sidebar. The header has a **quick-scan box** (URL + ML only, instant), the **alerts bell**, the light/dark **theme toggle** and, at the bottom of the sidebar, the API status dot with the loaded model version.

> [!WARNING]
> Scan suspicious links **in PhishGuard**, never by opening them in your own browser. A deep scan fetches the page from the server, with an SSRF guard that blocks private and local addresses.

### 1. Scan something

The **Scan** page has three input tabs:

| Tab | What you give it | What happens |
|---|---|---|
| **Single URL** | one link, e.g. `http://paypal-login-verify.secure-account.xyz/update` | **Deep scan on** runs DNS, WHOIS/RDAP, SSL/TLS, HTTP and content checks, brand detection and reputation lookups (2-4 s). **Deep scan off** runs URL features + ML only, in milliseconds. A progress list shows each stage. |
| **Email / SMS text** | a pasted message | every link is extracted, including defanged ones (`hxxp://`, `example[.]com`) and bare domains; tick the ones you want and scan them in one go |
| **QR code** | an image file | the QR code is decoded **in your browser** (jsQR), the URL inside is shown, then scanned |

Every scan opens its **report** at `/scans/<id>`.

### 2. Read a report

The top card summarises the result:

| Item | Meaning |
|---|---|
| **Risk gauge (0-100)** | `0.6 × ML probability × 100 + 0.4 × heuristic score`, raised to at least 90 on a blocklist hit and at least 85 for a verified community report; very popular official domains are capped unless something lists them |
| **Verdict** | **Legitimate** below 35, **Suspicious** 35-64, **Phishing** 65 and above (thresholds can be changed on Settings) |
| **Trust score** | `100 - risk`, so a high number is good |
| **Tier** | Trusted, Favorable, Neutral, Questionable or Untrusted, a five-band reading of the same score |
| **Threat type** | social engineering (phishing), malware, unwanted software or none, chosen from the evidence |
| **Engines** | how many detection sources flagged the URL (threat feeds, DNS blocklists, optional VirusTotal / Safe Browsing, PhishGuard ML) |
| **Stats row** | confidence, ML probability and model name, failed checks, scan duration, scan time |

Then the tabs, in order:

| Tab | What it shows |
|---|---|
| **Summary** | plain-English summary, score breakdown, positive and negative factors, every check grouped by category with pass/fail |
| **ML Explanation** | the phishing probability from each of the 4 models (Random Forest drives the score) and the URL features that pushed it up or down |
| **Domain** | WHOIS/RDAP registrar, creation and expiry dates, domain age, DNS records |
| **Geo & Hosting** | IP addresses, country, ASN and hosting provider |
| **SSL** | certificate validity, issuer, dates and hostname match |
| **HTTP** | status, redirect chain, response headers, security headers |
| **Content** | page title, category, language, forms and password fields, trackers |
| **Resources** | scripts, styles and images the page loads and the domains it contacts |
| **Brand** | impersonated brand and technique (typosquat, homoglyph, combosquat, sub-domain, punycode, ...) |
| **Reputation** | threat-feed hits, DNS-blocklist results, engine list, the community verdict with **Phishing** / **Legitimate** vote buttons |
| **Screenshot** | a page preview from thum.io, when **Capture page screenshots** is on in Settings (off by default) |
| **Source** | the stored HTML of the page |
| **Graph** | this domain's links to IPs, ASNs, name servers, registrars and brands |
| **Timeline** | every event for this scan and domain: scans, rescans, reports, alerts |
| **Raw JSON** | the complete API response |

Header buttons: **Rescan**, **Report** (submit to the community), **Tags & notes**, **Compare** (field-by-field difference with another scan of the same domain), **JSON** download, **Print**, **Share** (copy link) and **Delete**. Click the domain name for the **domain page** (`/domains/<domain>`): every scan of that domain and its risk trend.

### 3. History and pivots

**History** lists every scan with search and filters: verdict, source (web, API, bulk, text, QR, extension), TLD, brand, risk range and date range, plus sorting and paging. The chips in each row are **pivots**: click an IP, ASN, registrar, category, threat type or tier to see every other scan that shares it (the filter is stored in the URL, e.g. `/history?asn=13335`). **Export CSV / JSON** downloads exactly what is filtered.

### 4. Bulk scan

On **Bulk Scan**, paste up to **500 URLs** or upload a **CSV/TXT** file (max 5 MB). The job runs in the background with a progress bar, a verdict pie chart and a results table you can filter and open. Jobs keep running if you leave the page, and an alert is raised when a job finds phishing URLs.

### 5. Watchlist and typosquats

- **Watchlist:** add a URL or domain, a label, a check interval (every 15 minutes, hourly (the default), every 6 hours, daily or weekly; the API accepts 1 minute to 7 days) and optionally **Monitor typosquats**. The background loop runs the first check within about a minute and then re-scans each item when it is due (on Vercel the loop is off and the daily cron does this). **Run** checks an item immediately. Each item shows its check history. You get an alert when the verdict changes or when a new look-alike domain starts resolving.
- **Typosquat:** enter a domain (for example `paypal.com`) to generate dnstwist-style permutations (omission, repetition, transposition, homoglyph, bitsquatting, TLD swap, hyphenation, ...) and check which ones resolve in DNS. A chart compares generated vs. resolving permutations per technique, and any permutation can be quick-scanned with one click.

### 6. Community

On **Community**, report a URL as phishing or legitimate with a comment, and vote on other reports. The reporter's label counts as the first vote. A report becomes **verified** at +3 net phishing votes (its URL then gets a risk of at least 85) and **rejected** at -3. Votes from the Reputation tab of a report land here too.

### 7. Analytics

**Overview** gives the headline view: KPI cards, scans over time, verdict split, risk histogram, top impersonated brands, top hosting countries and a live feed of recent scans. **Analytics** goes deeper, with a range selector (24h / 7d / 30d / 90d / all): scans over time, average risk trend, a weekday × hour heatmap, TLDs, scan sources, impersonation techniques, SSL status, domain age, top failed checks, countries, top domains, threat types, reputation tiers, content categories, the **detection funnel**, throughput and check error rates.

### 8. Model Lab

**Model Lab** shows how the ML part was built and how well it works, all read from `backend/ml/artifacts/metrics.json`: the dataset and its composition, the comparison table of the four models (accuracy, precision, recall, F1, ROC-AUC, best value highlighted), the metric chart, the **realistic evaluation on unseen domains**, confusion matrices, ROC and precision-recall curves, feature importance and feature statistics (phishing vs. legitimate means).

### 9. Relationship graph

**Graph** draws how scanned domains connect through shared IPs, ASNs, name servers, registrars, brands and redirects (VirusTotal-Graph style). Search for a domain (or open it from a report's Graph tab), choose depth 1 or 2, drag nodes around and click one to see its details and linked scans. Clusters of phishing domains on the same infrastructure stand out quickly.

### 10. Threat feeds, alerts and activity log

- **Threat Feeds:** status and entry counts of the five local blocklists (OpenPhish, PhishTank, URLhaus, Phishing.Database, Phishing Army), charts of top TLDs and targeted brands, a search box across all entries and a **Refresh feeds** button.
- **Alerts:** high-risk scans, verdict changes, new typosquats, bulk jobs that found phishing and community verifications, with severity levels. Mark them read one by one or all at once; the bell in the header shows the unread count.
- **Activity Log:** the full audit trail (scans, rescans, deletions, reports, votes, bulk jobs, watchlist and settings changes, feed refreshes, exports), filterable by type.

### 11. Settings and API

- **Settings:** the suspicious and phishing thresholds (with a live preview of the bands), network checks on/off (off = instant offline URL + ML scoring), page screenshots on/off, the per-check timeout, data retention, and the optional VirusTotal / Google Safe Browsing API keys (stored server-side, masked in responses).
- **API guide** (`/api-guide`) shows ready-to-copy `curl` examples, and **Swagger UI** at [`/docs`](http://localhost:8000/docs) lets you call every endpoint from the browser.

> [!TIP]
> Presenting the project? [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md) is a minute-by-minute **5-minute viva demo script**: which URLs to scan, what to point at on each report tab, how to explain the metrics and the risk formula, and short answers to likely questions.
