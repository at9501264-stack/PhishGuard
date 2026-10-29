# PhishGuard — Competitive Feature Research (Oct 2026)

Research of the public URL-safety services that PhishGuard merges (see `docs/SPEC.md`). Features were confirmed from vendor pages, docs and blogs where they were reachable in Oct 2026. CheckPhish blocked direct fetching (HTTP 403), so its row comes from Bolster's knowledge base and search snippets. Kaspersky OpenTIP and Hybrid Analysis were left out: they are mainly file and sandbox tools, and SPEC already names the 12 services below.

## 1. Tools and key features

| # | Tool | URL | Key user-facing features |
|---|---|---|---|
| 1 | VirusTotal | https://www.virustotal.com | • Multi-engine verdict (detections out of about 90 engines) • Community score and comments/votes • Details tab: HTTP response, headers, redirect chain, categories • Relations tab plus VT Graph (domain/IP/redirect pivots) • **URL Scanning 2.0 (Aug 2026):** headless-browser screenshot, DOM tree, web-tech detection, network request log, contacted domains/IPs with geo, tracker IDs, password-field and cloned-site tags, favicon dhash, **History timeline** of past scans with filters • Public API (free key, rate-limited) |
| 2 | urlscan.io | https://urlscan.io | • Headless-browser scan: screenshot, DOM, full HTTP transaction list, contacted IPs/ASNs/countries, certificates, technologies • Verdicts (malicious/suspicious score, brand, category) • Brand detection for 1500+ brands • **Brand AI 2.0** (visual brand name, `visible.brandname`), **ML Verdicts 2.0** (score −100..100), **AI summaries and translation** of the screenshot (Mar 2026) • Search and pivot on any field (domain, IP, ASN, hash, favicon) • Public, unlisted and private visibility • Pro: visual similarity search, saved-search alerts, history back to 2016 • API |
| 3 | Google Safe Browsing / Transparency Report | https://transparencyreport.google.com/safe-browsing/search | • Site status lookup (flagged or not) • Threat type (social engineering, malware, unwanted software) • Explains why a site was flagged • No active scan • Lookup API (key) and Web Risk |
| 4 | PhishTank (Cisco Talos) | https://phishtank.org | • Community phish submission • Community **voting to verify** submissions • Online/offline status tracking • Target brand field • Searchable database • Downloadable feed (JSON/CSV, registration lifts limits) |
| 5 | OpenPhish | https://openphish.com | • Automated phishing-URL detection • Free community feed (`feed.txt`, updated about every 12h, non-commercial) • Premium feed with brand, IP, ASN and kit metadata • Phishing stats (top targeted brands and sectors) |
| 6 | URLVoid | https://www.urlvoid.com | • Checks 30+ blocklist engines, shown as a detection ratio with a link to each engine's report • IP address, server location, ASN • Domain creation date (age) • Bulk/API (paid) |
| 7 | CheckPhish (Bolster) | https://checkphish.bolster.ai | • Real-time sandboxed scan with screenshot, certificate, DOM tree, hosting details • Brand impersonation (3000+ brands) • **Typosquat/lookalike domain monitoring** • Outlook add-in email link scanner • Free API (about 25 scans/day) • Bolster platform: automated takedown |
| 8 | Sucuri SiteCheck | https://sitecheck.sucuri.net | • Remote malware scan (injected JS, spam/SEO spam, defacement, malicious iframes) • Blocklist status across Google SB, Norton, McAfee, ESET, Yandex, PhishTank, Spamhaus and others • **Outdated CMS/software detection** • Website errors • Security-hardening recommendations (headers, WAF) |
| 9 | ScamAdviser | https://www.scamadviser.com | • **Trust score 1-100** from 40+ data points, listing positive and negative factors • Domain age, owner/WHOIS privacy, server location, SSL, blacklists • Popularity/traffic • E-commerce signals (payment methods, crypto) • User reviews/ratings and scam reports • Browser extension |
| 10 | IPQualityScore (IPQS) URL scanner | https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner | • Risk score 0-100 (≥85 suspicious, 100 confirmed) • Booleans: phishing, malware, suspicious, spamming, adult, **parking** • Category (70+ content categories) • Domain age, DNS validity, redirects, server, content type, page size • Browser extension, API |
| 11 | Norton Safe Web | https://safeweb.norton.com | • Rating tiers: Safe / Caution / Unsafe / Untested • Threat report (threat types and counts) • **Community rating and user reviews**, with reviewers weighted by reputation • Site-owner re-evaluation/dispute • Re-checks based on how often a site is likely to change ("rating aging") • Browser extension |
| 12 | Cisco Talos Reputation Center | https://talosintelligence.com/reputation_center | • Web reputation tier (Trusted / Favorable / Neutral / Questionable / Untrusted) • Threat categories vs **content categories** • Email/spam sender reputation and volume, top spam countries • IP/domain owner and ASN • **Reputation dispute and recategorization tickets** |

## 2. Merged feature matrix

Legend for the "SPEC?" column: **Yes** = fully specified, **Partial** = some data exists but the feature is incomplete, **No** = missing.

| Feature | Tools | SPEC? | SPEC reference |
|---|---|---|---|
| Single URL scan with verdict and risk score | All | Yes | §3 Scoring, `POST /api/scan` |
| ML / AI classifier score with explanations | urlscan (ML Verdicts), IPQS, Bolster | Yes | §1 `predict()`, ScanResult.ml |
| Multi-engine blocklist check with per-engine results | VT, URLVoid, Sucuri, GSB | Partial | `reputation.sources`, §2 `feeds.lookup` (local feeds only; no "N/M engines" ratio, no DNSBLs) |
| Threat-intel feed ingestion (PhishTank/OpenPhish/URLhaus) | PhishTank, OpenPhish | Yes | §2 `feeds.py`, `GET /api/feeds*` |
| Feed browse/search and top targeted brands | PhishTank, OpenPhish | Yes | `GET /api/feeds/search`, `stats()` |
| Google Safe Browsing lookup | GSB, Sucuri, URLVoid | Partial | settings `google_safe_browsing_api_key` (needs key; no keyless threat-type label) |
| Screenshot | urlscan, VT, CheckPhish | Yes | `enable_screenshots`, `screenshot_url`, Screenshot tab |
| DOM / raw HTML snapshot viewer | urlscan, VT, CheckPhish | No | none (`http` keeps only derived fields) |
| Network request log / contacted domains and IPs | urlscan, VT | No | none (`external_scripts` is a count only) |
| Redirect chain | VT, urlscan, IPQS | Yes | `http.redirect_chain` |
| HTTP security headers | Sucuri, VT | Yes | `http.security_headers` |
| Technology detection | urlscan, VT, Sucuri | Yes | `http.technologies` |
| Outdated software / CMS version check | Sucuri | No | none |
| Malicious JS / injected spam / hidden iframes | Sucuri, VT | Partial | `http.suspicious_js`, `iframes` (no SEO-spam or miner signatures) |
| Login/password form detection | VT (password fields), urlscan | Yes | `http.forms` |
| SSL/TLS certificate details | All | Yes | `ssl` |
| WHOIS / domain age / registrar / privacy | URLVoid, ScamAdviser, IPQS | Yes | `domain_info.whois` |
| DNS records | VT, IPQS | Yes | `domain_info.dns` |
| IP geolocation / ASN / hosting | URLVoid, urlscan, Talos | Yes | `domain_info.geo` |
| Brand impersonation detection | urlscan, CheckPhish, OpenPhish | Yes | `brand` |
| Visual/favicon similarity and favicon hash | urlscan (Pro), VT (dhash) | No | none (`favicon_external` is a boolean only) |
| Typosquat / lookalike generation and resolution | CheckPhish | Yes | `GET /api/typosquat` |
| Domain monitoring and alerts | CheckPhish, urlscan Pro | Yes | Watchlist, Alerts |
| Saved searches / hunting rules with alerts | urlscan Pro, VT | No | none |
| Certificate-transparency monitoring for lookalikes | Bolster | No | none |
| Community submission and voting | PhishTank, VT | Yes | `/api/reports`, `/vote` |
| User reviews with star rating and reviewer reputation | Norton, ScamAdviser | Partial | reports have votes and comment only |
| Dispute / false-positive re-evaluation | Talos, Norton, GSB | Partial | report with label `legitimate` (no dispute workflow/status) |
| Trust score with positive/negative factors listed | ScamAdviser | Partial | `score_breakdown`, `checks` (no positive-factor list or trust framing) |
| Reputation tier labels (Safe/Caution/Untrusted…) | Norton, Talos | Partial | 3 verdicts only |
| Content category classification | Talos, IPQS, VT | No | none |
| Parked domain detection | IPQS | No | none |
| Email/spam reputation (SPF/DMARC/DNSBL) | Talos, IPQS (spamming) | Partial | `dns.txt`, `dns.mx` raw only |
| Popularity / traffic rank | ScamAdviser, Norton | No | none |
| E-commerce scam signals (payments, contact info, discounts) | ScamAdviser | No | none |
| AI summary / translation of the page | urlscan | No | none |
| Cloaking detection (different UA/geo) | urlscan, CheckPhish (proxy) | No | none |
| Downloaded file / payload hash | VT, urlscan | No | none |
| Tracker IDs (GA/GTM) for pivoting | VT | No | none |
| Scan history and search with filters | urlscan, VT | Yes | `GET /api/scans` |
| Pivot search by IP/ASN/registrar/NS/server | urlscan, VT | Partial | filters lack ip/asn/registrar/ns |
| Per-URL/domain history timeline | VT (History), urlscan | Yes | `GET /api/domains/{domain}` `risk_trend` |
| Compare two scans | VT history | Yes | `/compare/{other_id}` |
| Relationship graph | VT Graph | No | none |
| Bulk scanning | URLVoid, IPQS, VT | Yes | `/api/bulk*` |
| Extract URLs from email/SMS text | CheckPhish (Outlook) | Yes | `POST /api/extract` |
| Browser extension / email add-in | Norton, ScamAdviser, IPQS, CheckPhish | Partial | `source:"extension"` exists, but no extension is built |
| Public, unlisted or private scan visibility | urlscan | No | none (single-user app) |
| REST API with docs | All | Yes | §4, `/docs` |
| API keys and rate limits | VT, urlscan, CheckPhish | No | none |
| Export (CSV/JSON/PDF) | VT, urlscan | Yes | `/api/scans/export`, print/PDF |
| Global stats / trends dashboards | OpenPhish, Talos, PhishTank | Yes | `/api/analytics/*` |
| Recent-scans live feed | urlscan home, PhishTank | Yes | `GET /api/stats/live` |
| Takedown / abuse reporting | Bolster | No | none |
| Re-scan / rating aging | Norton, VT | Partial | `POST /rescan`, watchlist intervals (no auto re-check of stale scans) |

## GAPS

These are features from the tools above that SPEC.md does not fully cover. Each suggestion works locally with Python/FastAPI + React and no paid keys. **[R]** = realistic for this project. **[S]** = stretch (needs heavier dependencies or is flaky).

1. **DOM/HTML snapshot viewer** [R]: store the first 500 KB of fetched HTML, gzipped in SQLite; add `GET /api/scans/{id}/dom` and a "Source" tab with syntax highlighting.
2. **Contacted domains / resource list** [R]: parse `script/img/link/iframe/form` src/href with BeautifulSoup into `http.resources: [{url, domain, type, third_party}]` (or log real requests via Playwright [S]).
3. **Favicon hash and visual similarity** [R]: fetch the favicon, compute mmh3 (Shodan-style) and Pillow dHash, store per scan, and show "other scans with the same or similar favicon" (Hamming distance ≤ 6).
4. **Relationship graph** [R]: `GET /api/graph?domain=` builds nodes and edges (domain↔IP↔ASN↔NS↔registrar↔favicon↔redirect target) from stored scans; render with an SVG force layout.
5. **Pivot search fields** [R]: add `ip`, `asn`, `registrar`, `ns`, `server`, `favicon_hash` filters to `GET /api/scans`, with clickable values in the report.
6. **Multi-engine ratio plus free DNSBLs** [R]: treat each local feed and each free DNS blocklist (Spamhaus DBL/ZEN, SURBL, URIBL via dnspython) as an "engine" and show "3/9 engines flagged" with a per-engine table.
7. **Keyless GSB-style threat type** [R]: map checks and feed hits to a `threat_type` of social_engineering, malware or unwanted_software, shown as a badge.
8. **Outdated software detection** [R]: read versions from the `generator` meta, `X-Powered-By`, `Server` and `?ver=` asset strings, and compare them against a bundled JSON of current WordPress/Joomla/Drupal/jQuery/PHP/nginx versions.
9. **Malware/SEO-spam signatures** [R]: regex rules for `eval(atob(`, `document.write(unescape`, hidden 0-px iframes, coinhive/miner hosts and pharma/casino keyword spam, added as "content" checks.
10. **Content category classification** [R]: TF-IDF + LogisticRegression (or a keyword dictionary) over title and visible text into about 15 categories (banking, shopping, crypto, adult, gambling, login, parked…).
11. **Parked domain detection** [R]: flag parking NS/hosts (sedoparking, bodis, parkingcrew, dan.com, afternic) and "domain for sale" text, as `parked: bool`.
12. **Email/spam reputation** [R]: use dnspython to check SPF, DMARC (`_dmarc.`) and MX presence plus DNSBL listing of the IP, shown as an "Email security" card.
13. **Popularity rank** [R]: download the free Tranco top-1M CSV into `backend/data/`, look up the rank, use it as a safe signal, and show "Top 10k site" badges.
14. **E-commerce scam signals** [R]: parse the page for payment logos/crypto-only payment, missing contact/address/refund pages, extreme "% off" text and missing social links, added as checks.
15. **Trust score and positive factors** [R]: show `trust_score = 100 - risk_score` and split checks into "Positive" and "Negative" factor lists, ScamAdviser-style.
16. **Reputation tier labels** [R]: map the risk score to 5 tiers (Trusted / Favorable / Neutral / Questionable / Untrusted) plus "Untested" when the network checks failed.
17. **Star reviews and reviewer reputation** [R]: add `rating 1-5` to reports and weight votes by each voter's past agreement with verified outcomes.
18. **Dispute / re-evaluation workflow** [R]: `POST /api/disputes {scan_id, reason}` triggers a forced rescan, gets a status (open/upheld/overturned) and appears in the Community page.
19. **AI-style page summary** [R]: generate a rule-based natural-language summary from the checks, e.g. "Login form posting to external domain, 3-day-old domain, impersonates PayPal". Add language detection with `langdetect`. Translation is [S].
20. **Cloaking detection** [R]: fetch with desktop, mobile and Googlebot user agents, compare status, title and content hash, and add a `cloaking` check when they differ.
21. **Download/payload detection** [R]: detect `Content-Disposition` or executable/archive extensions in links or the final response, record sha256, and flag it (no AV engine).
22. **Tracker ID extraction** [R]: regex GA (`G-`, `UA-`), GTM, FB pixel and AdSense IDs into `http.trackers` for pivoting.
23. **Saved searches / hunting rules** [R]: `POST /api/rules {query filters}` is evaluated after each scan, and a match creates an alert.
24. **Certificate-transparency lookalike monitoring** [S]: poll the free crt.sh JSON (`?q=%brand%`) for watched domains and alert on new certs for lookalike names. Free but rate-limited and flaky.
25. **Takedown/abuse report generator** [R]: build an abuse email to the registrar or host from WHOIS/RDAP abuse contacts plus evidence (risk, screenshot link), with a copy/mailto button.
26. **Browser extension** [R]: a minimal Chrome MV3 extension that sends the current tab URL to `localhost:8000/api/scan` (`source:"extension"`) and shows a verdict badge.
27. **API keys and rate limiting** [R]: an `api_keys` table with an `X-API-Key` header for `source:"api"` and an in-memory token bucket per key, managed in Settings.
28. **Stale-scan auto re-check ("rating aging")** [R]: the background loop rescans any URL whose latest scan is older than N days and was phishing/suspicious, and logs the change.
29. **Scan visibility (public/unlisted/private)** [S, low value]: add a `visibility` column and hide private scans from the live feed and share links. Of limited use in a single-user local app.
