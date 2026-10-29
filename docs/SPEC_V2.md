# PhishGuard — SPEC v2 (feature-gap merge). Additive to `SPEC.md` (v1 stays valid).

> ## ⚠️ MINI-PROJECT SCOPE (decided 2026-10-24, overrides the rest of this file)
> This is a B.Tech **mini project demo running on demo data**, not a production system. Build fast; keep it working and clear.
> **KEEP (implement):** SSRF guard per hop (`net_safety.py`) · Tranco popularity rank + safe signal · RDAP fallback for WHOIS when the
> system `whois` binary is missing (needed on Vercel) · `dom_html` + `GET /api/scans/{id}/dom` + Source tab · `http.resources`,
> `http.contacted_domains`, `http.trackers` + Resources tab · `content` = category, language (+translate_url), parked (no ecommerce/software/signatures
> beyond what v1 already has) + Content tab · `summary_points` → `summary` · `reputation.engines` + `engine_ratio` (local feeds + DNSBL if already
> working + "PhishGuard ML") · `coverage` · scoring: `trust_score`, `tier`, `tested_depth`, `threat_type`, `factors`, `summary` · pivot filters
> (`ip, asn, registrar, category, threat_type, tier`) on `/api/scans` + export · `GET /api/graph` + Graph page + Graph tab (ForceGraph) ·
> `GET /api/scans/{id}/similar` (same IP/ASN/registrar only) · events `entity_type/entity_id` + `GET /api/scans/{id}/timeline` + Timeline tab ·
> analytics: `threat_types, tiers, categories` in distribution, `GET /api/analytics/funnel`, `avg_trust_score` in overview ·
> env vars `PHISHGUARD_DB_PATH`, `PHISHGUARD_NO_SEED`, `PHISHGUARD_NO_SCHEDULER`, `PHISHGUARD_CLOUD` (health returns `cloud: bool`; UI shows a demo banner).
> **CUT (do not build; remove half-built unwired code for these):** Playwright browser capture, cloaking, downloads/sha256, favicon hashing/similarity,
> outdated-software & ecommerce & extra signature checks, CT monitoring, abuse/takedown report generator, API keys & rate limiting, disputes,
> star reviews & weighted voter reputation, hunting rules, rating-aging auto re-check, scan visibility/share tokens, email-security card,
> usage/brands/engines analytics endpoints, extension v2 changes.

Source of the gaps: `docs/FEATURES.md` (research of VirusTotal, urlscan.io, Google Safe Browsing,
PhishTank, OpenPhish, URLVoid, CheckPhish, Sucuri, ScamAdviser, IPQS, Norton Safe Web, Cisco Talos).
Every gap G1–G29 below must be implemented. Ownership is the same as v1 (see SPEC.md) plus:
Frontend is split into **FE-Report** (owns `frontend/src/pages/Report.tsx` and `frontend/src/pages/report/**`)
and **FE-Pages** (everything else in `frontend/src/**` except `src/api/client_v2.ts`, which the
**FE-Contract** step writes first and both FE agents treat as read-only; `src/components/ForceGraph.tsx` is owned by FE-Pages).

## 0. Safety rules (all agents)
- **No fetching of internal addresses (SSRF guard).** Before ANY outbound connection to the scanned
  site (HTTP probe, SSL, favicon, cloaking variants, downloads, browser capture), resolve the host and
  refuse if any resolved IP is not `ipaddress.ip_address(ip).is_global` (blocks loopback, RFC1918,
  link-local/169.254.x, CGNAT, multicast, reserved) or the port is not 80/443/8080/8443. Re-check on
  every redirect hop. Blocked → sub-result `error: "blocked: non-public address"` and a `fail` check
  `private_network_host` ("Host resolves to a private/internal network address"). Lexical/ML still run.
- Downloads are hashed in a streaming way (max 25 MB) and NEVER written to disk.
- Browser capture (Playwright) is OFF by default (`enable_browser_capture: false`), runs headless
  Chromium with `accept_downloads=False`, a fresh context per scan, a route filter that aborts requests
  to non-public IPs, and a hard timeout.
- Everything stays JSON-serialisable (ISO strings, no bytes/datetime).

## 1. Engine additions (`backend/app/analysis/**`) — new keys in `run_checks()` output
New/updated modules (owner Engine): `net_safety.py`, `dnsbl.py`, `content.py`, `favicon.py`,
`cloaking.py`, `popularity.py`, `abuse.py`, `ct.py`, `browser.py`, `software_versions.json`.
Extra deps (Engine installs): `mmh3`, `Pillow`, `langdetect`, `playwright` (+ `playwright install chromium`).

`run_checks(url, settings)` gains these settings keys: `enable_browser_capture: bool`,
`enable_cloaking_check: bool` (default true), `enable_dnsbl: bool` (default true), `enable_rdap: bool` (default true).
It returns everything from v1 **plus**:
```
"http": { ...v1,
   "resources": [{"url","domain","type": "script|stylesheet|image|iframe|form|link|media|other","third_party": bool}],  # ≤200   (G2)
   "contacted_domains": [{"domain","count","third_party": bool}],                                                      # (G2)
   "trackers": [{"type": "google_analytics|gtag|gtm|facebook_pixel|adsense|hotjar|other","id"}],                       # (G22)
   "download": {"detected": bool, "filename", "content_type", "size", "sha256", "source": "final_response|link"} | null, # (G21)
   "download_links": [{"url","ext"}] },                                                                                 # (G21)
"dom_html": str | null,          # raw HTML of final page, ≤500 KB (API stores gzipped & strips it from the scan JSON) (G1)
"favicon": {"url", "mmh3": int|null, "dhash": "16-hex"|null, "size", "error"},                                         # (G3)
"reputation": { ...v1 (blacklisted, sources),
   "engines": [{"name","type": "feed|dnsbl|api|heuristic","listed": bool|null,"detail","category": "phishing|malware|spam|suspicious|clean|error"}],  # (G6)
   "engine_ratio": {"flagged": int, "total": int} },     # total = engines that returned a definite answer (listed not null)
"email_security": {"mx": bool, "mx_hosts": [], "spf": bool, "spf_record", "dmarc": bool, "dmarc_policy": "none|quarantine|reject"|null,
                   "ip_dnsbl_listed": bool|null, "score": 0-100},                                                     # (G12)
"popularity": {"rank": int|null, "tier": "top1k|top10k|top100k|top1m"|null, "source": "Tranco"},                        # (G13)
"content": {"language": "en"|null, "language_name", "translate_url",                                                  # (G19)
   "category": "banking|payment|shopping|crypto|social|email|cloud_storage|government|education|news|technology|entertainment|adult|gambling|parked|login|other",
   "category_confidence": 0-1, "categories": [{"name","score"}],                                                       # (G10)
   "parked": {"parked": bool, "reason"|null},                                                                         # (G11)
   "ecommerce": {"is_shop": bool, "payment_methods": [], "crypto_only": bool, "has_contact": bool, "has_refund_policy": bool,
                 "has_address": bool, "extreme_discounts": bool, "social_links": int},                                 # (G14)
   "signatures": [{"id","name","severity": "low|medium|high","match"}],                                                # (G9)
   "software": [{"name","version","latest","outdated": bool,"source"}],                                                # (G8)
   "word_count": int, "text_excerpt": str},
"cloaking": {"checked": bool, "detected": bool, "similarity": 0-1,
             "variants": [{"agent": "desktop|mobile|googlebot","status","final_url","title","length","hash"}], "detail"} , # (G20)
"abuse": {"registrar", "registrar_abuse_email", "host_org", "host_abuse_email", "source": "rdap"} ,                  # (G25)
"browser": null | {"screenshot_file": "<name>.png", "final_url", "title", "requests": [{"url","method","resource_type","status","domain"}],
                   "console": [{"type","text"}], "cookies": [{"name","domain","secure","http_only"}], "dom_html"}, # (G2 [S])
"summary_points": [str],   # ordered by severity, plain English facts e.g. "Login form posts to an external domain (evil.xyz)"  (G19)
"coverage": {"network": bool, "checks_total": int, "checks_errored": int}
```
New checks (category in `lexical|domain|network|ssl|content|reputation|brand|email|behavior`), at least:
`private_network_host`, `dnsbl_listed`, `engine_ratio`, `outdated_software`, `malware_signature`, `seo_spam`,
`crypto_miner`, `hidden_iframe`, `parked_domain`, `popular_site` (pass, strong safe signal for top10k),
`no_spf`, `no_dmarc`, `ecommerce_no_contact`, `ecommerce_crypto_only`, `extreme_discounts`, `cloaking_detected`,
`download_executable`, `favicon_brand_mismatch` (favicon dhash matches a known brand's favicon hash list —
optional, bundled small list ok), `tracker_present` (info). The heuristic score must include them.
Brand-owned official domains + Tranco top-10k must not get flagged by weak signals (keep false positives low).

`dnsbl.py`: domain → Spamhaus DBL (`dbl.spamhaus.org`), SURBL (`multi.surbl.org`), URIBL (`multi.uribl.com`);
IP → Spamhaus ZEN (`zen.spamhaus.org`), SpamCop (`bl.spamcop.net`). Treat Spamhaus `127.255.255.x`,
URIBL/SURBL `127.0.0.1` as **error/refused** (public-resolver block), not "listed". Cache 1h.
Engines list = each local feed (OpenPhish, PhishTank, URLhaus, Phishing.Database, Phishing Army) + each DNSBL +
GSB/VT if keys + heuristic engines ("PhishGuard ML" is added by the API, not the engine).

`ct.py` (G24): `async def ct_search(domain: str, timeout_s=15) -> list[{"common_name","name_value","issuer","not_before","id"}]`
and `async def ct_lookalikes(domain: str, since_days: int = 30) -> list[...]` (crt.sh JSON `?q=%25{label}%25&output=json`,
then keep names whose registered label is a typosquat/combosquat of `domain`, exclude the domain itself). Cache, never raise.
`abuse.py`: RDAP via `https://rdap.org/domain/{d}` and `https://rdap.org/ip/{ip}`; never raise.
`popularity.py`: Tranco top-1M (reuse `backend/ml/data/raw/` copy if present, else download to `backend/data/tranco/`), lazy dict.
`browser.py`: `async def capture(url, settings) -> dict|None` (None if disabled or Playwright missing); saves PNG to
`backend/data/screenshots/`. If capture succeeded, `screenshot_url` = `/api/screenshots/<file>`; else v1 thum.io behaviour.

## 2. API additions (`app/main.py`, `db.py`, `scoring.py`, `routers/**`, `services/**`)
DB migration must be idempotent (`ALTER TABLE … ADD COLUMN` guarded by PRAGMA table_info). New indexed scan columns:
`ip, asn, registrar, ns, server, favicon_mmh3, favicon_dhash, threat_type, trust_score, tier, category, language,
parked, popularity_rank, trackers (comma-joined ids), visibility, share_token, tested_depth`.
New tables: `scan_dom(scan_id PK, html_gz BLOB, size, truncated)`, `api_keys`, `api_key_usage(key_id, day, count)`,
`voters(name PK, agree, disagree)`, `disputes`, `rules`, `rule_matches`, `ct_findings`.
`events` gains `entity_type`, `entity_id` columns (scan|domain|report|dispute|rule|watch|bulk|key|settings).

### Scoring additions (`scoring.py`)
- `trust_score = 100 - risk_score` (G15).
- `tier` (G16): `Trusted` [0,15) · `Favorable` [15,S) · `Neutral` [S, (S+P)/2) · `Questionable` [(S+P)/2, P) · `Untrusted` [P,100]
  where S/P = suspicious/phishing thresholds. `tested_depth: "full"|"lexical"` ("lexical" when deep=false or network checks disabled →
  UI shows "Untested (lexical only)").
- `threat_type` (G7): `malware` (URLhaus hit, executable download, malware/miner signature) > `social_engineering`
  (phishing feed hit, brand impersonation, login/password form on suspicious site, verdict phishing) > `unwanted_software`
  (parked, SEO spam, cloaking, ecommerce scam signals) > `none`.
- `factors` (G15): `{"positive": [{"id","name","detail"}], "negative": [{"id","name","detail","severity": "low|medium|high"}]}` from checks.
- Engine list: API appends `{"name":"PhishGuard ML","type":"heuristic","listed": verdict=="phishing", ...}` and recomputes `engine_ratio`.
- `summary` (G19): 2–4 plain sentences: verdict + risk + tier, ML probability, then the top `summary_points`.
- Blacklist/verified-report floors from v1 still apply. Popular top-10k + official brand domain + no feed hit → cap risk at 30.

### ScanResult additions
`trust_score, tier, tested_depth, threat_type, factors, summary, favicon, email_security, popularity, content, cloaking,
abuse, browser (without dom_html), visibility: "public"|"unlisted"|"private", share_token, has_dom: bool`
(+ all new engine keys pass through; `dom_html` is NOT included). ScanSummary adds `trust_score, tier, threat_type, category, visibility`.

### Endpoints
- G1 `GET /api/scans/{id}/dom` → `{"html": str, "size": int, "truncated": bool}` (404 if none).
- G2/[S] `GET /api/screenshots/{file}` → PNG (path-traversal safe).
- G3 `GET /api/scans/{id}/similar` → `{"same_favicon": [ScanSummary], "similar_favicon": [{"scan": ScanSummary, "distance": int}] (Hamming ≤ 6),
  "same_ip": [...], "same_asn": [...], "same_trackers": [...], "same_registrar": [...]}` (each ≤20, excluding same domain for similar_*).
- G4 `GET /api/graph?domain=&scan_id=&depth=1|2&limit=150` → `{"nodes": [{"id","type": "domain|url|ip|asn|ns|registrar|favicon|tracker|brand|redirect|country","label","risk": num|null,"verdict": str|null,"count": int}],
  "edges": [{"source","target","type": "resolves_to|in_asn|uses_ns|registered_with|has_favicon|has_tracker|impersonates|redirects_to|located_in|scanned_as"}]}`;
  without params → global graph of the most recent/high-risk 50 domains.
- G5 `GET /api/scans` new filters: `ip, asn, registrar, ns, server, favicon (mmh3), tracker, category, threat_type, tier, language, visibility`.
  Same filters on `/api/scans/export`.
- G6 engine ratio lives in ScanResult.reputation; `GET /api/analytics/engines?range=` → `[{"name","type","checked","flagged","hit_rate","agreement" (with final verdict)}]`.
- G15–G16 in scoring; G7 in scoring.
- G17 reviews: `POST /api/reports` accepts optional `rating` (1–5). `GET /api/reviews?domain=` → `{"domain","avg_rating","count","distribution": {"1":n,…,"5":n},"items":[Report]}`.
  Votes are weighted: `weight = clamp(1 + (agree - disagree)/10, 0.5, 3)` from `voters` (updated when a report becomes verified/rejected: voters who voted with the outcome +agree, else +disagree).
  Report gains `rating, weighted_score, voter_reputation` (avg of voter weights). Verification threshold uses weighted_score (≥3 verified, ≤−3 rejected).
  `GET /api/voters` → leaderboard `[{"name","agree","disagree","weight"}]`.
- G18 disputes: `POST /api/disputes {"scan_id","reason","contact"?}` → forces a fresh deep rescan; status `overturned` automatically if the new verdict is better
  (or risk dropped ≥15), else `open`. `GET /api/disputes?status=open|upheld|overturned` → `{"items","total"}`; `POST /api/disputes/{id}/resolve {"status":"upheld|overturned","note"}`.
  Dispute = `{id, scan_id, url, domain, reason, contact, status, original_risk, original_verdict, new_risk, new_verdict, rescan_id, created_at, resolved_at, note}`.
- G23 hunting rules: `GET/POST /api/rules`, `PUT/DELETE /api/rules/{id}`, `GET /api/rules/{id}/matches` → `[ScanSummary + matched_at]`.
  Rule = `{id, name, filters: {q?, verdict?, min_risk?, max_risk?, brand?, tld?, threat_type?, category?, ip?, asn?, registrar?, ns?, favicon?, tracker?, source?}, severity: "info|warning|critical", enabled, created_at, match_count, last_match_at}`.
  Every completed scan is evaluated against enabled rules; match → `rule_matches` row + alert type `rule_match`.
- G24 CT: watchlist items gain `monitor_ct: bool` (POST/GET). Background loop runs `ct_lookalikes` per CT-monitored domain every 24h (and on `POST /api/watchlist/{id}/ct/run`);
  new names → `ct_findings` + alert `ct_lookalike`. `GET /api/watchlist/{id}/ct` → `[{"name","issuer","not_before","first_seen","scanned_scan_id"}]`.
- G25 `GET /api/scans/{id}/abuse-report` → `{"to": [emails], "cc": [], "subject", "body", "mailto"}` (registrar + host abuse contacts, evidence: URL, IP, risk, verdict, threat type, top factors, timestamps, screenshot link, PhishGuard report link `http://localhost:5173/scans/{id}`).
- G27 API keys: `POST /api/keys {"name","rate_limit_per_min": 60}` → `{id,name,prefix,key (shown once),rate_limit_per_min,created_at}`; `GET /api/keys` (no full key; `requests, last_used, revoked`);
  `DELETE /api/keys/{id}` (revoke); `GET /api/keys/{id}/usage?range=` → `[{"t","count"}]`. Middleware: header `X-API-Key` → validate (sha256 hash compare), 401 if invalid/revoked,
  token-bucket per key → 429 + `Retry-After`; scans made with a key get `source="api"` and `api_key_id`. No key = dashboard (allowed).
- G28 rating aging: settings `auto_recheck_enabled` (default true), `auto_recheck_days` (default 7). Watcher loop every 10 min rescans ≤5 stale domains whose latest scan is
  suspicious/phishing and older than N days (`source="recheck"`); event + alert if verdict changed.
- G29 visibility: `PATCH /api/scans/{id}` accepts `visibility`. Private scans are excluded from `/api/stats/live`, Overview live feed and the global graph;
  `GET /api/share/{share_token}` → ScanResult for public/unlisted (404 for private).
- Tracking: `GET /api/scans/{id}/timeline` → events where (entity_type=scan & entity_id=id) or (entity_type=domain & entity_id=domain), newest first.
  `GET /api/events` gains `entity_type`, `entity_id`, `q` filters.
- Analytics additions:
  - `overview` adds `avg_trust_score, rule_matches, disputes_open, api_requests, ct_findings, rechecks`.
  - `distribution` adds `threat_types, tiers, categories, languages, asns, registrars, trackers, tld_risk: [{"name","value","avg_risk"}], engines_flagged: [{"name","value"}], parked, ecommerce_flags: [{"name","value"}], email_security: [{"name","value"}] (no_spf/no_dmarc/dnsbl), popularity: [{"name","value"}]`.
  - `GET /api/analytics/funnel?range=` → `[{"stage","count"}]` stages: Scanned → Reachable → Has login/password form → Brand impersonation → Feed/DNSBL listed → Phishing verdict.
  - `GET /api/analytics/brands?range=` → `[{"brand","count","avg_risk","phishing","techniques": {..},"first_seen","last_seen"}]`.
  - `GET /api/analytics/usage?range=` → `{"by_source": [{"name","value"}], "by_api_key": [{"name","value"}], "timeseries": [{"t","dashboard","api","bulk","watch","extension","recheck"}]}`.
- Settings additions: `enable_browser_capture` (false), `enable_cloaking_check` (true), `enable_dnsbl` (true), `enable_rdap` (true), `auto_recheck_enabled` (true), `auto_recheck_days` (7).
- Seed: re-seed demo data **with network checks enabled** (concurrency 6) so the new fields are populated; keep `POST /api/admin/reset` + `/seed`.
  Also seed 2 hunting rules, 1 API key (named "demo"), a few reviews with ratings, 2 disputes, CT monitoring on one watch item.

## 3. Frontend additions
`src/api/client_v2.ts` (FE-Contract): TS types + fetch functions for every v2 field & endpoint above (re-export v1 types it extends).
`src/components/ForceGraph.tsx` (FE-Pages; FE-Contract writes a typed stub first): `export default function ForceGraph(props: {nodes: GraphNode[]; edges: GraphEdge[]; height?: number; onNodeClick?: (n: GraphNode) => void})`
— dependency-free SVG force simulation (or `d3-force` npm), zoom/pan, node colour by type and risk, legend, hover tooltip.

**FE-Report** (`/scans/:id`): header gains Trust score, Tier chip (+ "Untested (lexical only)"), Threat-type badge, engine ratio "N/M engines";
Summary tab gains AI summary paragraph + Positive/Negative factor lists; new tabs **Engines** (per-engine table, DNSBLs), **Content**
(category bars, language + Translate link, parked, ecommerce signals, outdated software table, malware/SEO signatures), **Resources**
(contacted domains, resources table, trackers with pivot links, downloads with sha256), **Source** (DOM viewer: line numbers, search, wrap toggle, copy, lazy-loaded from `/dom`),
**Email** (MX/SPF/DMARC/DNSBL card), **Favicon & Similar** (favicon image, mmh3, dhash, similar scans lists), **Cloaking** (variants comparison),
**Browser** (network requests table, console, cookies — only if `browser` present), **Graph** (ForceGraph for this scan's domain, depth 2),
**Timeline** (entity events). Every pivot value (IP, ASN, registrar, NS, server, favicon hash, tracker id, category) is a link to `/history?<field>=<value>`.
Actions: Dispute (modal), Abuse report (modal with To/Subject/Body, copy + mailto), Visibility selector, share link uses `share_token`.

**FE-Pages**: new pages **Graph** `/graph` (search domain, depth, global view), **Hunting Rules** `/rules` (CRUD, matches drawer),
**Disputes** `/disputes`, **API Keys** `/api-keys` (create → show key once, revoke, usage chart); Community gets star ratings
(submit + display), reviews per domain, voter leaderboard; History gets an advanced pivot filter panel synced with URL query params
(all v2 filters, chips, clear); Watchlist gets `monitor_ct` toggle + CT findings drawer + "Run CT now"; Analytics gets: threat types,
tiers, categories, languages, engines hit-rate/agreement table, funnel chart, brands table, ASNs, registrars, trackers, TLD avg-risk,
email-security, popularity, usage by source & API key (stacked timeseries); Overview adds avg trust score, rule matches, open disputes, API requests KPIs;
Settings gets the new toggles (browser capture with a security warning) and auto-recheck options; sidebar entries for the new pages.
Extension (`extension/**`): show trust score, tier and threat type in the popup.
