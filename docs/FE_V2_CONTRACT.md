# FE v2 contract (written by FE-Contract for FE-Report and FE-Pages)

Files:
- `frontend/src/api/client.ts`: v1 client, corrected to match the real backend. FE-Pages owns it from now on; keep the exports stable.
- `frontend/src/api/client_v2.ts`: v2 types and fetchers. **Read-only for both FE agents.** It re-exports everything from `client.ts`, so `import { api, apiV2, qk, type ScanResultV2 } from '../api/client_v2'` covers v1 and v2.
- `frontend/src/components/ForceGraph.tsx`: typed stub with the signature `export default function ForceGraph(props: { nodes: GraphNode[]; edges: GraphEdge[]; height?: number; onNodeClick?: (n: GraphNode) => void })`. FE-Pages replaces the body and keeps the signature.
- `frontend/vite.config.ts`: the dev and preview proxy target comes from `PHISHGUARD_API` (default `http://localhost:8000`) for `/api`, `/docs`, `/redoc`, `/openapi.json`, `/static` and `/screenshots`.

Where the v2 shapes come from: `docs/SPEC_V2.md` §1–2, cross-checked against the v2 backend services that had landed when this was written (`scoring.finalize`, `scanner.row_to_result/row_to_summary`, `disputes`, `rules`, `apikeys`, `community`, `events`, `filters`, `settings_service`). The v2 routers and the analytics service were not written yet. **Every v2 field is optional**, because scans stored under v1 don't have these fields (the backend backfills most of them).

---

## 1. How to call things

- **Fetchers.** `apiV2.<name>(...)` returns a `Promise`. Use it in `useQuery({ queryKey: qk.<name>(...), queryFn: () => apiV2.<name>(...) })`. v1 `api.*` still works and hits the same endpoints. Use `apiV2` when you want the v2 types.
- **Errors.** Every failure throws `ApiError` (`status`, `message` taken from the FastAPI `detail`, raw `body`). Status `0` means the backend can't be reached. `main.tsx` already turns off retries for 4xx.
  - `apiV2.dom(id)` resolves to **`null` on 404** (the scan has no DOM snapshot).
  - API-key 429 errors: `retryAfterOf(err)` returns the number of seconds.
- **Lists.** For endpoints where the spec leaves the wrapper open (rules, voters, keys, key usage, CT findings, rule matches, timeline, engines/funnel/brands, watchlist, alerts), the fetcher normalises with `asList` and **always resolves to an array**. `disputes()` resolves to `{items, total, page?, page_size?, counts}`. Paginated v1 lists (`scans`, `reports`, `events`) are `Paged<T>` = `{items, total, page, page_size}`; `events` also has `types`.
- **Ids.** Ids are integers in responses. Fetchers accept `Id = number | string`, so route params can be passed straight through. Path segments are encoded with `enc()`.
- **Query strings.** Use `qs(obj)` from `client.ts`. It skips `undefined`, `null`, `''` and empty arrays, joins arrays with commas (the backend accepts comma lists for verdict, source, tld, threat_type, category, language, visibility, tier, ip, tracker and event `type`), and accepts any object, so no casts are needed.
- **Base helpers.** `request(method, '/api/...', body?, init?)` and `http.{get,post,put,patch,del}(pathAfterApi, queryOrBody)`. `init.headers` is merged into the defaults, so extra headers such as `X-API-Key` don't replace them.
- **Enums.** Server enums use `Loose<T>`: the known literals plus any other string. You get autocomplete, but you can't index a `Record<Tier, …>` until you narrow the value. Narrow with `tierOf`, `threatTypeOf`, `visibilityOf`, `isTier`, `isThreatType` or `isVisibility`.
- **Percentages.** `fmtPct(v, digits, isRatio)` guesses whether a value is a ratio when `v <= 1`, so **pass `isRatio` explicitly**:
  - 0–100 percentages: `Overview.detection_rate` and `delta.*` (pass `false`).
  - 0–1 ratios: `confidence`, `ml.probability_phishing`, model metrics, `live.agreement_rate`, `check_error_rates[].rate`, `brand.similarity`, `cloaking.similarity`, `category_confidence`, `Voter.accuracy` (pass `true`).
  - The spec doesn't say whether `EngineStat.hit_rate` and `.agreement` are 0–1 or 0–100. Check the backend before choosing.
- **Pivots.** `pivotHref('ip', '1.2.3.4')` returns `/history?ip=1.2.3.4`. History reads `PIVOT_FIELDS` keys from the URL search params, and `apiV2.scans` / `apiV2.exportUrl` accept them as `ScanFiltersV2`.
- **Share links.** `shareLink(scan.share_token)` builds `<origin>/share/<token>`. **FE-Pages must register the route `share/:token`.** It renders a read-only report from `apiV2.share(token)`, which returns ApiError 404 for private or unknown tokens. `shareApiPath(token)` gives the API path.
- **Screenshots.** `screenshotSrc(scan)` returns the browser-capture PNG (`/api/screenshots/<file>`), then the v1 `screenshot_url`, then `null`.

### Query keys (`qk`)
- Keys are always `[resource, ...params]` with **string ids**. Sub-resources nest under their parent (`qk.scanDom(id) = ['scan', id, 'dom']`), so `invalidateQueries({ queryKey: qk.scan(id) })` also refreshes the dom, similar, timeline and abuse queries. Prefix invalidation works: `['rules']`, `['api-keys']`, `['disputes']`, `['reports']`, `['events']`, `['analytics']`, `['alerts']`.
- Keys for endpoints that v1 already uses match the v1 pages: `['scan', id]`, `['scans', f]`, `['domain', d]`, `['overview', r]`, `['distribution', r]`, `['timeseries', r, bucket]`, `['performance', r]`, `['settings']`, `['live']`, `['health']`, `['model']`, `['watchlist']`, `['bulk']`. This lets v1 and v2 fetchers share one cache entry.
- Migration caveat: v1 Watchlist uses `['watch-history', <number id>]`, but `qk.watchHistory` uses a string id. When you migrate a page, switch every key for that resource to `qk.*` at the same time.
- New keys: `scanSimilar`, `scanTimeline`, `scanAbuse`, `compare`, `share`, `graph(p)`, `engines/funnel/brands/usage(r)` (under `['analytics', …]`), `reports(status, page, extra)`, `reviews(d)`, `voters`, `disputes(status)`, `rules`, `ruleMatches(id)`, `watchHistory(id)`, `watchCt(id)`, `keys`, `keyUsage(id, r)`, `events(f)`, `alerts(...parts)`, `bulk(id?)`.

### Utilities to reuse (don't duplicate)
- `lib/format.ts`:
  - Numbers and time: `fmtNum`, `fmtCompact`, `fmtPct` (pass `isRatio`), `fmtMs`, `fmtDate`, `fmtRel`, `fmtTick`, `parseDate` (treats naive timestamps as UTC).
  - Text: `truncate`, `titleCase`, `hostOf`, `flagEmoji`.
  - Browser actions: `downloadBlob`, `copyText`, `safeGet`, `safeSet`.
  - Colour and verdicts: `cx`, `riskColor(score, sus, phish)`, `VERDICTS`, `VERDICT_COLOR`, `VERDICT_LABEL`, `PALETTE`, `ACCENT`, `isVerdict`.
- `lib/hooks.ts`: `useDebounced`, `useRange(key)` (the range is persisted), `bucketFor(range)`. `lib/theme.ts`: `useTheme`.
- Components:
  - Layout: `Card`, `CardHeader`, `PageHeader`, `KV`.
  - Charts: `ChartCard` (handles loading, error and empty states), `ChartTooltip`, `Legend`.
  - Tables: `DataTable`, `Pagination`.
  - Metrics: `Kpi`, `Sparkline`, `RiskGauge`, `Meter`.
  - Overlays and navigation: `Modal`, `Drawer`, `RangeSelect`, `Segmented`, `Tabs`, `useToast`.
  - States: `Skeleton`, `SkeletonRows`, `EmptyState`.
  - Status: `StatusIcon`, `BoolIcon`, `VerdictBadge`, `RiskPill`.
  - Form controls (`ui.tsx`): `Button`, `Input`, `Textarea`, `Select`, `Field`, `Toggle`, `Chip` (tones zinc, indigo, emerald, amber, rose = `Tone`), `ProgressBar`, `ErrorBox`.

---

## 2. `client_v2.ts` exports

**Fetchers (`apiV2`)**

| Group | Fetchers |
|---|---|
| Scans | `scan(url, deep, source, {visibility?})`, `scanWithKey(url, key, deep)` (sends `X-API-Key`; 401/429), `getScan`, `scans(ScanFiltersV2)`, `rescan(id, deep)` (returns a NEW scan), `patchScan(id, {tags, notes, visibility})`, `setVisibility`, `deleteScan`, `compare`, `exportUrl(fmt, filters)` |
| Per-scan | `dom(id)` (DomSnapshot or null), `similar`, `timeline` (EventItemV2[]), `abuseReport`, `share(token)`, `domain`, `live`, `bulkJob` |
| Graph | `graph({domain?, scan_id?, depth?, limit?})` (always `{nodes: [], edges: []}` arrays; no params = global graph) |
| Community | `createReport({…, rating})`, `reports(status, page, {q, page_size})`, `report(id)`, `vote`, `reviews(domain?)`, `voters()` |
| Disputes | `createDispute({scan_id, reason, contact?})` (waits for the forced rescan), `disputes(status?, {scan_id, q, page, page_size})` returns `DisputeList`, `resolveDispute(id, {status: upheld or overturned, note})` |
| Rules | `rules`, `createRule(RuleInput)`, `updateRule(id, …)` (PUT; send the full rule), `deleteRule`, `ruleMatches(id)` |
| Watchlist / CT | `watchAdd({…, monitor_ct})`, `watchlist`, `watchRun`, `watchDelete`, `watchHistory`, `ctFindings(id)`, `ctRun(id)` |
| API keys | `keys`, `createKey({name, rate_limit_per_min})` (`key` is shown once), `revokeKey`, `keyUsage(id, range)` |
| Events / alerts | `events({type, q, entity_type, entity_id, page, page_size})`, `alerts(unread?, {severity, limit})` (AlertV2 with `rule_id`/`dispute_id`) |
| Analytics | `overview`, `distribution`, `engines`, `funnel`, `brands`, `usage` (all `(range = '30d')`) |
| Settings | `settings`, `saveSettings(Partial<SettingsV2>)` |

**Scan types**

| Name | Purpose |
|---|---|
| `ScanResultV2` | ScanResult plus everything v2: `trust_score`, `tier`, `tested_depth`, `threat_type`, `threat_reasons`, `factors`, `summary`, `summary_points`, `favicon`, `email_security`, `popularity`, `content`, `cloaking`, `abuse`, `browser`, `visibility`, `share_token`, `has_dom`, `coverage`, `api_key_id`, `score_cap`, `dispute` (the latest one), plus `http: HttpInfoV2` and `reputation: ReputationV2` |
| `ScanSummaryV2` | History row plus `trust_score`, `tier`, `threat_type`, `category`, `visibility` |
| `HttpInfoV2` (+ `HttpResource`, `ContactedDomain`, `Tracker`, `DownloadInfo`, `DownloadLink`) | `http.resources`, `contacted_domains`, `trackers`, `download`, `download_links` |
| `ReputationV2`, `Engine`, `EngineRatio`, `CommunityInfoV2` | Per-engine results, "N/M engines", and weighted community stats |
| `FaviconInfo`, `EmailSecurity`, `Popularity`, `ContentInfo` (+ `CategoryScore`, `ParkedInfo`, `EcommerceSignals`, `ContentSignature`, `SoftwareVersion`), `CloakingInfo`/`CloakingVariant`, `AbuseContacts`, `BrowserCapture` (+ request/console/cookie), `Coverage`, `Factors`/`PositiveFactor`/`NegativeFactor` | The v2 sub-objects |
| `ScanFiltersV2`, `PivotField`, `ScanPatchV2`, `ScanSortV2` | Pivot filters (ip, asn, registrar, ns, server, favicon, tracker, category, threat_type, tier, language, visibility, parked, api_key_id), the patch body, and the extra sort keys |
| `DomSnapshot`, `SimilarScans`, `AbuseReport` | Responses of `/dom`, `/similar` and `/abuse-report` |
| `DomainDetailV2`, `CompareResultV2`, `LiveStatsV2`, `BulkJobDetailV2` | v1 responses with v2 summaries and results |

**Other types**

| Name | Purpose |
|---|---|
| `GraphNode`, `GraphEdge`, `GraphData`, `GraphParams`, `GraphNodeType`, `GraphEdgeType` | Relationship graph. Node ids are strings. Copy edges before giving them to a simulation that mutates them |
| `OverviewV2`, `DistributionV2`, `TldRisk`, `EngineStat`, `FunnelStage`, `BrandStat`, `UsageStats`, `UsagePoint`, `CountPoint` | Analytics additions |
| `ReportV2`, `ReportCreateV2`, `ReviewsSummary`, `Voter` | Ratings, weighted votes, reviews and the leaderboard |
| `Dispute`, `DisputeInput`, `DisputeResolve`, `DisputeStatus`, `DisputeList`, `ListResult` | Disputes |
| `Rule`, `RuleFilters`, `RuleInput`, `RuleMatch` | Hunting rules. Filters use the same keys as ScanFiltersV2, minus dates; unknown keys get a 422 |
| `WatchItemV2`, `WatchAddV2`, `WatchHistoryV2`, `CtFinding`, `CtRunResult` | Certificate-transparency monitoring |
| `ApiKey`, `ApiKeyCreated` | API keys |
| `EventItemV2`, `EventsPageV2`, `EventFilters`, `EntityType`, `AlertV2` | Activity log with entity fields, and alerts |
| `SettingsV2`, `SettingsV2Flags` | v2 settings |
| `Tier`, `TestedDepth`, `ThreatType`, `Visibility`, `ImpactLevel`, `ContentCategory`, `CheckCategoryV2`, `StoredScanSourceV2`, `EngineType`, `EngineCategory`, `ResourceType`, `TrackerType`, `PopularityTier`, `Tone`, `Loose<T>` | Enum types |

**Constants**

| Name | Purpose |
|---|---|
| `SETTINGS_V2_DEFAULTS` | Spec defaults: browser capture off; cloaking, DNSBL and RDAP on; auto-recheck on, 7 days |
| `TIERS`, `TIER_TONE`, `UNTESTED_LABEL` | Ordered tiers, the Chip tone for each tier, and "Untested (lexical only)" |
| `THREAT_TYPES`, `THREAT_TYPE_LABEL`, `THREAT_TYPE_TONE` | Threat-type badge text and tone |
| `VISIBILITIES`, `CONTENT_CATEGORIES`, `SCAN_SOURCES_V2` (adds `community`, `recheck`, `dispute`), `DISPUTE_STATUSES`, `ENTITY_TYPES` | Option lists for selects and filters |
| `PIVOT_FIELDS` | `{key, label, placeholder}` for each v2 pivot filter, for the History panel |

**Helpers**

| Name | Purpose |
|---|---|
| `tierFor(risk, sus, phish)`, `tierOf(scan)`, `trustScoreOf(scan)`, `threatTypeOf`, `visibilityOf`, `isLexicalOnly(scan)` | Narrowed values, with fallbacks for v1 scans |
| `engineRatioOf(scan)` | Uses `engine_ratio`, then the engines list, then the v1 sources (errored lookups are excluded) |
| `screenshotUrl(file)`, `screenshotSrc(scan)`, `pivotHref(field, value)`, `shareLink(token)`, `shareApiPath(token)` | URL builders |
| `nameValues(v, fallbackName)` | Normalises any chart-ish shape (array of objects, tuples, map or a bare number) to `NameValue[]` |
| `asPaged(v)` | Normalises `T[]` or `{items, total}` |
| `retryAfterOf(err)` | Seconds to wait after a 429 |
| `isTier`, `isThreatType`, `isVisibility` | Type guards |
| `qk` | Query keys (see §1) |

**Additions to `client.ts` that v2 relies on:** `request`, `http`, `qs` (arrays and objects), `enc`, `Id`, `Query`, `QueryValue`, `ScanSort`, `StoredScanSource`, `AlertSeverity`, `ReportStatus`, `CommunityStatus`, `CommunityInfo`, `SuspiciousJs`, `MetaRefresh`, `RedirectHop`, `TyposquatHit`, `BulkItem`, `BulkJobDetail`, `BulkCreated`, `BulkStatus`, `BulkVerdictCounts`, `WatchCheck`, `FeedStats`, `FeedsRefreshResult`, `FeedSearchResult`, `EventsPage`, `DeleteResult`, `SeedStatus`, `AdminSeedResult`.

---

## 3. v1 fixes made (backend code was treated as the truth)

**Changes in `client.ts`**
- Ids: every id is `number` (scan, summary, report, report `scan_id`, watch item, alert `scan_id`/`watch_id`, bulk job, event). Fetchers take `Id`.
- Wrappers and return types:
  - `feedsSearch` returns `{items, total, q}` (it is not an array) and gained a `limit` parameter.
  - `feeds()` has `refreshing`.
  - `feedsRefresh` returns `{status: "ok" | "running" | "error: …", feeds, stats}` with HTTP 200 even when it fails.
  - `watchRun` returns the updated `WatchItem`. `watchHistory` returns `{item, checks, typosquats}`.
  - `bulkJob` returns `BulkJobDetail` (`results` plus per-URL `items` with `status` and `error`). Jobs have `progress` (0–1), `finished_at`, and `verdict_counts.error`. `bulkCreate` and `bulkUpload` return `{job_id, total?, truncated?}`.
  - `alertRead` returns an `Alert`; `alertsReadAll` returns `{updated}`; `deleteScan` and `watchDelete` return `{deleted, id}`.
  - `Paged<T>` always has `page` and `page_size`.
  - `events()` returns `EventsPage`, which includes `types`.
- Field shapes:
  - `domain_info.punycode` is the decoded Unicode string or null, not a boolean.
  - `http.suspicious_js` is `{id, description}[]`, not `string[]`.
  - `http.meta_refresh` is `{content, target, external}` or null, not a boolean.
  - `reputation.community.status` is one of `none`, `pending`, `verified`, `rejected`.
  - `reputation.sources[]` gained `match` and `error` (plus VirusTotal counts).
  - `score_breakdown[]` gained `contribution` and `note`.
  - `ScanResult` gained `heuristic_score` and `network_checks`.
  - `brand.details` is a string, and brand gained `official_domain`, `matched_keyword` and `defensive_redirect`.
  - `geo.asn` is a string like `"AS15169"`, and geo gained `as_name` and `private`.
  - `feeds.stats.*` lists are `NameValue[]`; stats also has `top_registered_domains`, `unique_hosts`, `computed_at` and `targets_estimated`.
  - `Overview.detection_rate` is documented as 0–100; `delta` follows the v1 rules.
  - `TimePoint.avg_risk` is 0 (not null) for empty buckets.
  - `Performance` gained `count`, `avg_ms` and `range`; `check_error_rates` rows gained `errors` and `total`.
  - `ModelInfo.live` gained `feedback_samples` and `verdicts`; dataset and model rows gained their extra fields.
  - `Health` gained `seeding`. `LiveStats` gained `unread_alerts` and `server_time`.
  - `WatchItem` gained `last_scan_id` and `known_typosquats` (a count). Typosquat hits gained `mx`.
  - `DomainDetail.risk_trend[]` gained `scan_id`.
  - Extra fields that are now typed: whois (`registration_length_days`, `name_servers`, `org`, `found`, `error`), DNS (`cname`, `spf`, `dmarc`, `resolves`), SSL (`issuer_org`, `issuer_cn`, `subject_org`, `serial`, `validity_days`, `free_cert`, `cipher`), HTTP (`content_type`, `headers`, `hidden_iframes`, `cross_domain_redirects`, `favicon_url`, `urgency_phrases`, `text_length`, `forms.password_to_external`, `forms.sensitive_inputs`, `links.null_ratio`, `links.total`), and feed metadata (`homepage`, `kind`, `last_attempt`, `error`).
- Parameters the backend supports that were missing:
  - `scans` and `exportUrl` gained `tag`, `domain` and `blacklisted`. `verdict`, `source` and `tld` accept arrays or comma lists. Sort keys are now `created_at | risk_score | domain | duration_ms | confidence`. `exportUrl` drops any sort the export endpoint rejects.
  - `rescan(id, deep)`, `reports(status, page, {q, page_size})`, `report(id)`, `alerts(unread, {severity, limit})`, `typosquat(domain, limit)`, `events(type, page, page_size, q)`.
  - Admin calls: `adminSeed(force, deep)`, `adminSeedStatus()`, `adminReset(reseed, deep)`.
- Helpers: `request` and `http` are exported so `client_v2` can reuse them. `qs` handles arrays and objects without casts. Extra request headers are merged instead of replacing the defaults.

**Page fixes (kept minimal)**
- `pages/report/Sections.tsx`:
  - The HTTP tab crashed React whenever `suspicious_js` was non-empty, because it rendered objects. It now renders the descriptions.
  - Meta refresh shows Yes, External or No.
  - Punycode shows the decoded hostname.
  - Community status `none` now reads "Not reported".
  - A source whose lookup errored shows "Lookup failed" instead of "Not listed".
- `pages/Overview.tsx`: detection rate is 0–100, but `fmtPct` treated values ≤ 1 as ratios (1.0 was shown as 100%). It now passes `isRatio=false`. `agreement_rate` now passes `isRatio=true` explicitly.
- `pages/Activity.tsx`: the type filter now comes from the API's `types`. The old hard-coded `watch` and `settings` never matched the real types (`watch_add`, `watch_run`, `settings_update`, …).
- `pages/Report.tsx`: voting looked for an existing report with `r.url === scan.url`, but reports store the normalized URL, and it only searched page 1. Every vote therefore created a duplicate report. It now matches `url` or `normalized_url` and searches by domain with `page_size=200`.
- `pages/Analytics.tsx`: the average-risk line now treats empty buckets as gaps (the backend sends 0).
- `pages/Feeds.tsx`: the refresh toast now reflects the returned `status` (`ok`, `running` or `error`) instead of always reporting success.
- `pages/History.tsx`: added the `community` source option. FE-Pages should switch this list to `SCAN_SOURCES_V2`.

## 4. Open points to verify once the v2 routers land
- Whether `GET /api/rules`, `/keys`, `/voters`, `/watchlist/{id}/ct`, `/scans/{id}/timeline` and the analytics engines, funnel and brands endpoints return arrays or `{items}`. The fetchers handle both.
- `POST /api/watchlist/{id}/ct/run` has no fixed response shape (`CtRunResult` is typed loosely). Refetch `ctFindings` after calling it.
- `distribution.parked` has no specified shape; use `nameValues(d.parked, 'parked')`.
- Whether `EngineStat.hit_rate` and `.agreement` are ratios or percentages.
- The spec has no endpoint for updating `monitor_ct` on an existing watch item; it can only be set on create.
- `POST /api/scan` may not accept `visibility`; `apiV2.scan` only sends it when it is given. Use `setVisibility` after the scan as the reliable path.
