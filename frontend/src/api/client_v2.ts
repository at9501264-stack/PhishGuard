// PhishGuard v2 API contract (docs/SPEC_V2.md §1-2) - written by FE-Contract.
// READ-ONLY for FE-Report and FE-Pages. See docs/FE_V2_CONTRACT.md for conventions.
//
// - Re-exports everything from ./client, so pages can import v1 + v2 symbols from this one module.
// - v2 types extend the v1 ones (`ScanResultV2 extends ScanResult`, ...); every v2 field is optional/nullable
//   because scans stored before the v2 backend (and partially-implemented endpoints) will not have them.
// - Fetchers reuse client.ts's `request`/`http` helpers and `qs` query builder; errors are `ApiError`.
// - List endpoints whose wrapper the spec leaves open are normalised with `asList` and ALWAYS resolve to arrays.

import {
  ApiError,
  api,
  asList,
  enc,
  http,
  qs,
  request,
  type Alert,
  type AlertSeverity,
  type BulkJobDetail,
  type CheckCategory,
  type CommunityInfo,
  type CompareResult,
  type DeleteResult,
  type Distribution,
  type DomainDetail,
  type EventItem,
  type HttpInfo,
  type Id,
  type LiveStats,
  type NameValue,
  type Overview,
  type Paged,
  type Range,
  type Report,
  type ReportStatus,
  type Reputation,
  type ScanFilters,
  type ScanResult,
  type ScanSort,
  type ScanSource,
  type ScanSummary,
  type Settings,
  type StoredScanSource,
  type Verdict,
  type WatchHistory,
  type WatchItem,
} from './client'

export * from './client'

const { get, post, put, patch, del } = http

// =============================================================================================== enums

/** Known literal values plus "any other string" (keeps autocomplete; forces a guard before indexing a Record). */
export type Loose<T extends string> = T | (string & {})

/** v1 categories + `email` (SPF/DMARC/DNSBL) + `behavior` (cloaking, downloads, trackers...). */
export type CheckCategoryV2 = CheckCategory | 'email' | 'behavior'

/** Reputation tier (G16): Trusted [0,15) · Favorable [15,S) · Neutral [S,(S+P)/2) · Questionable [(S+P)/2,P) · Untrusted [P,100]. */
export type Tier = 'Trusted' | 'Favorable' | 'Neutral' | 'Questionable' | 'Untrusted'

/** "lexical" = deep=false or network checks disabled -> UI shows `UNTESTED_LABEL` next to the tier. */
export type TestedDepth = 'full' | 'lexical'

/** GSB-style threat type (G7). Priority: malware > social_engineering > unwanted_software > none. */
export type ThreatType = 'malware' | 'social_engineering' | 'unwanted_software' | 'none'

/** Scan visibility (G29). Private scans are hidden from the live feed, Overview feed and global graph; share links 404. */
export type Visibility = 'public' | 'unlisted' | 'private'

/** Severity of negative factors and content signatures. */
export type ImpactLevel = 'low' | 'medium' | 'high'

/** Content category (G10). */
export type ContentCategory =
  | 'banking'
  | 'payment'
  | 'shopping'
  | 'crypto'
  | 'social'
  | 'email'
  | 'cloud_storage'
  | 'government'
  | 'education'
  | 'news'
  | 'technology'
  | 'entertainment'
  | 'adult'
  | 'gambling'
  | 'parked'
  | 'login'
  | 'other'

/** Stored scan sources incl. v2 `recheck` (G28 auto re-check) and `dispute` (forced rescan of a dispute, G18). */
export type StoredScanSourceV2 = StoredScanSource | 'recheck' | 'dispute' | 'seed'

/** Extra sort keys accepted by GET /api/scans in v2 (export still only supports created_at | risk_score). */
export type ScanSortV2 = ScanSort | 'trust_score' | 'popularity_rank'

/** Matches the `tone` prop of <Chip> in components/ui.tsx. */
export type Tone = 'zinc' | 'indigo' | 'emerald' | 'amber' | 'rose'

// ========================================================================================== scan parts

/** Trust factors (G15), derived from checks (+ "ml_probability", "engine_ratio", "popular_or_official"). */
export interface PositiveFactor {
  id: string
  name: string
  detail?: string | null
  /** check category, or "ml" */
  category?: string | null
  weight?: number | null
}
export interface NegativeFactor extends PositiveFactor {
  severity?: Loose<ImpactLevel> | null
}
export interface Factors {
  positive?: PositiveFactor[] | null
  negative?: NegativeFactor[] | null
}

export type ResourceType = 'script' | 'stylesheet' | 'image' | 'iframe' | 'form' | 'link' | 'media' | 'other'

/** One page resource (G2), max 200 per scan. */
export interface HttpResource {
  url: string
  domain?: string | null
  type?: Loose<ResourceType> | null
  third_party?: boolean | null
}

/** Domain contacted by the page (G2). */
export interface ContactedDomain {
  domain: string
  count?: number | null
  third_party?: boolean | null
}

export type TrackerType = 'google_analytics' | 'gtag' | 'gtm' | 'facebook_pixel' | 'adsense' | 'hotjar' | 'other'

/** Tracker id found in the page (G22) - pivot with `tracker=<id>`. */
export interface Tracker {
  type?: Loose<TrackerType> | null
  id: string
}

/** Download / payload detection (G21). Hashed in a streaming way, never written to disk. */
export interface DownloadInfo {
  detected?: boolean | null
  filename?: string | null
  content_type?: string | null
  /** bytes */
  size?: number | null
  sha256?: string | null
  source?: Loose<'final_response' | 'link'> | null
}

export interface DownloadLink {
  url: string
  ext?: string | null
}

/** `http` with the v2 additions. */
export interface HttpInfoV2 extends HttpInfo {
  resources?: HttpResource[] | null
  contacted_domains?: ContactedDomain[] | null
  trackers?: Tracker[] | null
  download?: DownloadInfo | null
  download_links?: DownloadLink[] | null
}

/** Favicon fingerprint (G3). Pivot with `favicon=<mmh3>`; similar = dHash Hamming distance <= 6. */
export interface FaviconInfo {
  url?: string | null
  /** Shodan-style MurmurHash3 (signed int) */
  mmh3?: number | null
  /** 16-hex perceptual hash */
  dhash?: string | null
  /** bytes */
  size?: number | null
  error?: string | null
}

export type EngineType = 'feed' | 'dnsbl' | 'api' | 'heuristic'
export type EngineCategory = 'phishing' | 'malware' | 'spam' | 'suspicious' | 'clean' | 'error'

/** One reputation "engine" (G6): local feeds, DNSBLs, GSB/VT (with keys), heuristics, "PhishGuard ML". */
export interface Engine {
  name: string
  type?: Loose<EngineType> | null
  /** null = no definite answer (error/refused) - excluded from engine_ratio.total */
  listed?: boolean | null
  detail?: string | null
  category?: Loose<EngineCategory> | null
}

/** "N/M engines": total = engines with a definite answer (listed !== null). */
export interface EngineRatio {
  flagged: number
  total: number
}

/** Community aggregate with the weighted-vote / rating additions (G17). */
export interface CommunityInfoV2 extends CommunityInfo {
  weighted_score?: number | null
  avg_rating?: number | null
  /** number of reports carrying a rating */
  ratings?: number | null
}

export interface ReputationV2 extends Reputation {
  community?: CommunityInfoV2 | null
  /** includes the API-added "PhishGuard ML" heuristic engine */
  engines?: Engine[] | null
  engine_ratio?: EngineRatio | null
}

/** Email-security posture (G12). */
export interface EmailSecurity {
  mx?: boolean | null
  mx_hosts?: string[] | null
  spf?: boolean | null
  spf_record?: string | null
  dmarc?: boolean | null
  dmarc_policy?: Loose<'none' | 'quarantine' | 'reject'> | null
  /** site IP listed on Spamhaus ZEN / SpamCop; null = not checked / refused */
  ip_dnsbl_listed?: boolean | null
  /** 0-100, higher = better */
  score?: number | null
}

export type PopularityTier = 'top1k' | 'top10k' | 'top100k' | 'top1m'

/** Tranco popularity (G13). */
export interface Popularity {
  rank?: number | null
  tier?: Loose<PopularityTier> | null
  /** "Tranco" */
  source?: string | null
}

export interface CategoryScore {
  name: Loose<ContentCategory>
  /** 0-1 */
  score: number
}

/** Parked-domain detection (G11). */
export interface ParkedInfo {
  parked?: boolean | null
  reason?: string | null
}

/** E-commerce scam signals (G14). */
export interface EcommerceSignals {
  is_shop?: boolean | null
  payment_methods?: string[] | null
  crypto_only?: boolean | null
  has_contact?: boolean | null
  has_refund_policy?: boolean | null
  has_address?: boolean | null
  extreme_discounts?: boolean | null
  social_links?: number | null
}

/** Malware / SEO-spam / miner signature hit (G9). */
export interface ContentSignature {
  id: string
  name?: string | null
  severity?: Loose<ImpactLevel> | null
  /** matched snippet */
  match?: string | null
}

/** Detected software version vs bundled latest list (G8). */
export interface SoftwareVersion {
  name: string
  version?: string | null
  latest?: string | null
  outdated?: boolean | null
  /** where the version was read from (generator meta, X-Powered-By, ?ver= ...) */
  source?: string | null
}

/** Page content analysis (G8-G11, G14, G19). */
export interface ContentInfo {
  /** ISO 639-1, e.g. "en" */
  language?: string | null
  language_name?: string | null
  /** Google Translate link for the page */
  translate_url?: string | null
  category?: Loose<ContentCategory> | null
  /** 0-1 */
  category_confidence?: number | null
  categories?: CategoryScore[] | null
  parked?: ParkedInfo | null
  ecommerce?: EcommerceSignals | null
  signatures?: ContentSignature[] | null
  software?: SoftwareVersion[] | null
  word_count?: number | null
  text_excerpt?: string | null
}

/** One user-agent fetch used for cloaking comparison (G20). */
export interface CloakingVariant {
  agent: Loose<'desktop' | 'mobile' | 'googlebot'>
  status?: number | null
  final_url?: string | null
  title?: string | null
  /** response length (bytes) */
  length?: number | null
  /** content hash */
  hash?: string | null
}

export interface CloakingInfo {
  checked?: boolean | null
  detected?: boolean | null
  /** 0-1 similarity between variants */
  similarity?: number | null
  variants?: CloakingVariant[] | null
  detail?: string | null
}

/** RDAP abuse contacts (G25). */
export interface AbuseContacts {
  registrar?: string | null
  registrar_abuse_email?: string | null
  host_org?: string | null
  host_abuse_email?: string | null
  /** "rdap" */
  source?: string | null
}

export interface BrowserRequest {
  url: string
  method?: string | null
  resource_type?: string | null
  status?: number | null
  domain?: string | null
}

export interface BrowserConsoleEntry {
  type?: string | null
  text?: string | null
}

export interface BrowserCookie {
  name: string
  domain?: string | null
  secure?: boolean | null
  http_only?: boolean | null
}

/** Headless-browser capture (G2 [S]); null unless `enable_browser_capture` is on. `dom_html` is stripped by the API. */
export interface BrowserCapture {
  /** PNG under /api/screenshots/ - use screenshotUrl() */
  screenshot_file?: string | null
  final_url?: string | null
  title?: string | null
  requests?: BrowserRequest[] | null
  console?: BrowserConsoleEntry[] | null
  cookies?: BrowserCookie[] | null
}

/** How much of the analysis actually ran. */
export interface Coverage {
  network?: boolean | null
  checks_total?: number | null
  checks_errored?: number | null
}

// ============================================================================================ scans

/** Full scan result with every v2 field (all optional - older scans lack them). */
export interface ScanResultV2 extends ScanResult {
  source?: Loose<StoredScanSourceV2> | null
  http?: HttpInfoV2 | null
  reputation?: ReputationV2 | null
  /** 100 - risk_score (G15) */
  trust_score?: number | null
  tier?: Loose<Tier> | null
  tested_depth?: Loose<TestedDepth> | null
  threat_type?: Loose<ThreatType> | null
  factors?: Factors | null
  /** 2-4 plain-English sentences (G19) */
  summary?: string | null
  /** ordered by severity, plain-English facts */
  summary_points?: string[] | null
  favicon?: FaviconInfo | null
  email_security?: EmailSecurity | null
  popularity?: Popularity | null
  content?: ContentInfo | null
  cloaking?: CloakingInfo | null
  abuse?: AbuseContacts | null
  browser?: BrowserCapture | null
  visibility?: Loose<Visibility> | null
  /** used for share links: shareLink(token) / apiV2.share(token) */
  share_token?: string | null
  /** a DOM snapshot exists -> apiV2.dom(id) */
  has_dom?: boolean | null
  coverage?: Coverage | null
  /** set when the scan was made with an API key (source="api") */
  api_key_id?: number | null
  /** popular/official-domain risk cap (risk capped at 30 when no feed/engine hit) */
  score_cap?: { applied?: boolean | null; reason?: string | null; cap?: number | null } | null
  /** evidence strings behind threat_type */
  threat_reasons?: string[] | null
  /** latest dispute filed for this scan, if any */
  dispute?: { id: number; status: Loose<DisputeStatus> } | null
}

/** History-row summary with the v2 columns. */
export interface ScanSummaryV2 extends ScanSummary {
  source?: Loose<StoredScanSourceV2> | null
  trust_score?: number | null
  tier?: Loose<Tier> | null
  threat_type?: Loose<ThreatType> | null
  category?: Loose<ContentCategory> | null
  visibility?: Loose<Visibility> | null
}

/** PATCH /api/scans/{id} body. */
export interface ScanPatchV2 {
  tags?: string[]
  notes?: string | null
  visibility?: Visibility
}

/** v1 filters + v2 pivot filters (G5). Same filters work on /api/scans/export. */
export interface ScanFiltersV2 extends ScanFilters {
  ip?: string
  /** e.g. "AS13335" */
  asn?: string
  registrar?: string
  /** name server host */
  ns?: string
  /** Server header value */
  server?: string
  /** favicon mmh3 hash */
  favicon?: string | number
  /** tracker id, e.g. "G-ABC123" */
  tracker?: string
  category?: Loose<ContentCategory>
  threat_type?: Loose<ThreatType>
  tier?: Loose<Tier>
  language?: string
  visibility?: Loose<Visibility>
  parked?: boolean | 'true' | 'false'
  /** scans made with a given API key */
  api_key_id?: Id
  sort?: Loose<ScanSortV2>
}

/** v2 pivot filter keys (the History "advanced pivot" panel, `pivotHref` targets). */
export type PivotField =
  | 'ip'
  | 'asn'
  | 'registrar'
  | 'ns'
  | 'server'
  | 'favicon'
  | 'tracker'
  | 'category'
  | 'threat_type'
  | 'tier'
  | 'language'
  | 'visibility'

/** GET /api/scans/{id}/dom (G1). */
export interface DomSnapshot {
  html: string
  /** bytes of the stored (uncompressed) HTML */
  size: number
  /** HTML was cut at 500 KB */
  truncated: boolean
  /** "http" probe or "browser" capture */
  source?: string | null
}

/** GET /api/scans/{id}/similar (G3); each list <= 20, similar_* exclude the same domain. */
export interface SimilarScans {
  same_favicon?: ScanSummaryV2[] | null
  /** dHash Hamming distance <= 6 */
  similar_favicon?: { scan: ScanSummaryV2; distance: number }[] | null
  same_ip?: ScanSummaryV2[] | null
  same_asn?: ScanSummaryV2[] | null
  same_trackers?: ScanSummaryV2[] | null
  same_registrar?: ScanSummaryV2[] | null
}

/** GET /api/scans/{id}/abuse-report (G25): ready-to-send abuse email. */
export interface AbuseReport {
  to: string[]
  cc?: string[] | null
  subject: string
  body: string
  /** mailto: URL with to/cc/subject/body encoded */
  mailto: string
}

export interface DomainDetailV2 extends DomainDetail {
  scans?: ScanSummaryV2[] | null
  latest?: ScanResultV2 | null
}

export interface CompareResultV2 extends CompareResult {
  a: ScanResultV2
  b: ScanResultV2
}

export interface LiveStatsV2 extends LiveStats {
  /** private scans excluded */
  last_scans?: ScanSummaryV2[] | null
}

export interface BulkJobDetailV2 extends BulkJobDetail {
  results: ScanSummaryV2[]
}

// ============================================================================================ graph

export type GraphNodeType = 'domain' | 'url' | 'ip' | 'asn' | 'ns' | 'registrar' | 'favicon' | 'tracker' | 'brand' | 'redirect' | 'country'
export type GraphEdgeType =
  | 'resolves_to'
  | 'in_asn'
  | 'uses_ns'
  | 'registered_with'
  | 'has_favicon'
  | 'has_tracker'
  | 'impersonates'
  | 'redirects_to'
  | 'located_in'
  | 'scanned_as'

/** Relationship-graph node (G4). `id` is a unique string; edges reference it. */
export interface GraphNode {
  id: string
  type: Loose<GraphNodeType>
  label: string
  /** 0-100 (domains/urls), null for infrastructure nodes */
  risk?: number | null
  verdict?: Loose<Verdict> | null
  /** number of scans touching this node */
  count?: number | null
}

/** Graph edge; `source`/`target` are GraphNode ids (copy before handing to a simulation that mutates them). */
export interface GraphEdge {
  source: string
  target: string
  type: Loose<GraphEdgeType>
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

/** GET /api/graph params; none = global graph of the most recent/high-risk 50 domains. */
export interface GraphParams {
  domain?: string
  scan_id?: Id
  depth?: 1 | 2
  /** default 150 */
  limit?: number
}

// ======================================================================================== analytics

export interface OverviewV2 extends Overview {
  /** 0-100 */
  avg_trust_score?: number | null
  rule_matches?: number | null
  disputes_open?: number | null
  api_requests?: number | null
  ct_findings?: number | null
  rechecks?: number | null
}

export interface TldRisk extends NameValue {
  avg_risk?: number | null
}

/** Distribution + v2 breakdowns. Shapes the spec leaves open are typed loosely - run them through nameValues(). */
export interface DistributionV2 extends Distribution {
  threat_types?: NameValue[] | null
  tiers?: NameValue[] | null
  categories?: NameValue[] | null
  languages?: NameValue[] | null
  asns?: NameValue[] | null
  registrars?: NameValue[] | null
  trackers?: NameValue[] | null
  tld_risk?: TldRisk[] | null
  engines_flagged?: NameValue[] | null
  /** spec gives no shape: count or [{name,value}] - use nameValues(d.parked, 'parked') */
  parked?: NameValue[] | number | null
  ecommerce_flags?: NameValue[] | null
  /** no_spf / no_dmarc / dnsbl */
  email_security?: NameValue[] | null
  popularity?: NameValue[] | null
}

/** GET /api/analytics/engines row (G6). Rates: expected 0-1 ratios - format with fmtPct(v) (auto ratio/percent). */
export interface EngineStat {
  name: string
  type?: Loose<EngineType> | null
  checked?: number | null
  flagged?: number | null
  hit_rate?: number | null
  /** agreement with the final verdict */
  agreement?: number | null
}

/** Scanned -> Reachable -> Has login/password form -> Brand impersonation -> Feed/DNSBL listed -> Phishing verdict. */
export interface FunnelStage {
  stage: string
  count: number
}

export interface BrandStat {
  brand: string
  count: number
  avg_risk?: number | null
  phishing?: number | null
  /** technique -> count */
  techniques?: Record<string, number> | null
  first_seen?: string | null
  last_seen?: string | null
}

/** Usage timeseries point: one numeric column per source. */
export interface UsagePoint {
  t: string
  dashboard?: number
  api?: number
  bulk?: number
  watch?: number
  extension?: number
  recheck?: number
  [source: string]: string | number | null | undefined
}

export interface UsageStats {
  by_source?: NameValue[] | null
  by_api_key?: NameValue[] | null
  timeseries?: UsagePoint[] | null
}

/** {t, count} point (API-key usage). */
export interface CountPoint {
  t: string
  count: number
}

// ======================================================================================== community

/** Report with ratings and weighted votes (G17). */
export interface ReportV2 extends Report {
  /** 1-5 stars */
  rating?: number | null
  /** sum of weighted votes; >= 3 verified, <= -3 rejected */
  weighted_score?: number | null
  /** average weight of the voters */
  voter_reputation?: number | null
}

export interface ReportCreateV2 {
  url: string
  label: 'phishing' | 'legitimate'
  brand?: string
  comment?: string
  reporter?: string
  /** 1-5 */
  rating?: number
}

/** GET /api/reviews?domain= (domain omitted -> all reports). */
export interface ReviewsSummary {
  domain: string | null
  avg_rating?: number | null
  /** number of RATED reports */
  count: number
  /** keys "1".."5" */
  distribution?: Partial<Record<'1' | '2' | '3' | '4' | '5', number>> | null
  /** all reports for the domain (rated or not) */
  total_reports?: number | null
  /** rated first, newest first */
  items?: ReportV2[] | null
}

/** Voter leaderboard row; weight = clamp(1 + (agree - disagree)/10, 0.5, 3). */
export interface Voter {
  name: string
  agree: number
  disagree: number
  weight: number
  votes?: number | null
  /** agree / (agree + disagree), 0-1 */
  accuracy?: number | null
}

export type DisputeStatus = 'open' | 'upheld' | 'overturned'

/** False-positive dispute (G18). Creating one forces a fresh deep rescan (rescan_id). */
export interface Dispute {
  id: number
  scan_id: number
  url?: string | null
  domain?: string | null
  reason?: string | null
  contact?: string | null
  status: Loose<DisputeStatus>
  original_risk?: number | null
  original_verdict?: Loose<Verdict> | null
  new_risk?: number | null
  new_verdict?: Loose<Verdict> | null
  rescan_id?: number | null
  created_at?: string | null
  resolved_at?: string | null
  note?: string | null
}

export interface DisputeInput {
  scan_id: Id
  reason: string
  contact?: string
}

export interface DisputeResolve {
  status: 'upheld' | 'overturned'
  note?: string
}

/** {items,total} wrapper for endpoints without guaranteed pagination fields. */
export interface ListResult<T> {
  items: T[]
  total: number
  page?: number
  page_size?: number
}

/** GET /api/disputes: items + per-status counts (all disputes, ignoring the filter). */
export interface DisputeList extends ListResult<Dispute> {
  counts?: Partial<Record<DisputeStatus, number>> | null
}

// ============================================================================================ rules

/**
 * Hunting-rule filters (G23) - same keys/semantics as ScanFiltersV2 minus dates and paging. Unknown keys are
 * rejected (422); verdict/threat_type values are validated; empty values are dropped by the backend.
 */
export interface RuleFilters {
  q?: string
  /** comma list, e.g. "phishing,suspicious" */
  verdict?: string
  source?: string
  min_risk?: number
  max_risk?: number
  brand?: string
  tld?: string
  tag?: string
  domain?: string
  blacklisted?: boolean
  threat_type?: Loose<ThreatType>
  category?: Loose<ContentCategory>
  tier?: Loose<Tier>
  language?: string
  visibility?: Loose<Visibility>
  parked?: boolean
  ip?: string
  asn?: string
  registrar?: string
  ns?: string
  server?: string
  favicon?: string | number
  tracker?: string
  api_key_id?: number
}

export interface Rule {
  id: number
  name: string
  filters: RuleFilters
  severity: Loose<AlertSeverity>
  enabled: boolean
  created_at?: string | null
  updated_at?: string | null
  match_count?: number | null
  last_match_at?: string | null
}

export interface RuleInput {
  name: string
  filters: RuleFilters
  severity?: AlertSeverity
  enabled?: boolean
}

/** GET /api/rules/{id}/matches row. */
export interface RuleMatch extends ScanSummaryV2 {
  matched_at?: string | null
  rule_id?: number | null
}

// ======================================================================================= watchlist

export interface WatchItemV2 extends WatchItem {
  /** Certificate-transparency lookalike monitoring (G24) - set on create. */
  monitor_ct?: boolean | null
  /** last CT poll time / error (if exposed by the API) */
  ct_last_run?: string | null
  ct_last_error?: string | null
}

export interface WatchAddV2 {
  target: string
  interval_minutes: number
  monitor_typosquats: boolean
  monitor_ct?: boolean
  label?: string
}

export interface WatchHistoryV2 extends WatchHistory {
  item?: WatchItemV2 | null
}

/** CT lookalike finding (crt.sh). */
export interface CtFinding {
  id?: number | null
  watch_id?: number | null
  /** watched domain the lookalike was found for */
  domain?: string | null
  /** crt.sh certificate id */
  cert_id?: string | null
  /** lookalike hostname */
  name: string
  issuer?: string | null
  not_before?: string | null
  first_seen?: string | null
  /** set once PhishGuard scanned the lookalike */
  scanned_scan_id?: number | null
}

/** POST /api/watchlist/{id}/ct/run - shape not fixed by the spec; refetch apiV2.ctFindings() afterwards. */
export interface CtRunResult {
  status?: string
  new?: number | null
  total?: number | null
  findings?: CtFinding[] | null
  item?: WatchItemV2 | null
  [k: string]: unknown
}

// ========================================================================================= API keys

/** API key (G27) as listed - never contains the full key. */
export interface ApiKey {
  id: number
  name: string
  /** first characters of the key, for display */
  prefix?: string | null
  rate_limit_per_min?: number | null
  created_at?: string | null
  requests?: number | null
  last_used?: string | null
  revoked?: boolean | null
  revoked_at?: string | null
  /** number of scans made with this key */
  scans?: number | null
}

/** POST /api/keys response - `key` is shown ONCE. */
export interface ApiKeyCreated extends ApiKey {
  key: string
}

// =========================================================================================== events

export type EntityType = 'scan' | 'domain' | 'report' | 'dispute' | 'rule' | 'watch' | 'bulk' | 'key' | 'settings'

export interface EventItemV2 extends EventItem {
  entity_type?: Loose<EntityType> | null
  /** number for numeric entities (scan, rule, ...), string for domain/settings */
  entity_id?: string | number | null
  /** related scan / domain (used by the per-scan timeline) */
  scan_id?: number | null
  domain?: string | null
}

/** Alert with v2 links. New alert types: rule_match, ct_lookalike (+ recheck / dispute related). */
export interface AlertV2 extends Alert {
  rule_id?: number | null
  dispute_id?: number | null
}

export interface EventsPageV2 extends Paged<EventItemV2> {
  types?: string[] | null
}

export interface EventFilters {
  /** comma list or array */
  type?: string | readonly string[]
  /** message search */
  q?: string
  entity_type?: Loose<EntityType>
  /** scan id, domain name, rule id ... */
  entity_id?: Id
  page?: number
  page_size?: number
}

// ========================================================================================= settings

export interface SettingsV2 extends Settings {
  /** Playwright capture - OFF by default (security-sensitive) */
  enable_browser_capture?: boolean
  enable_cloaking_check?: boolean
  enable_dnsbl?: boolean
  enable_rdap?: boolean
  /** G28 rating aging */
  auto_recheck_enabled?: boolean
  auto_recheck_days?: number
}

export type SettingsV2Flags = Required<
  Pick<SettingsV2, 'enable_browser_capture' | 'enable_cloaking_check' | 'enable_dnsbl' | 'enable_rdap' | 'auto_recheck_enabled' | 'auto_recheck_days'>
>

/** Spec defaults for the v2 settings (use when the backend omits them). */
export const SETTINGS_V2_DEFAULTS: SettingsV2Flags = {
  enable_browser_capture: false,
  enable_cloaking_check: true,
  enable_dnsbl: true,
  enable_rdap: true,
  auto_recheck_enabled: true,
  auto_recheck_days: 7,
}

// ======================================================================================== constants

export const TIERS: Tier[] = ['Trusted', 'Favorable', 'Neutral', 'Questionable', 'Untrusted']
export const UNTESTED_LABEL = 'Untested (lexical only)'
export const TIER_TONE: Record<Tier, Tone> = { Trusted: 'emerald', Favorable: 'emerald', Neutral: 'zinc', Questionable: 'amber', Untrusted: 'rose' }

export const THREAT_TYPES: ThreatType[] = ['malware', 'social_engineering', 'unwanted_software', 'none']
export const THREAT_TYPE_LABEL: Record<ThreatType, string> = {
  malware: 'Malware',
  social_engineering: 'Social engineering',
  unwanted_software: 'Unwanted software',
  none: 'No threat',
}
export const THREAT_TYPE_TONE: Record<ThreatType, Tone> = { malware: 'rose', social_engineering: 'rose', unwanted_software: 'amber', none: 'zinc' }

export const VISIBILITIES: Visibility[] = ['public', 'unlisted', 'private']

export const CONTENT_CATEGORIES: ContentCategory[] = [
  'banking',
  'payment',
  'shopping',
  'crypto',
  'social',
  'email',
  'cloud_storage',
  'government',
  'education',
  'news',
  'technology',
  'entertainment',
  'adult',
  'gambling',
  'parked',
  'login',
  'other',
]

export const SCAN_SOURCES_V2: StoredScanSourceV2[] = ['web', 'api', 'bulk', 'text', 'qr', 'watch', 'extension', 'community', 'recheck', 'dispute']
export const DISPUTE_STATUSES: DisputeStatus[] = ['open', 'upheld', 'overturned']
export const ENTITY_TYPES: EntityType[] = ['scan', 'domain', 'report', 'dispute', 'rule', 'watch', 'bulk', 'key', 'settings']

/** Metadata for the History pivot-filter panel (all v2 filters). */
export const PIVOT_FIELDS: { key: PivotField; label: string; placeholder: string }[] = [
  { key: 'ip', label: 'IP address', placeholder: '203.0.113.7' },
  { key: 'asn', label: 'ASN', placeholder: 'AS13335' },
  { key: 'registrar', label: 'Registrar', placeholder: 'NameCheap, Inc.' },
  { key: 'ns', label: 'Name server', placeholder: 'ns1.example.com' },
  { key: 'server', label: 'Server header', placeholder: 'nginx' },
  { key: 'favicon', label: 'Favicon hash (mmh3)', placeholder: '-1234567890' },
  { key: 'tracker', label: 'Tracker ID', placeholder: 'G-XXXXXXX' },
  { key: 'category', label: 'Content category', placeholder: 'banking' },
  { key: 'threat_type', label: 'Threat type', placeholder: 'social_engineering' },
  { key: 'tier', label: 'Tier', placeholder: 'Untrusted' },
  { key: 'language', label: 'Language', placeholder: 'en' },
  { key: 'visibility', label: 'Visibility', placeholder: 'public' },
]

// ========================================================================================== helpers

export const isTier = (v: unknown): v is Tier => typeof v === 'string' && (TIERS as string[]).includes(v)
export const isThreatType = (v: unknown): v is ThreatType => typeof v === 'string' && (THREAT_TYPES as string[]).includes(v)
export const isVisibility = (v: unknown): v is Visibility => typeof v === 'string' && (VISIBILITIES as string[]).includes(v)

/** Tier for a risk score using the scoring.py bands (S/P = suspicious/phishing thresholds). */
export function tierFor(risk: number | null | undefined, sus = 35, phish = 65): Tier | null {
  if (risk == null || Number.isNaN(Number(risk))) return null
  const r = Number(risk)
  if (r < Math.min(15, sus)) return 'Trusted'
  if (r < sus) return 'Favorable'
  if (r < (sus + phish) / 2) return 'Neutral'
  if (r < phish) return 'Questionable'
  return 'Untrusted'
}

type ScanLike = Partial<Pick<ScanResultV2, 'risk_score' | 'trust_score' | 'tier' | 'threat_type' | 'visibility' | 'tested_depth' | 'network_checks'>>

/** Backend tier if valid, else derived from risk_score (v1 scans). */
export function tierOf(scan: ScanLike | null | undefined, sus = 35, phish = 65): Tier | null {
  if (!scan) return null
  return isTier(scan.tier) ? scan.tier : tierFor(scan.risk_score, sus, phish)
}

/** trust_score, or 100 - risk_score for v1 scans. */
export function trustScoreOf(scan: ScanLike | null | undefined): number | null {
  if (!scan) return null
  if (scan.trust_score != null) return scan.trust_score
  return scan.risk_score != null ? Math.max(0, Math.min(100, 100 - scan.risk_score)) : null
}

/** Narrowed threat type (null when missing/unknown). */
export function threatTypeOf(scan: ScanLike | null | undefined): ThreatType | null {
  return isThreatType(scan?.threat_type) ? scan.threat_type : null
}

/** Narrowed visibility, default "public". */
export function visibilityOf(scan: ScanLike | null | undefined): Visibility {
  return isVisibility(scan?.visibility) ? scan.visibility : 'public'
}

/** true when only lexical + ML ran -> show UNTESTED_LABEL. */
export function isLexicalOnly(scan: ScanLike | null | undefined): boolean {
  if (!scan) return false
  if (scan.tested_depth != null) return scan.tested_depth === 'lexical'
  return scan.network_checks === false
}

/** engine_ratio, else derived from engines, else from v1 reputation.sources (errored lookups excluded). */
export function engineRatioOf(scan: Pick<ScanResultV2, 'reputation'> | null | undefined): EngineRatio | null {
  const rep = scan?.reputation
  if (!rep) return null
  if (rep.engine_ratio && typeof rep.engine_ratio.total === 'number') return rep.engine_ratio
  if (Array.isArray(rep.engines) && rep.engines.length) {
    const definite = rep.engines.filter((e) => e && e.listed != null)
    return { flagged: definite.filter((e) => e.listed === true).length, total: definite.length }
  }
  if (Array.isArray(rep.sources) && rep.sources.length) {
    const definite = rep.sources.filter((s) => s && !s.error)
    return { flagged: definite.filter((s) => s.listed).length, total: definite.length }
  }
  return null
}

/** URL of a stored screenshot PNG (G2): /api/screenshots/<file>. */
export function screenshotUrl(file: string): string {
  return `/api/screenshots/${enc(file)}`
}

/** Best screenshot source for a scan: browser capture PNG, else v1 `screenshot_url` (thum.io), else null. */
export function screenshotSrc(scan: Pick<ScanResultV2, 'browser' | 'screenshot_url'> | null | undefined): string | null {
  const file = scan?.browser?.screenshot_file
  if (file) return screenshotUrl(file)
  return scan?.screenshot_url || null
}

/** Link to History filtered by a pivot value, e.g. pivotHref('ip', '1.2.3.4') -> "/history?ip=1.2.3.4". */
export function pivotHref(field: PivotField | keyof ScanFiltersV2, value: string | number): string {
  return `/history${qs({ [field]: String(value) })}`
}

/** API path of a shared scan (public/unlisted only; private -> 404). */
export function shareApiPath(token: string): string {
  return `/api/share/${enc(token)}`
}

/** Front-end share link. FE-Pages registers the route `share/:token` (read-only report via apiV2.share). */
export function shareLink(token: string, origin?: string): string {
  const o = origin ?? (typeof window !== 'undefined' ? window.location.origin : '')
  return `${o}/share/${enc(token)}`
}

/**
 * Normalise chart data to NameValue[]: accepts [{name,value}] | [{name|label|key|id|...,count|total}] | [[name, n]] |
 * {name: n} | a bare number (-> [{name: fallbackName, value}]). Drops entries without a name.
 */
export function nameValues(v: unknown, fallbackName = 'value'): NameValue[] {
  if (v == null) return []
  if (typeof v === 'number') return Number.isFinite(v) ? [{ name: fallbackName, value: v }] : []
  if (Array.isArray(v)) {
    const out: NameValue[] = []
    for (const it of v) {
      if (Array.isArray(it)) {
        if (it[0] != null) out.push({ name: String(it[0]), value: Number(it[1]) || 0 })
      } else if (it && typeof it === 'object') {
        const o = it as Record<string, unknown>
        const name = o.name ?? o.label ?? o.key ?? o.id ?? o.stage ?? o.bucket ?? o.brand ?? o.domain ?? o.type
        if (name == null || name === '') continue
        out.push({ name: String(name), value: Number(o.value ?? o.count ?? o.total ?? 0) || 0 })
      }
    }
    return out
  }
  if (typeof v === 'object') return Object.entries(v as Record<string, unknown>).map(([name, value]) => ({ name, value: Number(value) || 0 }))
  return []
}

/** Normalise T[] | {items,total,...} into ListResult<T>. */
export function asPaged<T>(v: unknown): ListResult<T> {
  const items = asList<T>(v)
  const o = v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
  const num = (x: unknown) => (typeof x === 'number' && Number.isFinite(x) ? x : undefined)
  return { items, total: num(o.total) ?? items.length, page: num(o.page), page_size: num(o.page_size) }
}

/** Seconds to wait from a 429 ApiError (API-key rate limit), else null. */
export function retryAfterOf(e: unknown): number | null {
  if (!(e instanceof ApiError) || e.status !== 429) return null
  const n = Number((e.body as { retry_after?: unknown } | null)?.retry_after)
  return Number.isFinite(n) ? n : null
}

function nullOn404(e: unknown): null {
  if (e instanceof ApiError && e.status === 404) return null
  throw e
}

// ======================================================================================= query keys

const sid = (id: Id) => String(id)

/**
 * TanStack Query keys. Ids are normalised to strings; sub-resources nest under their parent so
 * `invalidateQueries({ queryKey: qk.scan(id) })` also refreshes dom/similar/timeline/abuse.
 * Keys for endpoints shared with v1 (overview, distribution, timeseries, scans, domain, settings...) match the
 * keys v1 pages already use, so v1 and v2 fetchers share one cache entry.
 */
export const qk = {
  health: ['health'] as const,
  live: ['live'] as const,
  settings: ['settings'] as const,
  model: ['model'] as const,
  scans: (f: ScanFiltersV2 = {}) => ['scans', f] as const,
  scan: (id: Id) => ['scan', sid(id)] as const,
  scanDom: (id: Id) => ['scan', sid(id), 'dom'] as const,
  scanSimilar: (id: Id) => ['scan', sid(id), 'similar'] as const,
  scanTimeline: (id: Id) => ['scan', sid(id), 'timeline'] as const,
  scanAbuse: (id: Id) => ['scan', sid(id), 'abuse-report'] as const,
  compare: (id: Id, other: Id) => ['compare', sid(id), sid(other)] as const,
  share: (token: string) => ['share', token] as const,
  domain: (domain: string) => ['domain', domain] as const,
  graph: (p: GraphParams = {}) => ['graph', p] as const,
  overview: (range: Range) => ['overview', range] as const,
  timeseries: (range: Range, bucket?: 'hour' | 'day') => ['timeseries', range, bucket] as const,
  distribution: (range: Range) => ['distribution', range] as const,
  performance: (range: Range) => ['performance', range] as const,
  engines: (range: Range) => ['analytics', 'engines', range] as const,
  funnel: (range: Range) => ['analytics', 'funnel', range] as const,
  brands: (range: Range) => ['analytics', 'brands', range] as const,
  usage: (range: Range) => ['analytics', 'usage', range] as const,
  reports: (status?: string, page = 1, extra: object = {}) => ['reports', status ?? 'all', page, extra] as const,
  reviews: (domain: string) => ['reviews', domain] as const,
  voters: ['voters'] as const,
  disputes: (status?: string) => ['disputes', status ?? 'all'] as const,
  rules: ['rules'] as const,
  ruleMatches: (id: Id) => ['rules', sid(id), 'matches'] as const,
  watchlist: ['watchlist'] as const,
  watchHistory: (id: Id) => ['watch-history', sid(id)] as const,
  watchCt: (id: Id) => ['watch-ct', sid(id)] as const,
  keys: ['api-keys'] as const,
  keyUsage: (id: Id, range: Range) => ['api-keys', sid(id), 'usage', range] as const,
  events: (f: EventFilters = {}) => ['events', f] as const,
  alerts: (...parts: (string | number | boolean)[]) => ['alerts', ...parts] as const,
  bulk: (id?: Id) => (id == null ? (['bulk'] as const) : (['bulk', sid(id)] as const)),
}

// ========================================================================================= fetchers

/** v2 fetchers. Same calling style as v1 `api`; list endpoints resolve to arrays (asList-normalised). */
export const apiV2 = {
  // ---- scans (v1 endpoints, typed with v2 fields)
  /** `opts.visibility` is only sent when given (ignored by backends that don't accept it on create). */
  scan: (url: string, deep = true, source: ScanSource = 'web', opts: { visibility?: Visibility } = {}) =>
    post<ScanResultV2>('/scan', { url, deep, source, ...(opts.visibility ? { visibility: opts.visibility } : {}) }),
  /** Scan through the API-key middleware (source becomes "api"); 401 invalid/revoked, 429 rate-limited (Retry-After). */
  scanWithKey: (url: string, key: string, deep = false) =>
    request<ScanResultV2>('POST', '/api/scan', { url, deep, source: 'api' }, { headers: { 'X-API-Key': key } }),
  getScan: (id: Id) => get<ScanResultV2>(`/scans/${enc(id)}`),
  scans: (f: ScanFiltersV2 = {}) => get<Paged<ScanSummaryV2>>('/scans', f),
  /** Returns a NEW scan (new id). */
  rescan: (id: Id, deep = true) => post<ScanResultV2>(`/scans/${enc(id)}/rescan${qs({ deep })}`),
  patchScan: (id: Id, body: ScanPatchV2) => patch<ScanResultV2>(`/scans/${enc(id)}`, body),
  setVisibility: (id: Id, visibility: Visibility) => patch<ScanResultV2>(`/scans/${enc(id)}`, { visibility }),
  deleteScan: (id: Id) => del<DeleteResult>(`/scans/${enc(id)}`),
  compare: (id: Id, other: Id) => get<CompareResultV2>(`/scans/${enc(id)}/compare/${enc(other)}`),
  /** CSV/JSON download URL with v1 + pivot filters. */
  exportUrl: (format: 'csv' | 'json', f: ScanFiltersV2 = {}) => api.exportUrl(format, f),
  /** DOM snapshot (G1); resolves to null when the scan has none (404). */
  dom: (id: Id) => get<DomSnapshot>(`/scans/${enc(id)}/dom`).catch(nullOn404),
  similar: (id: Id) => get<SimilarScans>(`/scans/${enc(id)}/similar`),
  /** Entity events for the scan + its domain, newest first. */
  timeline: (id: Id) => get<unknown>(`/scans/${enc(id)}/timeline`).then((v) => asList<EventItemV2>(v)),
  abuseReport: (id: Id) => get<AbuseReport>(`/scans/${enc(id)}/abuse-report`),
  /** Shared scan by token (public/unlisted); ApiError 404 for private/unknown. */
  share: (token: string) => get<ScanResultV2>(`/share/${enc(token)}`),
  domain: (domain: string) => get<DomainDetailV2>(`/domains/${enc(domain)}`),
  live: () => get<LiveStatsV2>('/stats/live'),
  bulkJob: (id: Id) => get<BulkJobDetailV2>(`/bulk/${enc(id)}`),

  // ---- graph (G4)
  graph: (p: GraphParams = {}) =>
    get<Partial<GraphData> | null>('/graph', p).then((g): GraphData => ({
      nodes: Array.isArray(g?.nodes) ? g.nodes : [],
      edges: Array.isArray(g?.edges) ? g.edges : [],
    })),

  // ---- community, reviews, voters (G17)
  createReport: (b: ReportCreateV2) => post<ReportV2>('/reports', b),
  reports: (status?: ReportStatus | string, page = 1, opts: { q?: string; page_size?: number } = {}) =>
    get<Paged<ReportV2>>('/reports', { status, page, ...opts }),
  report: (id: Id) => get<ReportV2>(`/reports/${enc(id)}`),
  vote: (id: Id, vote: 'phishing' | 'legitimate', voter?: string) => post<ReportV2>(`/reports/${enc(id)}/vote`, { vote, voter }),
  /** Ratings summary + reports for a domain (host or registered domain); omit domain for all reports. */
  reviews: (domain?: string) => get<ReviewsSummary>('/reviews', { domain }),
  /** Leaderboard, highest weight first. */
  voters: () => get<unknown>('/voters').then((v) => asList<Voter>(v)),

  // ---- disputes (G18)
  /** Forces a fresh deep rescan; resolves after it (status may already be "overturned"). */
  createDispute: (b: DisputeInput) => post<Dispute>('/disputes', b),
  disputes: (status?: DisputeStatus | string, opts: { scan_id?: Id; q?: string; page?: number; page_size?: number } = {}) =>
    get<unknown>('/disputes', { status, ...opts }).then((v): DisputeList => {
      const counts = v && typeof v === 'object' && !Array.isArray(v) ? (v as { counts?: DisputeList['counts'] }).counts : null
      return { ...asPaged<Dispute>(v), counts: counts ?? null }
    }),
  resolveDispute: (id: Id, b: DisputeResolve) => post<Dispute>(`/disputes/${enc(id)}/resolve`, b),

  // ---- hunting rules (G23)
  rules: () => get<unknown>('/rules').then((v) => asList<Rule>(v)),
  createRule: (b: RuleInput) => post<Rule>('/rules', b),
  /** PUT - send the full rule (name, filters, severity, enabled) to be safe. */
  updateRule: (id: Id, b: Partial<RuleInput>) => put<Rule>(`/rules/${enc(id)}`, b),
  deleteRule: (id: Id) => del<DeleteResult>(`/rules/${enc(id)}`),
  ruleMatches: (id: Id) => get<unknown>(`/rules/${enc(id)}/matches`).then((v) => asList<RuleMatch>(v)),

  // ---- watchlist + certificate transparency (G24)
  watchAdd: (b: WatchAddV2) => post<WatchItemV2>('/watchlist', b),
  watchlist: () => get<unknown>('/watchlist').then((v) => asList<WatchItemV2>(v)),
  watchRun: (id: Id) => post<WatchItemV2>(`/watchlist/${enc(id)}/run`),
  watchDelete: (id: Id) => del<DeleteResult>(`/watchlist/${enc(id)}`),
  watchHistory: (id: Id) => get<WatchHistoryV2>(`/watchlist/${enc(id)}/history`),
  ctFindings: (id: Id) => get<unknown>(`/watchlist/${enc(id)}/ct`).then((v) => asList<CtFinding>(v)),
  ctRun: (id: Id) => post<CtRunResult>(`/watchlist/${enc(id)}/ct/run`),

  // ---- API keys (G27)
  keys: () => get<unknown>('/keys').then((v) => asList<ApiKey>(v)),
  createKey: (b: { name: string; rate_limit_per_min?: number }) => post<ApiKeyCreated>('/keys', b),
  /** Revokes (key stays listed with revoked=true); resolves to the revoked key or {deleted,id}. */
  revokeKey: (id: Id) => del<Partial<ApiKey> & DeleteResult>(`/keys/${enc(id)}`),
  keyUsage: (id: Id, range: Range = '30d') => get<unknown>(`/keys/${enc(id)}/usage`, { range }).then((v) => asList<CountPoint>(v)),

  // ---- activity log with entity filters, alerts with rule/dispute links
  events: (f: EventFilters = {}) => get<EventsPageV2>('/events', f),
  alerts: (unread?: boolean, opts: { severity?: AlertSeverity | string; limit?: number } = {}) =>
    get<unknown>('/alerts', { unread, ...opts }).then((v) => asList<AlertV2>(v)),

  // ---- analytics
  overview: (range: Range = '30d') => get<OverviewV2>('/analytics/overview', { range }),
  distribution: (range: Range = '30d') => get<DistributionV2>('/analytics/distribution', { range }),
  engines: (range: Range = '30d') => get<unknown>('/analytics/engines', { range }).then((v) => asList<EngineStat>(v)),
  funnel: (range: Range = '30d') => get<unknown>('/analytics/funnel', { range }).then((v) => asList<FunnelStage>(v)),
  brands: (range: Range = '30d') => get<unknown>('/analytics/brands', { range }).then((v) => asList<BrandStat>(v)),
  usage: (range: Range = '30d') => get<UsageStats>('/analytics/usage', { range }),

  // ---- settings
  settings: () => get<SettingsV2>('/settings'),
  saveSettings: (s: Partial<SettingsV2>) => put<SettingsV2>('/settings', s),
}
