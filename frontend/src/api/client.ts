// Typed API client for the PhishGuard backend (see docs/SPEC.md §4).
// Types mirror what the FastAPI backend actually returns (backend code wins over the spec where they differ).
// All fields are typed as optional/nullable where the backend may omit them; UI code must render defensively.
// v2 additions live in ./client_v2.ts (which re-exports everything from this file).

export type Verdict = 'legitimate' | 'suspicious' | 'phishing'
export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info' | 'error'
export type CheckCategory = 'lexical' | 'domain' | 'network' | 'ssl' | 'content' | 'reputation' | 'brand'
/** Sources accepted by `POST /api/scan`. */
export type ScanSource = 'web' | 'api' | 'bulk' | 'text' | 'qr' | 'watch' | 'extension'
/** Sources that can appear on stored scans (community = scan triggered by a community report). */
export type StoredScanSource = ScanSource | 'community'
export type Range = '24h' | '7d' | '30d' | '90d' | 'all'
/** All ids are integers in the backend; routes/params may still pass them as strings. */
export type Id = number | string
export type AlertSeverity = 'info' | 'warning' | 'critical'
/** Status of a single community report. */
export type ReportStatus = 'pending' | 'verified' | 'rejected'
/** Aggregate community status on a scan (`none` = never reported). */
export type CommunityStatus = 'none' | ReportStatus

export interface Check {
  id: string
  category: CheckCategory | string
  name: string
  status: CheckStatus
  detail?: string | null
  /** 0-10 */
  weight?: number | null
}

export interface ModelProb {
  name: string
  /** 0-1 */
  probability: number
}

export interface Explanation {
  feature: string
  label?: string | null
  value?: number | string | null
  impact: number
  direction?: 'risk' | 'safe' | string
}

export interface MlResult {
  model_name?: string | null
  model_version?: string | null
  /** 0-1 */
  probability_phishing?: number | null
  per_model?: ModelProb[] | null
  explanations?: Explanation[] | null
}

export interface Whois {
  registrar?: string | null
  creation_date?: string | null
  expiry_date?: string | null
  updated_date?: string | null
  age_days?: number | null
  days_to_expiry?: number | null
  registration_length_days?: number | null
  privacy_protected?: boolean | null
  /** Registrant country code (2-3 letters, upper-case). */
  country?: string | null
  name_servers?: string[] | null
  org?: string | null
  /** false when the registry returned nothing useful. */
  found?: boolean | null
  error?: string | null
}

export interface Dns {
  a?: string[] | null
  aaaa?: string[] | null
  /** "<preference> <host>" strings */
  mx?: string[] | null
  ns?: string[] | null
  txt?: string[] | null
  cname?: string[] | null
  spf?: boolean | null
  dmarc?: boolean | null
  resolves?: boolean | null
}

export interface Geo {
  country?: string | null
  country_code?: string | null
  city?: string | null
  /** "AS15169" style string */
  asn?: string | number | null
  as_name?: string | null
  org?: string | null
  isp?: string | null
  lat?: number | null
  lon?: number | null
  hosting?: boolean | null
  /** true when the IP is private/loopback (no lookup performed). */
  private?: boolean | null
}

export interface DomainInfo {
  domain?: string | null
  registered_domain?: string | null
  subdomain?: string | null
  tld?: string | null
  is_ip?: boolean | null
  /** Decoded Unicode hostname when the host is punycode (xn--), else null. NOT a boolean. */
  punycode?: string | null
  whois?: Whois | null
  dns?: Dns | null
  ip?: string | null
  geo?: Geo | null
}

export interface SslInfo {
  enabled?: boolean | null
  valid?: boolean | null
  issuer?: string | null
  issuer_org?: string | null
  issuer_cn?: string | null
  subject?: string | null
  subject_org?: string | null
  san?: string[] | null
  serial?: string | null
  not_before?: string | null
  not_after?: string | null
  days_left?: number | null
  age_days?: number | null
  validity_days?: number | null
  protocol?: string | null
  cipher?: string | null
  self_signed?: boolean | null
  /** Issued by a free CA (Let's Encrypt, ZeroSSL, Google Trust, ...). */
  free_cert?: boolean | null
  error?: string | null
}

export interface RedirectHop {
  url: string
  status?: number | null
}

/** One suspicious-JavaScript pattern hit (objects, not strings). */
export interface SuspiciousJs {
  id: string
  description?: string | null
}

/** `<meta http-equiv="refresh">` details; null when the page has none. */
export interface MetaRefresh {
  content?: string | null
  target?: string | null
  external?: boolean | null
}

export interface HttpInfo {
  reachable?: boolean | null
  final_url?: string | null
  status_code?: number | null
  response_ms?: number | null
  redirect_chain?: RedirectHop[] | null
  cross_domain_redirects?: number | null
  server?: string | null
  content_type?: string | null
  title?: string | null
  /** hsts, csp, x_frame_options, x_content_type_options, referrer_policy, permissions_policy */
  security_headers?: Record<string, boolean | null> | null
  /** Subset of raw response headers (lower-case names). */
  headers?: Record<string, string> | null
  technologies?: string[] | null
  forms?: {
    count?: number | null
    password_fields?: number | null
    external_actions?: number | null
    login_form?: boolean | null
    password_to_external?: boolean | null
    sensitive_inputs?: string[] | null
  } | null
  links?: {
    internal?: number | null
    external?: number | null
    null_links?: number | null
    /** 0-1 */
    external_ratio?: number | null
    /** 0-1 */
    null_ratio?: number | null
    total?: number | null
  } | null
  iframes?: number | null
  hidden_iframes?: number | null
  external_scripts?: number | null
  meta_refresh?: MetaRefresh | null
  page_size_kb?: number | null
  favicon_external?: boolean | null
  favicon_url?: string | null
  suspicious_js?: SuspiciousJs[] | null
  urgency_phrases?: string[] | null
  text_length?: number | null
  error?: string | null
}

export interface BrandInfo {
  impersonated_brand?: string | null
  /** 0-1 */
  similarity?: number | null
  technique?: 'typosquat' | 'homoglyph' | 'combosquat' | 'subdomain' | 'punycode' | 'path' | 'content' | string | null
  /** Human-readable explanation string. */
  details?: string | null
  /** true when the domain IS an official domain of a known brand. */
  official_domain?: boolean | null
  matched_keyword?: string | null
  /** Look-alike that simply redirects to the brand's official site. */
  defensive_redirect?: boolean | null
}

export interface ReputationSource {
  name: string
  listed: boolean
  detail?: string | null
  /** How a feed matched: exact URL or (parent) domain. */
  match?: 'url' | 'domain' | null
  /** true when the lookup itself failed (API error) - not a "clean" answer. */
  error?: boolean | null
  /** VirusTotal only */
  malicious?: number | null
  suspicious?: number | null
  engines?: number | null
}

export interface CommunityInfo {
  reports?: number | null
  phishing_votes?: number | null
  legitimate_votes?: number | null
  status?: CommunityStatus | null
}

export interface Reputation {
  blacklisted?: boolean | null
  sources?: ReputationSource[] | null
  community?: CommunityInfo | null
}

export interface ScoreComponent {
  component: string
  /** 0-100 */
  score: number
  /** 0-1 (0 for floor-style components: Blacklists, Community) */
  weight?: number | null
  /** Points this component added to the final risk. */
  contribution?: number | null
  note?: string | null
}

export interface ScanResult {
  id: number
  url: string
  normalized_url?: string | null
  domain?: string | null
  registered_domain?: string | null
  tld?: string | null
  created_at?: string | null
  duration_ms?: number | null
  source?: StoredScanSource | string | null
  verdict: Verdict
  /** 0-100 */
  risk_score: number
  /** 0-1 */
  confidence?: number | null
  ml?: MlResult | null
  features?: Record<string, number | string | null> | null
  checks?: Check[] | null
  domain_info?: DomainInfo | null
  ssl?: SslInfo | null
  http?: HttpInfo | null
  brand?: BrandInfo | null
  reputation?: Reputation | null
  screenshot_url?: string | null
  score_breakdown?: ScoreComponent[] | null
  /** 0-100 engine heuristic score (before blending with ML). */
  heuristic_score?: number | null
  /** false when the scan ran lexical/ML only (deep=false or network checks disabled). */
  network_checks?: boolean | null
  tags?: string[] | null
  notes?: string | null
}

export interface ScanSummary {
  id: number
  url: string
  domain?: string | null
  tld?: string | null
  created_at?: string | null
  verdict: Verdict
  risk_score: number
  confidence?: number | null
  source?: StoredScanSource | string | null
  /** impersonated brand */
  brand?: string | null
  country_code?: string | null
  blacklisted?: boolean | null
  duration_ms?: number | null
}

/** Paginated list wrapper used by /scans, /reports, /events. */
export interface Paged<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface Health {
  status?: string
  model_loaded?: boolean
  model_version?: string | null
  /** "ok" | "error" */
  db?: string | boolean | null
  uptime_s?: number | null
  feeds_entries?: number | null
  /** true while the demo seed is running */
  seeding?: boolean | null
}

export interface DomainDetail {
  domain: string
  /** newest first, max 200 */
  scans?: ScanSummary[] | null
  first_seen?: string | null
  last_seen?: string | null
  scan_count?: number | null
  avg_risk?: number | null
  latest?: ScanResult | null
  /** oldest first */
  risk_trend?: { t: string; risk: number; scan_id?: number | null }[] | null
}

export interface CompareResult {
  a: ScanResult
  b: ScanResult
  /** `field` is a dotted path, e.g. "ssl.issuer", "checks.domain_age", "reputation.listed_sources". */
  diff?: { field: string; a: unknown; b: unknown }[] | null
}

/** queued | running | completed | failed */
export type BulkStatus = 'queued' | 'running' | 'completed' | 'failed'

export type BulkVerdictCounts = Partial<Record<Verdict, number>> & { error?: number }

export interface BulkItem {
  url: string
  /** pending | done | error */
  status: 'pending' | 'done' | 'error' | string
  scan_id?: number | null
  error?: string | null
}

export interface BulkJob {
  id: number
  name?: string | null
  status?: BulkStatus | string | null
  total?: number | null
  done?: number | null
  /** 0-1 ratio (1.0 for an empty job) */
  progress?: number | null
  created_at?: string | null
  finished_at?: string | null
  verdict_counts?: BulkVerdictCounts | null
  /** detail endpoint only */
  results?: ScanSummary[] | null
  /** detail endpoint only: per-URL status/error */
  items?: BulkItem[] | null
}

export interface BulkJobDetail extends BulkJob {
  results: ScanSummary[]
  items: BulkItem[]
}

export interface BulkCreated {
  job_id: number
  /** upload only */
  total?: number
  /** upload only: more than 500 URLs were supplied */
  truncated?: boolean
}

export interface TyposquatHit {
  domain: string
  technique: string
  resolves?: boolean | null
  ip?: string | null
  /** has MX records */
  mx?: boolean | null
}

export interface TyposquatResult {
  /** registered domain that was permuted */
  domain: string
  total_generated?: number | null
  results?: TyposquatHit[] | null
}

export interface Report {
  id: number
  /** normalized URL (compare with ScanResult.normalized_url, not .url) */
  url: string
  domain?: string | null
  label: 'phishing' | 'legitimate'
  brand?: string | null
  comment?: string | null
  reporter?: string | null
  created_at?: string | null
  phishing_votes?: number | null
  legitimate_votes?: number | null
  status?: ReportStatus | string | null
  /** null right after POST /api/reports (scan runs in background, filled seconds later) */
  scan_id?: number | null
}

export interface WatchItem {
  id: number
  target: string
  label?: string | null
  interval_minutes?: number | null
  monitor_typosquats?: boolean | null
  created_at?: string | null
  last_checked?: string | null
  last_risk?: number | null
  last_verdict?: Verdict | null
  last_scan_id?: number | null
  change?: 'up' | 'down' | 'same' | null
  /** number of alerts raised for this item */
  alerts?: number | null
  /** number of known (resolving) typosquats */
  known_typosquats?: number | null
}

export interface WatchCheck {
  t: string
  risk_score: number
  verdict?: Verdict | null
  scan_id?: number | null
}

export interface WatchHistory {
  item?: WatchItem | null
  /** oldest first */
  checks?: WatchCheck[] | null
  /** typosquats from the latest check that monitored them */
  typosquats?: TyposquatHit[] | null
}

export interface Alert {
  id: number
  /** high_risk_scan | suspicious_scan | verdict_change | typosquat_new | typosquat_baseline | community_verified | community_rejected | bulk_complete | system | ... */
  type?: string | null
  severity?: AlertSeverity | string | null
  title: string
  detail?: string | null
  created_at?: string | null
  read?: boolean | null
  scan_id?: number | null
  watch_id?: number | null
}

export interface Feed {
  name: string
  /** download source actually used */
  url?: string | null
  homepage?: string | null
  /** urls | domains | mixed | phishtank */
  kind?: string | null
  entries?: number | null
  last_updated?: string | null
  last_attempt?: string | null
  /** ok | stale | error | never */
  status?: string | null
  error?: string | null
}

export interface NameValue {
  name: string
  value: number
}

export interface FeedStats {
  total_entries?: number | null
  unique_hosts?: number | null
  by_feed?: Record<string, number> | null
  top_domains_tlds?: NameValue[] | null
  top_registered_domains?: NameValue[] | null
  /** estimated from a sample (targets_estimated=true) */
  top_targets?: NameValue[] | null
  computed_at?: string | null
  targets_estimated?: boolean | null
}

export interface FeedsResponse {
  feeds?: Feed[] | null
  stats?: FeedStats | null
  /** a background refresh is in progress */
  refreshing?: boolean | null
}

export interface FeedsRefreshResult {
  /** "ok" | "running" (still going after 120 s, continues in background) | "error: ..." */
  status: string
  feeds?: Feed[] | null
  stats?: FeedStats | null
}

export interface FeedEntry {
  url: string
  domain?: string | null
  feed?: string | null
  target?: string | null
}

export interface FeedSearchResult {
  items: FeedEntry[]
  total: number
  q: string
}

export interface Overview {
  range?: Range
  total_scans?: number | null
  phishing?: number | null
  suspicious?: number | null
  legitimate?: number | null
  /** 0-100 PERCENTAGE of (phishing + suspicious) / total. Use fmtPct(v, 1, false). */
  detection_rate?: number | null
  avg_risk?: number | null
  avg_duration_ms?: number | null
  unique_domains?: number | null
  blacklisted_hits?: number | null
  brands_impersonated?: number | null
  reports_total?: number | null
  reports_verified?: number | null
  watch_count?: number | null
  unread_alerts?: number | null
  /** Percent change vs the previous equal period (0 for range=all, 100 when the previous period was empty). */
  delta?: { total_scans?: number | null; phishing?: number | null; avg_risk?: number | null } | null
}

export interface TimePoint {
  /** bucket start, ISO UTC */
  t: string
  total?: number
  phishing?: number
  suspicious?: number
  legitimate?: number
  /** NOTE: backend sends 0 (not null) for empty buckets - check `total` before plotting. */
  avg_risk?: number | null
}

export interface Distribution {
  verdicts?: NameValue[] | null
  /** buckets "0-10" ... "90-100" */
  risk_histogram?: { bucket: string; count: number }[] | null
  tlds?: NameValue[] | null
  countries?: { code?: string | null; name?: string | null; value: number }[] | null
  brands?: NameValue[] | null
  sources?: NameValue[] | null
  techniques?: NameValue[] | null
  checks_failed?: { id: string; name?: string | null; count: number }[] | null
  top_domains?: { domain: string; count: number; avg_risk?: number | null }[] | null
  /** weekday 0 = Monday ... 6 = Sunday, hour 0-23 UTC; all 168 cells present */
  heatmap?: { weekday: number; hour: number; count: number }[] | null
  ssl?: NameValue[] | null
  domain_age?: { bucket: string; count: number }[] | null
}

export interface ModelMetrics {
  name: string
  /** metrics are 0-1 ratios */
  accuracy?: number | null
  precision?: number | null
  recall?: number | null
  f1?: number | null
  roc_auc?: number | null
  train_time_s?: number | null
  predict_time_ms?: number | null
  cv_f1_mean?: number | null
  cv_f1_std?: number | null
  /** [[tn, fp], [fn, tp]] */
  confusion_matrix?: number[][] | null
  roc_curve?: { fpr?: number[]; tpr?: number[] } | null
  pr_curve?: { precision?: number[]; recall?: number[] } | null
  file?: string | null
}

export interface ModelInfo {
  version?: string | null
  trained_at?: string | null
  dataset?: {
    name?: string | null
    source?: string | null
    total?: number | null
    phishing?: number | null
    legitimate?: number | null
    train_size?: number | null
    test_size?: number | null
    openphish_urls?: number | null
    tranco_domains?: number | null
    notes?: string | null
  } | null
  best_model?: string | null
  models?: ModelMetrics[] | null
  feature_importance?: { feature: string; label?: string | null; importance: number }[] | null
  feature_stats?: { feature: string; label?: string | null; mean_phishing: number; mean_legitimate: number }[] | null
  feature_names?: string[] | null
  total_training_time_s?: number | null
  /** set when metrics could not be loaded */
  error?: string | null
  live?: {
    predictions?: number | null
    /** 0-1 */
    avg_probability?: number | null
    /** 0-1, null when no data */
    agreement_rate?: number | null
    /** 0-1 vs verified/rejected reports, null when no data */
    feedback_accuracy?: number | null
    feedback_samples?: number | null
    verdicts?: Partial<Record<Verdict, number>> | null
  } | null
}

export interface Performance {
  range?: Range
  /** number of scans in range */
  count?: number | null
  p50_ms?: number | null
  p95_ms?: number | null
  p99_ms?: number | null
  max_ms?: number | null
  avg_ms?: number | null
  throughput_per_hour?: { t: string; count: number }[] | null
  /** total errored checks */
  errors?: number | null
  /** rate is a 0-1 ratio */
  check_error_rates?: { id: string; rate: number; errors?: number | null; total?: number | null }[] | null
}

export interface EventItem {
  id: number
  type: string
  message?: string | null
  meta?: Record<string, unknown> | null
  created_at?: string | null
}

/** GET /api/events: Paged + `types` = every distinct event type in the DB (use it for filters). */
export interface EventsPage extends Paged<EventItem> {
  types?: string[] | null
}

export interface Settings {
  suspicious_threshold: number
  phishing_threshold: number
  enable_network_checks: boolean
  enable_screenshots: boolean
  timeout_s: number
  /** masked "****abcd" on GET; send "" to clear, omit (or send the masked value) to keep */
  virustotal_api_key?: string | null
  google_safe_browsing_api_key?: string | null
  /** 0 = keep forever */
  retention_days?: number | null
}

export interface LiveStats {
  /** newest 10 */
  last_scans?: ScanSummary[] | null
  scans_last_minute?: number | null
  scans_last_hour?: number | null
  unread_alerts?: number | null
  server_time?: string | null
}

export interface DeleteResult {
  deleted?: boolean
  id?: number
  [k: string]: unknown
}

export interface SeedStatus {
  running: boolean
  last?: { status?: string; scans?: number; phishing_urls?: number; at?: string } | null
  demo_scans?: number | null
}

export interface AdminSeedResult extends Partial<SeedStatus> {
  /** started | skipped | already_running */
  status: string
  deep?: boolean
  reason?: string
}

// ---------------------------------------------------------------------------

export class ApiError extends Error {
  status: number
  body: unknown
  constructor(status: number, message: string, body?: unknown) {
    super(message)
    this.status = status
    this.body = body
  }
}

export type QueryValue = string | number | boolean | null | undefined | readonly (string | number)[]
export type Query = Record<string, QueryValue>

/**
 * Query-string builder. Skips undefined/null/'' values and empty arrays; arrays are joined with commas
 * (the backend accepts comma-separated lists for verdict/source/tld/type). Accepts any plain object
 * (e.g. a filters interface) so callers don't need casts. Returns "" or "?a=1&b=2".
 */
export function qs(params?: object | null): string {
  if (!params) return ''
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params as Record<string, unknown>)) {
    if (v === undefined || v === null || v === '') continue
    if (Array.isArray(v)) {
      const parts = v.filter((x) => x !== undefined && x !== null && x !== '').map(String)
      if (parts.length) sp.set(k, parts.join(','))
      continue
    }
    if (typeof v === 'object') continue
    sp.set(k, String(v))
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

/** Encode one path segment (ids, domains, tokens). */
export const enc = (v: string | number) => encodeURIComponent(String(v))

function errorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === 'object' && 'detail' in body) {
    const d = (body as { detail: unknown }).detail
    if (typeof d === 'string') return d
    if (Array.isArray(d) && d.length) {
      const first = d[0] as { msg?: string }
      if (first?.msg) return first.msg
    }
  }
  return fallback
}

/** Base fetch helper: JSON (or FormData) in, parsed JSON out, throws ApiError on non-2xx / network failure. */
export async function request<T>(method: string, path: string, body?: unknown, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  let payload: BodyInit | undefined
  if (body instanceof FormData) payload = body
  else if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    payload = JSON.stringify(body)
  }
  // extra headers (e.g. X-API-Key) are merged, not replaced
  if (init?.headers) new Headers(init.headers).forEach((v, k) => (headers[k] = v))
  let res: Response
  try {
    res = await fetch(path, { ...init, method, headers, body: payload })
  } catch {
    throw new ApiError(0, 'Cannot reach the PhishGuard API. Is the backend running on :8000?')
  }
  const text = await res.text()
  let data: unknown = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
  }
  if (!res.ok) throw new ApiError(res.status, errorMessage(data, `${res.status} ${res.statusText}`), data)
  return data as T
}

const get = <T,>(p: string, q?: object | null) => request<T>('GET', `/api${p}${qs(q)}`)
const post = <T,>(p: string, b?: unknown) => request<T>('POST', `/api${p}`, b ?? {})
const put = <T,>(p: string, b?: unknown) => request<T>('PUT', `/api${p}`, b)
const patch = <T,>(p: string, b?: unknown) => request<T>('PATCH', `/api${p}`, b)
const del = <T,>(p: string) => request<T>('DELETE', `/api${p}`)

/** Verb helpers; `p` is the path AFTER "/api" (e.g. "/scans/1"). GET takes a query object (see `qs`). */
export const http = { get, post, put, patch, del }

export type ScanSort = 'created_at' | 'risk_score' | 'domain' | 'duration_ms' | 'confidence'

export interface ScanFilters {
  /** substring of url / domain / brand / notes */
  q?: string
  /** comma list or array, e.g. "phishing,suspicious" */
  verdict?: string | readonly string[]
  source?: string | readonly string[]
  tld?: string | readonly string[]
  /** impersonated brand (case-insensitive exact) */
  brand?: string
  /** exact tag */
  tag?: string
  /** host or registered domain */
  domain?: string
  blacklisted?: boolean | 'true' | 'false'
  min_risk?: number | string
  max_risk?: number | string
  /** YYYY-MM-DD or ISO */
  date_from?: string
  date_to?: string
  sort?: ScanSort | string
  order?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

export const api = {
  health: () => get<Health>('/health'),

  scan: (url: string, deep = true, source: ScanSource = 'web') => post<ScanResult>('/scan', { url, deep, source }),
  scans: (f: ScanFilters = {}) => get<Paged<ScanSummary>>('/scans', f),
  getScan: (id: Id) => get<ScanResult>(`/scans/${enc(id)}`),
  deleteScan: (id: Id) => del<DeleteResult>(`/scans/${enc(id)}`),
  /** Creates and returns a NEW scan (new id); tags are carried over. */
  rescan: (id: Id, deep = true) => post<ScanResult>(`/scans/${enc(id)}/rescan${qs({ deep })}`),
  patchScan: (id: Id, body: { tags?: string[]; notes?: string | null }) => patch<ScanResult>(`/scans/${enc(id)}`, body),
  compare: (id: Id, other: Id) => get<CompareResult>(`/scans/${enc(id)}/compare/${enc(other)}`),
  /** Download URL for <a href download>. Same filters as `scans` (pagination dropped; sort limited to created_at|risk_score). */
  exportUrl: (format: 'csv' | 'json', f: ScanFilters = {}) => {
    const { page: _p, page_size: _ps, sort, ...rest } = f
    void _p
    void _ps
    const s = sort === 'created_at' || sort === 'risk_score' ? sort : undefined
    return `/api/scans/export${qs({ format, ...rest, sort: s })}`
  },

  domain: (domain: string) => get<DomainDetail>(`/domains/${enc(domain)}`),

  bulkCreate: (urls: string[], name?: string) => post<BulkCreated>('/bulk', { urls, name }),
  bulkUpload: (file: File, name?: string) => {
    const fd = new FormData()
    fd.append('file', file)
    if (name) fd.append('name', name)
    return request<BulkCreated>('POST', '/api/bulk/upload', fd)
  },
  bulkJobs: () => get<BulkJob[]>('/bulk'),
  bulkJob: (id: Id) => get<BulkJobDetail>(`/bulk/${enc(id)}`),

  extract: (text: string) => post<{ urls: string[] }>('/extract', { text }),
  typosquat: (domain: string, limit?: number) => get<TyposquatResult>('/typosquat', { domain, limit }),

  /** The reporter's label counts as the first vote; `scan_id` is null until the background scan finishes. */
  createReport: (b: { url: string; label: 'phishing' | 'legitimate'; brand?: string; comment?: string; reporter?: string }) =>
    post<Report>('/reports', b),
  reports: (status?: string, page = 1, opts: { q?: string; page_size?: number } = {}) =>
    get<Paged<Report>>('/reports', { status, page, ...opts }),
  report: (id: Id) => get<Report>(`/reports/${enc(id)}`),
  vote: (id: Id, vote: 'phishing' | 'legitimate', voter?: string) => post<Report>(`/reports/${enc(id)}/vote`, { vote, voter }),

  watchAdd: (b: { target: string; interval_minutes: number; monitor_typosquats: boolean; label?: string }) =>
    post<WatchItem>('/watchlist', b),
  watchlist: () => get<WatchItem[]>('/watchlist'),
  watchDelete: (id: Id) => del<DeleteResult>(`/watchlist/${enc(id)}`),
  /** Runs the check synchronously and returns the updated item. */
  watchRun: (id: Id) => post<WatchItem>(`/watchlist/${enc(id)}/run`),
  watchHistory: (id: Id) => get<WatchHistory>(`/watchlist/${enc(id)}/history`),

  /** Plain array, newest first (default limit 200). */
  alerts: (unread?: boolean, opts: { severity?: AlertSeverity | string; limit?: number } = {}) =>
    get<Alert[]>('/alerts', { unread, ...opts }),
  alertRead: (id: Id) => post<Alert>(`/alerts/${enc(id)}/read`),
  alertsReadAll: () => post<{ updated: number }>('/alerts/read-all'),

  feeds: () => get<FeedsResponse>('/feeds'),
  /** Waits up to 120 s. Always HTTP 200 - inspect `status` ("ok" | "running" | "error: ..."). */
  feedsRefresh: () => post<FeedsRefreshResult>('/feeds/refresh'),
  feedsSearch: (q: string, limit?: number) => get<FeedSearchResult>('/feeds/search', { q, limit }),

  overview: (range: Range) => get<Overview>('/analytics/overview', { range }),
  timeseries: (range: Range, bucket?: 'hour' | 'day') => get<TimePoint[]>('/analytics/timeseries', { range, bucket }),
  distribution: (range: Range) => get<Distribution>('/analytics/distribution', { range }),
  model: () => get<ModelInfo>('/analytics/model'),
  performance: (range: Range) => get<Performance>('/analytics/performance', { range }),

  /** `type` accepts a comma list; `q` searches the message. */
  events: (type?: string, page = 1, page_size = 50, q?: string) => get<EventsPage>('/events', { type, page, page_size, q }),

  settings: () => get<Settings>('/settings'),
  saveSettings: (s: Partial<Settings>) => put<Settings>('/settings', s),

  live: () => get<LiveStats>('/stats/live'),

  /** Demo data: runs in the background (deep=true enables network checks). */
  adminSeed: (force = false, deep = false) => post<AdminSeedResult>(`/admin/seed${qs({ force, deep })}`),
  adminSeedStatus: () => get<SeedStatus>('/admin/seed'),
  /** Wipes all data except settings; reseed=true loads demo data afterwards. */
  adminReset: (reseed = false, deep = false) => post<{ status: string; reseed: boolean }>(`/admin/reset${qs({ reseed, deep })}`),
}

/** Normalise list-ish responses: accepts T[] or {items: T[]} or {results: T[]}. */
export function asList<T>(v: unknown): T[] {
  if (Array.isArray(v)) return v as T[]
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>
    for (const k of ['items', 'results', 'data', 'entries', 'jobs', 'alerts']) {
      if (Array.isArray(o[k])) return o[k] as T[]
    }
  }
  return []
}
