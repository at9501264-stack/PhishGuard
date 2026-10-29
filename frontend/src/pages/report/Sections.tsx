import { useMemo, useState, type ReactNode } from 'react'
import { Bar, BarChart, CartesianGrid, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ArrowDown, Check as CheckIco, Copy, ExternalLink, Globe, ImageOff, Lock, MapPin, Server, ShieldAlert, ShieldCheck, ThumbsDown, ThumbsUp } from 'lucide-react'
import type { Check, ScanResult } from '../../api/client'
import { Card, CardHeader, KV } from '../../components/Card'
import { ChartTooltip } from '../../components/ChartCard'
import { DataTable } from '../../components/DataTable'
import { EmptyState } from '../../components/EmptyState'
import { Meter } from '../../components/RiskGauge'
import { BoolIcon, StatusIcon } from '../../components/StatusIcon'
import { Button, Chip, ProgressBar } from '../../components/ui'
import { ACCENT, PALETTE, VERDICT_COLOR, copyText, cx, flagEmoji, fmtDate, fmtMs, fmtNum, fmtPct, parseDate, riskColor, titleCase } from '../../lib/format'
import { EnginesCard, PivotLink } from './V2Sections'

const CATEGORY_ORDER = ['lexical', 'domain', 'network', 'ssl', 'content', 'brand', 'reputation']
const CATEGORY_LABEL: Record<string, string> = {
  lexical: 'URL / Lexical',
  domain: 'Domain & WHOIS',
  network: 'Network & Hosting',
  ssl: 'SSL / TLS',
  content: 'HTTP & Content',
  brand: 'Brand impersonation',
  reputation: 'Reputation & Threat intel',
}

function yesNo(v: boolean | null | undefined, yes = 'Yes', no = 'No'): ReactNode {
  if (v == null) return null
  return v ? yes : no
}

function Section({ title, subtitle, children, right, className }: { title: ReactNode; subtitle?: ReactNode; children: ReactNode; right?: ReactNode; className?: string }) {
  return (
    <Card className={className}>
      <CardHeader title={title} subtitle={subtitle} right={right} />
      {children}
    </Card>
  )
}

function StatusCounts({ checks }: { checks: Check[] }) {
  const c = { pass: 0, warn: 0, fail: 0, info: 0, error: 0 } as Record<string, number>
  for (const ch of checks) c[ch.status] = (c[ch.status] ?? 0) + 1
  return (
    <div className="flex items-center gap-2.5 text-xs tnum">
      {(['fail', 'warn', 'pass', 'info', 'error'] as const).map((s) =>
        c[s] ? (
          <span key={s} className="inline-flex items-center gap-1 text-zinc-600 dark:text-zinc-400" title={s}>
            <StatusIcon status={s} className="size-3.5" />
            {c[s]}
          </span>
        ) : null,
      )}
    </div>
  )
}

// ---------------------------------------------------------------- Summary
export function SummaryTab({ scan }: { scan: ScanResult }) {
  const checks = scan.checks ?? []
  const [filter, setFilter] = useState<'all' | 'issues'>('all')
  const groups = useMemo(() => {
    const m = new Map<string, Check[]>()
    for (const c of checks) {
      if (filter === 'issues' && !(c.status === 'fail' || c.status === 'warn')) continue
      const k = c.category || 'other'
      m.set(k, [...(m.get(k) ?? []), c])
    }
    const order = (k: string) => {
      const i = CATEGORY_ORDER.indexOf(k)
      return i === -1 ? 99 : i
    }
    return [...m.entries()].sort((a, b) => order(a[0]) - order(b[0]))
  }, [checks, filter])
  const breakdown = scan.score_breakdown ?? []
  const keyFindings = checks.filter((c) => c.status === 'fail').sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0)).slice(0, 5)

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="space-y-4">
        <Section title="Score breakdown" subtitle="How the final risk score was composed">
          {breakdown.length === 0 ? (
            <EmptyState compact title="No breakdown available" />
          ) : (
            <div className="space-y-3">
              {breakdown.map((b, i) => (
                <div key={i}>
                  <div className="mb-1 flex items-baseline justify-between text-xs">
                    <span className="font-medium text-zinc-700 dark:text-zinc-300">{titleCase(b.component)}</span>
                    <span className="tnum text-zinc-500">
                      <span className="font-semibold text-zinc-900 dark:text-zinc-100">{fmtNum(b.score, 0)}</span>
                      {b.weight != null && <> · weight {b.weight <= 1 ? fmtPct(b.weight, 0) : fmtNum(b.weight, 1)}</>}
                    </span>
                  </div>
                  <ProgressBar value={b.score} color={riskColor(b.score)} />
                </div>
              ))}
            </div>
          )}
        </Section>
        <Section title="Key findings" subtitle="Highest-weight failed checks">
          {keyFindings.length === 0 ? (
            <div className="flex items-center gap-2 text-sm text-emerald-600 dark:text-emerald-400">
              <ShieldCheck className="size-4" /> No failed checks
            </div>
          ) : (
            <ul className="space-y-2">
              {keyFindings.map((c) => (
                <li key={c.id} className="flex gap-2 text-sm">
                  <StatusIcon status={c.status} className="mt-0.5" />
                  <span className="min-w-0">
                    <span className="font-medium">{c.name}</span>
                    {c.detail && <span className="block text-xs text-zinc-500">{c.detail}</span>}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>

      <Section
        className="lg:col-span-2"
        title={`Security checks (${checks.length})`}
        subtitle="Grouped by category"
        right={
          <div className="flex items-center gap-3">
            <StatusCounts checks={checks} />
            <select value={filter} onChange={(e) => setFilter(e.target.value as 'all' | 'issues')} className="no-print h-7 rounded border border-zinc-200 bg-white px-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900">
              <option value="all">All</option>
              <option value="issues">Issues only</option>
            </select>
          </div>
        }
      >
        {groups.length === 0 ? (
          <EmptyState compact title={checks.length ? 'No issues found' : 'No checks recorded'} />
        ) : (
          <div className="space-y-4">
            {groups.map(([cat, list]) => (
              <div key={cat} className="print-break">
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="label">{CATEGORY_LABEL[cat] ?? titleCase(cat)}</span>
                  <StatusCounts checks={list} />
                </div>
                <ul className="divide-y divide-zinc-100 rounded-md border border-zinc-100 dark:divide-zinc-800 dark:border-zinc-800">
                  {list.map((c) => (
                    <li key={c.id} className="flex items-start gap-2.5 px-3 py-2">
                      <StatusIcon status={c.status} className="mt-0.5" />
                      <div className="min-w-0 flex-1">
                        <div className="text-sm">{c.name}</div>
                        {c.detail && <div className="break-words text-xs text-zinc-500">{c.detail}</div>}
                      </div>
                      {c.weight != null && c.weight > 0 && (
                        <span className="tnum shrink-0 text-[11px] text-zinc-400" title="Check weight">
                          w{c.weight}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  )
}

// ---------------------------------------------------------------- ML
export function MlTab({ scan }: { scan: ScanResult }) {
  const ml = scan.ml ?? {}
  const expl = (ml.explanations ?? []).map((e) => {
    const signed = e.direction === 'safe' ? -Math.abs(e.impact) : e.direction === 'risk' ? Math.abs(e.impact) : e.impact
    return { name: e.label || titleCase(e.feature), impact: Number(signed.toFixed(4)), value: e.value }
  })
  expl.sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact))
  const perModel = (ml.per_model ?? []).map((m) => ({ name: m.name, probability: Math.round((m.probability ?? 0) * 1000) / 10 }))
  const features = Object.entries(scan.features ?? {})
  const prob = ml.probability_phishing

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <div className="label">Primary model</div>
          <div className="mt-1 text-lg font-semibold">{ml.model_name ?? '—'}</div>
          <div className="font-mono text-xs text-zinc-500">v{ml.model_version ?? '—'}</div>
        </Card>
        <Card>
          <div className="label">Phishing probability</div>
          <div className="tnum mt-1 text-lg font-semibold" style={{ color: riskColor(prob != null ? prob * 100 : null) }}>
            {prob == null ? '—' : fmtPct(prob, 1, true)}
          </div>
          <Meter value={prob ?? 0} />
        </Card>
        <Card>
          <div className="label">Ensemble agreement</div>
          {perModel.length ? (
            <>
              <div className="tnum mt-1 text-lg font-semibold">
                {perModel.filter((m) => m.probability >= 50).length} / {perModel.length}
              </div>
              <div className="text-xs text-zinc-500">models predict phishing (p ≥ 0.5)</div>
            </>
          ) : (
            <div className="mt-1 text-lg">—</div>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Section className="lg:col-span-3" title="Feature contributions" subtitle={<>Signed impact on the prediction · <span className="text-rose-500">risk →</span> / <span className="text-emerald-500">← safe</span></>}>
          {expl.length === 0 ? (
            <EmptyState compact title="No explanations available" />
          ) : (
            <div style={{ height: Math.max(200, expl.length * 30 + 30) }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={expl} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
                  <CartesianGrid horizontal={false} strokeDasharray="3 3" />
                  <XAxis type="number" tickLine={false} />
                  <YAxis type="category" dataKey="name" width={170} tickLine={false} axisLine={false} interval={0} tick={{ fontSize: 11 }} />
                  <ReferenceLine x={0} className="stroke-zinc-400" />
                  <Tooltip
                    cursor={{ fillOpacity: 0.06 }}
                    content={({ active, payload }) => {
                      const p = payload?.[0]?.payload as { name: string; impact: number; value: unknown } | undefined
                      if (!active || !p) return null
                      return (
                        <div className="rounded-md border border-zinc-200 bg-white px-2.5 py-2 text-xs shadow-md dark:border-zinc-700 dark:bg-zinc-900">
                          <div className="font-medium">{p.name}</div>
                          <div className="text-zinc-500">
                            value <span className="tnum font-medium text-zinc-900 dark:text-zinc-100">{String(p.value ?? '—')}</span>
                          </div>
                          <div className={p.impact >= 0 ? 'text-rose-500' : 'text-emerald-500'}>
                            impact {p.impact >= 0 ? '+' : ''}
                            {p.impact}
                          </div>
                        </div>
                      )
                    }}
                  />
                  <Bar dataKey="impact" radius={2} barSize={14}>
                    {expl.map((e, i) => (
                      <Cell key={i} fill={e.impact >= 0 ? VERDICT_COLOR.phishing : VERDICT_COLOR.legitimate} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Section>
        <Section className="lg:col-span-2" title="Per-model probability" subtitle="Phishing probability by classifier">
          {perModel.length === 0 ? (
            <EmptyState compact title="No per-model data" />
          ) : (
            <div style={{ height: 240 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={perModel} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                  <CartesianGrid vertical={false} strokeDasharray="3 3" />
                  <XAxis dataKey="name" tickLine={false} interval={0} tick={{ fontSize: 10 }} tickFormatter={(n: string) => n.replace('Logistic Regression', 'LogReg').replace('Gradient Boosting', 'GBoost').replace('Random Forest', 'RF').replace('Support Vector Machine', 'SVM').replace('Decision Tree', 'DTree')} />
                  <YAxis domain={[0, 100]} tickLine={false} axisLine={false} unit="%" />
                  <ReferenceLine y={50} strokeDasharray="4 4" className="stroke-zinc-400" />
                  <Tooltip content={<ChartTooltip valueFormatter={(v) => `${v.toFixed(1)}%`} />} cursor={{ fillOpacity: 0.06 }} />
                  <Bar dataKey="probability" name="P(phishing)" radius={[3, 3, 0, 0]} barSize={32}>
                    {perModel.map((m, i) => (
                      <Cell key={i} fill={m.name === ml.model_name ? ACCENT : PALETTE[(i + 1) % PALETTE.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Section>
      </div>

      <Section title={`Extracted features (${features.length})`} subtitle="Lexical URL features fed to the model">
        {features.length === 0 ? (
          <EmptyState compact title="No features recorded" />
        ) : (
          <div className="grid gap-x-6 sm:grid-cols-2 lg:grid-cols-3">
            {features.map(([k, v]) => (
              <div key={k} className="flex items-center justify-between border-b border-zinc-100 py-1.5 text-xs dark:border-zinc-800">
                <span className="truncate font-mono text-zinc-600 dark:text-zinc-400">{k}</span>
                <span className="tnum font-medium">{typeof v === 'number' ? fmtNum(v, Number.isInteger(v) ? 0 : 3) : String(v ?? '—')}</span>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  )
}

// ---------------------------------------------------------------- Domain
export function DomainTab({ scan }: { scan: ScanResult }) {
  const di = scan.domain_info ?? {}
  const w = di.whois ?? {}
  const dns = di.dns ?? {}
  const age = w.age_days
  const ageTone = age == null ? 'zinc' : age < 30 ? 'rose' : age < 365 ? 'amber' : 'emerald'
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section title="Domain" right={<Globe className="size-4 text-zinc-400" />}>
        <KV
          rows={[
            ['Domain', <span className="font-mono">{di.domain ?? scan.domain}</span>],
            ['Registered domain', <span className="font-mono">{di.registered_domain ?? scan.registered_domain}</span>],
            ['Subdomain', di.subdomain ? <span className="font-mono">{di.subdomain}</span> : null],
            ['TLD', di.tld ?? scan.tld ? <span className="font-mono">.{(di.tld ?? scan.tld ?? '').replace(/^\./, '')}</span> : null],
            ['IP address host', yesNo(di.is_ip)],
            ['Punycode / IDN', di.punycode ? <span className="font-mono">{di.punycode}</span> : di.is_ip ? null : 'No'],
          ]}
        />
      </Section>
      <Section title="Domain age" subtitle="Newly-registered domains are a strong phishing signal">
        <div className="flex items-baseline gap-2">
          <span className="tnum text-3xl font-semibold">{age == null ? '—' : fmtNum(age)}</span>
          <span className="text-sm text-zinc-500">days old</span>
          {age != null && <Chip tone={ageTone}>{age < 30 ? 'very new' : age < 365 ? 'under 1 year' : `${(age / 365).toFixed(1)} years`}</Chip>}
        </div>
        <div className="mt-4">
          <Meter value={Math.min(age ?? 0, 3650)} max={3650} color={age == null ? '#a1a1aa' : age < 30 ? VERDICT_COLOR.phishing : age < 365 ? VERDICT_COLOR.suspicious : VERDICT_COLOR.legitimate} />
          <div className="mt-1 flex justify-between text-[10px] text-zinc-400">
            <span>0</span>
            <span>1y</span>
            <span>5y</span>
            <span>10y+</span>
          </div>
        </div>
        {w.days_to_expiry != null && <div className="mt-3 text-xs text-zinc-500">Expires in <span className="tnum font-medium text-zinc-800 dark:text-zinc-200">{fmtNum(w.days_to_expiry)}</span> days</div>}
      </Section>
      <Section title="WHOIS">
        {Object.keys(w).length === 0 ? (
          <EmptyState compact title="WHOIS data unavailable" description="The registry may rate-limit lookups or the scan ran without network checks." />
        ) : (
          <KV
            rows={[
              ['Registrar', w.registrar ? <PivotLink field="registrar" value={w.registrar} /> : null],
              ['Registrant country', w.country ? `${flagEmoji(w.country)} ${w.country}` : null],
              ['Created', fmtDate(w.creation_date, false)],
              ['Updated', fmtDate(w.updated_date, false)],
              ['Expires', fmtDate(w.expiry_date, false)],
              ['Privacy protected', yesNo(w.privacy_protected)],
            ]}
          />
        )}
      </Section>
      <Section title="DNS records">
        {(['a', 'aaaa', 'mx', 'ns', 'txt'] as const).every((k) => !(dns[k]?.length)) ? (
          <EmptyState compact title="No DNS records" description="The domain may not resolve." />
        ) : (
          <div className="space-y-2.5">
            {(['a', 'aaaa', 'mx', 'ns', 'txt'] as const).map((k) => (
              <div key={k} className="flex gap-3">
                <span className="label w-10 shrink-0 pt-0.5">{k}</span>
                <div className="min-w-0 flex-1 space-y-0.5">
                  {dns[k]?.length ? (
                    dns[k]!.map((r, i) => (
                      <div key={i} className="break-all font-mono text-xs">
                        {r}
                      </div>
                    ))
                  ) : (
                    <span className="text-xs text-zinc-400">—</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  )
}

// ---------------------------------------------------------------- Geo
export function GeoTab({ scan }: { scan: ScanResult }) {
  const di = scan.domain_info ?? {}
  const g = di.geo ?? {}
  const hasLoc = g.lat != null && g.lon != null
  const bbox = hasLoc ? `${g.lon! - 2},${g.lat! - 1.5},${g.lon! + 2},${g.lat! + 1.5}` : ''
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section title="Hosting & network" right={<Server className="size-4 text-zinc-400" />}>
        <KV
          rows={[
            ['IP address', di.ip ? <span className="font-mono"><PivotLink field="ip" value={di.ip} /></span> : null],
            ['Country', g.country || g.country_code ? `${flagEmoji(g.country_code)} ${g.country ?? g.country_code}` : null],
            ['City', g.city],
            ['ASN', g.asn != null ? <span className="font-mono"><PivotLink field="asn" value={String(g.asn).startsWith('AS') ? String(g.asn) : `AS${g.asn}`} /></span> : null],
            ['Organisation', g.org],
            ['ISP', g.isp],
            ['Hosting / datacenter', g.hosting == null ? null : g.hosting ? <Chip tone="amber">Hosting provider</Chip> : <Chip>Residential / business</Chip>],
            ['Coordinates', hasLoc ? <span className="tnum font-mono">{g.lat!.toFixed(3)}, {g.lon!.toFixed(3)}</span> : null],
          ]}
        />
      </Section>
      <Section title="Location" right={<MapPin className="size-4 text-zinc-400" />}>
        {hasLoc ? (
          <div className="space-y-2">
            <iframe
              title="Server location map"
              className="h-64 w-full rounded-md border border-zinc-200 dark:border-zinc-800"
              loading="lazy"
              src={`https://www.openstreetmap.org/export/embed.html?bbox=${encodeURIComponent(bbox)}&layer=mapnik&marker=${g.lat},${g.lon}`}
            />
            <a className="inline-flex items-center gap-1 text-xs text-indigo-600 hover:underline dark:text-indigo-400" href={`https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=6/${g.lat}/${g.lon}`} target="_blank" rel="noreferrer">
              Open in OpenStreetMap <ExternalLink className="size-3" />
            </a>
          </div>
        ) : (
          <EmptyState compact title="No geolocation" description="IP geolocation was not available for this host." />
        )}
      </Section>
    </div>
  )
}

// ---------------------------------------------------------------- SSL
export function SslTab({ scan }: { scan: ScanResult }) {
  const s = scan.ssl ?? {}
  const nb = parseDate(s.not_before)
  const na = parseDate(s.not_after)
  let pctElapsed: number | null = null
  if (nb && na && na > nb) pctElapsed = Math.max(0, Math.min(100, ((Date.now() - nb.getTime()) / (na.getTime() - nb.getTime())) * 100))
  const status = !s.enabled ? 'No HTTPS' : s.valid ? 'Valid certificate' : 'Invalid certificate'
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section title="Certificate" right={<Lock className="size-4 text-zinc-400" />}>
        <div className="mb-4 flex items-center gap-2">
          {s.enabled && s.valid ? <ShieldCheck className="size-5 text-emerald-500" /> : <ShieldAlert className="size-5 text-rose-500" />}
          <span className="font-medium">{s.enabled == null ? 'SSL not checked' : status}</span>
          {s.self_signed && <Chip tone="rose">self-signed</Chip>}
        </div>
        <KV
          rows={[
            ['Issuer', s.issuer],
            ['Subject', s.subject],
            ['Protocol', s.protocol],
            ['Days left', s.days_left != null ? fmtNum(s.days_left) : null],
            ['Certificate age', s.age_days != null ? `${fmtNum(s.age_days)} days` : null],
            ['Valid from', fmtDate(s.not_before, false)],
            ['Valid until', fmtDate(s.not_after, false)],
            ['Self-signed', yesNo(s.self_signed)],
          ]}
        />
        {s.error && <div className="mt-3 rounded-md bg-rose-50 px-3 py-2 text-xs text-rose-700 dark:bg-rose-950/30 dark:text-rose-300">{s.error}</div>}
      </Section>
      <div className="space-y-4">
        <Section title="Validity timeline">
          {nb && na ? (
            <div>
              <div className="relative h-3 rounded-full bg-zinc-100 dark:bg-zinc-800">
                <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${pctElapsed ?? 0}%`, background: (s.days_left ?? 0) < 15 ? VERDICT_COLOR.suspicious : ACCENT }} />
                {pctElapsed != null && pctElapsed < 100 && <div className="absolute -top-1 h-5 w-0.5 bg-zinc-900 dark:bg-zinc-100" style={{ left: `${pctElapsed}%` }} title="Today" />}
              </div>
              <div className="mt-2 flex justify-between text-xs text-zinc-500">
                <span>{fmtDate(s.not_before, false)}</span>
                <span className="font-medium text-zinc-700 dark:text-zinc-300">today · {pctElapsed != null ? `${pctElapsed.toFixed(0)}% elapsed` : ''}</span>
                <span>{fmtDate(s.not_after, false)}</span>
              </div>
              <div className="mt-3 text-xs text-zinc-500">
                Short-lived, freshly issued certificates (e.g. &lt; 30 days old) are common on phishing kits using free CAs.
              </div>
            </div>
          ) : (
            <EmptyState compact title="No validity dates" />
          )}
        </Section>
        <Section title={`Subject alternative names (${s.san?.length ?? 0})`}>
          {s.san?.length ? (
            <div className="flex max-h-48 flex-wrap gap-1.5 overflow-y-auto">
              {s.san.map((n) => (
                <Chip key={n} className="font-mono">
                  {n}
                </Chip>
              ))}
            </div>
          ) : (
            <EmptyState compact title="No SAN entries" />
          )}
        </Section>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- HTTP
const HEADER_LABEL: Record<string, string> = {
  hsts: 'Strict-Transport-Security',
  csp: 'Content-Security-Policy',
  x_frame_options: 'X-Frame-Options',
  x_content_type_options: 'X-Content-Type-Options',
  referrer_policy: 'Referrer-Policy',
  permissions_policy: 'Permissions-Policy',
}

function Stat({ label, value, warn }: { label: string; value: ReactNode; warn?: boolean }) {
  return (
    <div className="rounded-md border border-zinc-100 px-3 py-2 dark:border-zinc-800">
      <div className="label">{label}</div>
      <div className={cx('tnum mt-0.5 text-lg font-semibold', warn && 'text-rose-600 dark:text-rose-400')}>{value ?? '—'}</div>
    </div>
  )
}

export function HttpTab({ scan }: { scan: ScanResult }) {
  const h = scan.http ?? {}
  const chain = h.redirect_chain ?? []
  const headers = h.security_headers ?? {}
  const headerKeys = Object.keys(HEADER_LABEL).concat(Object.keys(headers).filter((k) => !(k in HEADER_LABEL)))
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-3">
        <Section title="Response">
          <KV
            cols={1}
            rows={[
              ['Reachable', h.reachable == null ? null : <BoolIcon value={h.reachable} />],
              ['Status code', h.status_code != null ? <Chip tone={h.status_code < 300 ? 'emerald' : h.status_code < 400 ? 'amber' : 'rose'}>{h.status_code}</Chip> : null],
              ['Response time', fmtMs(h.response_ms)],
              ['Server', h.server],
              ['Page title', h.title],
              ['Final URL', h.final_url ? <span className="font-mono text-xs">{h.final_url}</span> : null],
              ['Page size', h.page_size_kb != null ? `${fmtNum(h.page_size_kb, 1)} KB` : null],
            ]}
          />
          {h.error && <div className="mt-3 rounded-md bg-rose-50 px-3 py-2 text-xs text-rose-700 dark:bg-rose-950/30 dark:text-rose-300">{h.error}</div>}
        </Section>
        <Section className="lg:col-span-2" title={`Redirect chain (${chain.length} hop${chain.length === 1 ? '' : 's'})`}>
          {chain.length === 0 ? (
            <EmptyState compact title="No redirects" description="The URL responded directly." />
          ) : (
            <ol className="relative space-y-0">
              {chain.map((hop, i) => (
                <li key={i} className="relative flex gap-3 pb-4 last:pb-0">
                  {i < chain.length - 1 && <span className="absolute left-[11px] top-6 h-[calc(100%-16px)] w-px bg-zinc-200 dark:bg-zinc-700" />}
                  <span className={cx('tnum relative z-[1] flex size-6 shrink-0 items-center justify-center rounded-full border text-[11px] font-semibold', i === chain.length - 1 ? 'border-indigo-500 bg-indigo-500 text-white' : 'border-zinc-300 bg-white dark:border-zinc-600 dark:bg-zinc-900')}>
                    {i + 1}
                  </span>
                  <div className="min-w-0 flex-1 pt-0.5">
                    <div className="break-all font-mono text-xs">{hop.url}</div>
                    <div className="mt-0.5 flex items-center gap-2 text-[11px] text-zinc-500">
                      {hop.status != null && <Chip tone={hop.status < 300 ? 'emerald' : hop.status < 400 ? 'amber' : 'rose'}>{hop.status}</Chip>}
                      {i < chain.length - 1 && (
                        <span className="inline-flex items-center gap-0.5">
                          <ArrowDown className="size-3" /> redirects
                        </span>
                      )}
                      {i === chain.length - 1 && <span>final destination</span>}
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </Section>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Security headers" subtitle={`${Object.values(headers).filter(Boolean).length} of ${headerKeys.length} present`}>
          {Object.keys(headers).length === 0 ? (
            <EmptyState compact title="Headers not available" />
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              {headerKeys.map((k) => (
                <div key={k} className={cx('flex items-center gap-2 rounded-md border px-3 py-2 text-xs', headers[k] ? 'border-emerald-200 bg-emerald-50/50 dark:border-emerald-900 dark:bg-emerald-500/5' : 'border-zinc-200 dark:border-zinc-800')}>
                  <BoolIcon value={headers[k] ?? false} />
                  <span className="truncate font-mono">{HEADER_LABEL[k] ?? k}</span>
                </div>
              ))}
            </div>
          )}
        </Section>
        <Section title="Technologies">
          {h.technologies?.length ? (
            <div className="flex flex-wrap gap-1.5">
              {h.technologies.map((t) => (
                <Chip key={t} tone="indigo">
                  {t}
                </Chip>
              ))}
            </div>
          ) : (
            <EmptyState compact title="No technologies detected" />
          )}
          {h.suspicious_js?.length ? (
            <div className="mt-4">
              <div className="label mb-1.5">Suspicious JavaScript</div>
              <div className="flex flex-wrap gap-1.5">
                {h.suspicious_js.map((t, i) => (
                  <Chip key={t?.id ?? i} tone="rose" className="font-mono">
                    <span title={t?.id ?? undefined}>{t?.description || t?.id || '—'}</span>
                  </Chip>
                ))}
              </div>
            </div>
          ) : null}
        </Section>
      </div>

      <Section title="Page content analysis">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-6">
          <Stat label="Forms" value={fmtNum(h.forms?.count)} />
          <Stat label="Password fields" value={fmtNum(h.forms?.password_fields)} warn={(h.forms?.password_fields ?? 0) > 0} />
          <Stat label="External form actions" value={fmtNum(h.forms?.external_actions)} warn={(h.forms?.external_actions ?? 0) > 0} />
          <Stat label="Login form" value={h.forms?.login_form == null ? '—' : h.forms.login_form ? 'Yes' : 'No'} warn={!!h.forms?.login_form} />
          <Stat label="Internal links" value={fmtNum(h.links?.internal)} />
          <Stat label="External links" value={fmtNum(h.links?.external)} />
          <Stat label="Null links" value={fmtNum(h.links?.null_links)} warn={(h.links?.null_links ?? 0) > 5} />
          <Stat label="External link ratio" value={h.links?.external_ratio != null ? fmtPct(h.links.external_ratio, 0) : '—'} warn={(h.links?.external_ratio ?? 0) > 0.6} />
          <Stat label="Iframes" value={fmtNum(h.iframes)} warn={(h.iframes ?? 0) > 0} />
          <Stat label="External scripts" value={fmtNum(h.external_scripts)} />
          <Stat label="Meta refresh" value={h.meta_refresh ? (h.meta_refresh.external ? 'External' : 'Yes') : h.reachable ? 'No' : '—'} warn={!!h.meta_refresh?.external} />
          <Stat label="External favicon" value={h.favicon_external == null ? '—' : h.favicon_external ? 'Yes' : 'No'} warn={!!h.favicon_external} />
        </div>
      </Section>
    </div>
  )
}

// ---------------------------------------------------------------- Brand
export function BrandTab({ scan }: { scan: ScanResult }) {
  const b = scan.brand ?? {}
  const sim = b.similarity ?? 0
  const details = b.details
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section title="Brand impersonation">
        {b.impersonated_brand ? (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <span className="flex size-12 items-center justify-center rounded-lg bg-rose-50 text-lg font-semibold uppercase text-rose-600 dark:bg-rose-500/10 dark:text-rose-400">
                {b.impersonated_brand.slice(0, 2)}
              </span>
              <div>
                <div className="text-lg font-semibold">{titleCase(b.impersonated_brand)}</div>
                <div className="text-xs text-zinc-500">Likely impersonated brand</div>
              </div>
              {b.technique && (
                <Chip tone="rose" className="ml-auto">
                  {b.technique}
                </Chip>
              )}
            </div>
            <Meter label="Similarity to the genuine brand domain" value={sim} color={sim > 0.8 ? VERDICT_COLOR.phishing : sim > 0.5 ? VERDICT_COLOR.suspicious : ACCENT} />
          </div>
        ) : (
          <EmptyState compact icon={<ShieldCheck className="size-5" />} title="No brand impersonation detected" description="The domain does not resemble any monitored brand." />
        )}
      </Section>
      <Section title="Techniques explained">
        <ul className="space-y-2 text-xs text-zinc-600 dark:text-zinc-400">
          {[
            ['typosquat', 'Misspelled domain, e.g. paypa1.com'],
            ['homoglyph', 'Look-alike characters, e.g. Cyrillic “а” for Latin “a”'],
            ['combosquat', 'Brand plus keywords, e.g. paypal-secure-login.com'],
            ['subdomain', 'Brand used as a subdomain, e.g. paypal.com.evil.io'],
            ['punycode', 'Internationalised (xn--) domain hiding look-alikes'],
            ['path', 'Brand name only in the URL path'],
            ['content', 'Brand detected in page title / content'],
          ].map(([k, d]) => (
            <li key={k} className={cx('flex gap-2 rounded px-2 py-1', b.technique === k && 'bg-rose-50 text-rose-700 dark:bg-rose-500/10 dark:text-rose-300')}>
              <span className="w-20 shrink-0 font-mono font-medium">{k}</span>
              <span>{d}</span>
            </li>
          ))}
        </ul>
        {details != null && details !== '' && (
          <div className="mt-3 rounded-md bg-zinc-50 p-2 font-mono text-[11px] text-zinc-600 dark:bg-zinc-800/50 dark:text-zinc-400">
            {typeof details === 'string' ? details : JSON.stringify(details, null, 2)}
          </div>
        )}
      </Section>
    </div>
  )
}

// ---------------------------------------------------------------- Reputation
export function ReputationTab({ scan, onVote, voting }: { scan: ScanResult; onVote: (v: 'phishing' | 'legitimate') => void; voting?: boolean }) {
  const r = scan.reputation ?? {}
  const sources = r.sources ?? []
  const c = r.community ?? {}
  const pv = c.phishing_votes ?? 0
  const lv = c.legitimate_votes ?? 0
  const listed = sources.filter((s) => s.listed).length
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <EnginesCard scan={scan} />
      <Section
        className="lg:col-span-2"
        title="Blacklist & threat-intelligence sources"
        subtitle={`${listed} of ${sources.length} sources flag this URL`}
        right={r.blacklisted ? <Chip tone="rose">Blacklisted</Chip> : r.blacklisted === false ? <Chip tone="emerald">Clean</Chip> : null}
      >
        <DataTable
          rows={sources}
          rowKey={(s, i) => `${s.name}-${i}`}
          dense
          empty={<EmptyState compact title="No reputation sources checked" />}
          columns={[
            { key: 'name', header: 'Source', render: (s) => <span className="font-medium">{s.name}</span> },
            {
              key: 'listed',
              header: 'Status',
              render: (s) => (s.listed ? <Chip tone="rose">Listed</Chip> : s.error ? <Chip>Lookup failed</Chip> : <Chip tone="emerald">Not listed</Chip>),
            },
            { key: 'detail', header: 'Detail', render: (s) => <span className="text-xs text-zinc-500">{s.detail ?? '—'}</span> },
          ]}
        />
      </Section>
      <Section title="Community verdict" subtitle="PhishTank-style crowd votes">
        <div className="mb-3 grid grid-cols-2 gap-2 text-center">
          <div className="rounded-md bg-rose-50 py-2 dark:bg-rose-500/10">
            <div className="tnum text-xl font-semibold text-rose-600 dark:text-rose-400">{pv}</div>
            <div className="label">phishing</div>
          </div>
          <div className="rounded-md bg-emerald-50 py-2 dark:bg-emerald-500/10">
            <div className="tnum text-xl font-semibold text-emerald-600 dark:text-emerald-400">{lv}</div>
            <div className="label">legitimate</div>
          </div>
        </div>
        {pv + lv > 0 && (
          <div className="mb-3 flex h-2 overflow-hidden rounded-full">
            <div style={{ width: `${(pv / (pv + lv)) * 100}%`, background: VERDICT_COLOR.phishing }} />
            <div style={{ width: `${(lv / (pv + lv)) * 100}%`, background: VERDICT_COLOR.legitimate }} />
          </div>
        )}
        <KV
          cols={1}
          rows={[
            ['Reports', fmtNum(c.reports ?? 0)],
            ['Status', c.status && c.status !== 'none' ? <Chip tone={c.status === 'verified' ? 'rose' : c.status === 'rejected' ? 'emerald' : 'zinc'}>{c.status}</Chip> : 'Not reported'],
          ]}
        />
        <div className="no-print mt-4 grid grid-cols-2 gap-2">
          <Button size="sm" variant="danger" icon={<ThumbsDown className="size-3.5" />} loading={voting} onClick={() => onVote('phishing')}>
            Phishing
          </Button>
          <Button size="sm" icon={<ThumbsUp className="size-3.5" />} loading={voting} onClick={() => onVote('legitimate')}>
            Legitimate
          </Button>
        </div>
      </Section>
    </div>
  )
}

// ---------------------------------------------------------------- Screenshot
export function ScreenshotTab({ scan }: { scan: ScanResult }) {
  const [failed, setFailed] = useState(false)
  const src = scan.screenshot_url
  return (
    <Section title="Page screenshot" subtitle="Preview image from the third-party thum.io screenshot service" right={src && !failed ? <a href={src} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-indigo-600 hover:underline dark:text-indigo-400">Open full size <ExternalLink className="size-3" /></a> : null}>
      {src && !failed ? (
        <div className="overflow-hidden rounded-md border border-zinc-200 dark:border-zinc-800">
          <div className="flex items-center gap-1.5 border-b border-zinc-200 bg-zinc-50 px-3 py-1.5 dark:border-zinc-800 dark:bg-zinc-900">
            <span className="size-2.5 rounded-full bg-zinc-300 dark:bg-zinc-700" />
            <span className="size-2.5 rounded-full bg-zinc-300 dark:bg-zinc-700" />
            <span className="size-2.5 rounded-full bg-zinc-300 dark:bg-zinc-700" />
            <span className="ml-2 truncate font-mono text-[11px] text-zinc-500">{scan.http?.final_url ?? scan.url}</span>
          </div>
          <img src={src} alt="Screenshot of the scanned page" className="w-full" onError={() => setFailed(true)} />
        </div>
      ) : (
        <EmptyState icon={<ImageOff className="size-5" />} title="No screenshot available" description="Screenshots require network checks and screenshot capture to be enabled in Settings, and the page must be reachable." />
      )}
    </Section>
  )
}

// ---------------------------------------------------------------- Raw
export function RawTab({ scan }: { scan: ScanResult }) {
  const [copied, setCopied] = useState(false)
  const json = useMemo(() => JSON.stringify(scan, null, 2), [scan])
  return (
    <Section
      title="Raw JSON"
      subtitle={`${fmtNum(json.length / 1024, 1)} KB`}
      right={
        <Button
          size="sm"
          icon={copied ? <CheckIco className="size-3.5" /> : <Copy className="size-3.5" />}
          onClick={async () => {
            if (await copyText(json)) {
              setCopied(true)
              setTimeout(() => setCopied(false), 1500)
            }
          }}
        >
          {copied ? 'Copied' : 'Copy'}
        </Button>
      }
    >
      <pre className="thin-scroll max-h-[70vh] overflow-auto rounded-md bg-zinc-50 p-3 font-mono text-[11px] leading-relaxed text-zinc-800 dark:bg-zinc-950 dark:text-zinc-300">{json}</pre>
    </Section>
  )
}
