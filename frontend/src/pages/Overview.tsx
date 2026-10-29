import { useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Activity, BrainCircuit, Radio, ScanSearch } from 'lucide-react'
import { api, asList, type Alert, type ScanSummary } from '../api/client'
import type { OverviewV2 } from '../api/client_v2'
import { Card, CardHeader, PageHeader } from '../components/Card'
import { ChartCard, ChartTooltip, Legend } from '../components/ChartCard'
import { Kpi } from '../components/Kpi'
import { RangeSelect } from '../components/RangeSelect'
import { RiskPill, VerdictBadge } from '../components/VerdictBadge'
import { EmptyState } from '../components/EmptyState'
import { SkeletonRows } from '../components/Skeleton'
import { Button, Chip, ErrorBox } from '../components/ui'
import { bucketFor, useRange } from '../lib/hooks'
import { ACCENT, VERDICT_COLOR, VERDICTS, VERDICT_LABEL, cx, flagEmoji, fmtCompact, fmtMs, fmtNum, fmtPct, fmtRel, fmtTick, isVerdict, truncate } from '../lib/format'

const sevColor: Record<string, string> = { critical: 'bg-rose-500', warning: 'bg-amber-500', info: 'bg-sky-500' }

export default function Overview() {
  const [range, setRange] = useRange()
  const bucket = bucketFor(range)
  const nav = useNavigate()

  const ov = useQuery({ queryKey: ['overview', range], queryFn: () => api.overview(range) })
  const ts = useQuery({ queryKey: ['timeseries', range, bucket], queryFn: () => api.timeseries(range, bucket) })
  const dist = useQuery({ queryKey: ['distribution', range], queryFn: () => api.distribution(range) })
  const live = useQuery({ queryKey: ['live'], queryFn: api.live, refetchInterval: 5000 })
  const alerts = useQuery({ queryKey: ['alerts', 'recent'], queryFn: () => api.alerts() })
  const model = useQuery({ queryKey: ['model'], queryFn: api.model, staleTime: 120_000 })
  const health = useQuery({ queryKey: ['health'], queryFn: api.health, retry: false })

  const o = ov.data as OverviewV2 | undefined
  const series = useMemo(() => asList<{ t: string; total?: number; phishing?: number; suspicious?: number; legitimate?: number; avg_risk?: number | null }>(ts.data), [ts.data])
  const spark = (k: 'total' | 'phishing' | 'suspicious' | 'legitimate' | 'avg_risk') => series.map((p) => Number(p[k] ?? 0))
  const d = dist.data
  const verdicts = (d?.verdicts ?? []).filter((v) => v && v.value > 0)
  const verdictTotal = verdicts.reduce((s, v) => s + v.value, 0)
  const total = o?.total_scans ?? 0
  const share = (n?: number | null) => (total > 0 && n != null ? `${((n / total) * 100).toFixed(1)}% of scans` : undefined)
  const best = model.data?.models?.find((m) => m.name === model.data?.best_model) ?? model.data?.models?.[0]
  const loading = ov.isLoading

  return (
    <div className="space-y-4">
      <PageHeader
        title="Overview"
        subtitle="Real-time phishing detection activity and risk posture"
        actions={
          <>
            <RangeSelect value={range} onChange={setRange} />
            <Link to="/scan">
              <Button variant="primary" icon={<ScanSearch className="size-4" />}>
                New scan
              </Button>
            </Link>
          </>
        }
      />
      {ov.error && <ErrorBox error={ov.error} onRetry={() => ov.refetch()} />}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Kpi loading={loading} label="Total scans" value={fmtNum(o?.total_scans)} delta={o?.delta?.total_scans} goodWhen="neutral" spark={spark('total')} color={ACCENT} />
        <Kpi loading={loading} label="Phishing" value={fmtNum(o?.phishing)} sub={share(o?.phishing)} delta={o?.delta?.phishing} goodWhen="down" spark={spark('phishing')} color={VERDICT_COLOR.phishing} />
        <Kpi loading={loading} label="Suspicious" value={fmtNum(o?.suspicious)} sub={share(o?.suspicious)} spark={spark('suspicious')} color={VERDICT_COLOR.suspicious} />
        <Kpi loading={loading} label="Legitimate" value={fmtNum(o?.legitimate)} sub={share(o?.legitimate)} spark={spark('legitimate')} color={VERDICT_COLOR.legitimate} />
        <Kpi loading={loading} label="Detection rate" value={fmtPct(o?.detection_rate, 1, false)} sub="phishing + suspicious" />
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Kpi loading={loading} label="Avg trust score" value={fmtNum(o?.avg_trust_score, 1)} sub="0-100 · higher is safer" />
        <Kpi loading={loading} label="Avg risk score" value={fmtNum(o?.avg_risk, 1)} delta={o?.delta?.avg_risk} goodWhen="down" spark={spark('avg_risk')} color="#8b5cf6" />
        <Kpi loading={loading} label="Avg scan time" value={fmtMs(o?.avg_duration_ms)} sub="end-to-end analysis" />
        <Kpi loading={loading} label="Unique domains" value={fmtNum(o?.unique_domains)} />
        <Kpi loading={loading} label="Blacklist hits" value={fmtNum(o?.blacklisted_hits)} sub="threat-feed matches" />
        <Kpi loading={loading} label="Brands impersonated" value={fmtNum(o?.brands_impersonated)} sub={o?.reports_total != null ? `${fmtNum(o.reports_total)} community reports` : undefined} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <ChartCard
          className="lg:col-span-2"
          title="Scans over time"
          subtitle={`By verdict · per ${bucket}`}
          loading={ts.isLoading}
          error={ts.error}
          onRetry={() => ts.refetch()}
          empty={series.length === 0}
          height={260}
          right={<Legend items={VERDICTS.map((v) => ({ label: VERDICT_LABEL[v], color: VERDICT_COLOR[v] }))} />}
        >
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={series} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
              <defs>
                {VERDICTS.map((v) => (
                  <linearGradient key={v} id={`ov-${v}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={VERDICT_COLOR[v]} stopOpacity={0.35} />
                    <stop offset="100%" stopColor={VERDICT_COLOR[v]} stopOpacity={0.05} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid vertical={false} strokeDasharray="3 3" />
              <XAxis dataKey="t" tickFormatter={(t) => fmtTick(String(t), bucket)} minTickGap={24} tickLine={false} />
              <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip labelFormatter={(l) => fmtTick(String(l), bucket)} />} />
              {(['legitimate', 'suspicious', 'phishing'] as const).map((v) => (
                <Area key={v} type="monotone" dataKey={v} name={VERDICT_LABEL[v]} stackId="1" stroke={VERDICT_COLOR[v]} strokeWidth={1.5} fill={`url(#ov-${v})`} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Verdict split" subtitle={`${fmtNum(verdictTotal)} scans`} loading={dist.isLoading} error={dist.error} empty={verdicts.length === 0} height={260}>
          <div className="relative h-full">
            <ResponsiveContainer width="100%" height="80%">
              <PieChart>
                <Pie data={verdicts} dataKey="value" nameKey="name" innerRadius="62%" outerRadius="90%" paddingAngle={2} stroke="none">
                  {verdicts.map((v) => (
                    <Cell key={v.name} fill={isVerdict(v.name) ? VERDICT_COLOR[v.name] : '#a1a1aa'} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-x-0 top-[40%] -translate-y-1/2 text-center">
              <div className="tnum text-2xl font-semibold">{fmtPct(o?.detection_rate, 0, false)}</div>
              <div className="label">detected</div>
            </div>
            <div className="mt-2 flex justify-center">
              <Legend
                items={verdicts.map((v) => ({
                  label: VERDICT_LABEL[v.name as keyof typeof VERDICT_LABEL] ?? v.name,
                  color: isVerdict(v.name) ? VERDICT_COLOR[v.name] : '#a1a1aa',
                  value: verdictTotal ? `${Math.round((v.value / verdictTotal) * 100)}%` : undefined,
                }))}
              />
            </div>
          </div>
        </ChartCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <ChartCard title="Risk score distribution" subtitle="Histogram of risk scores" loading={dist.isLoading} error={dist.error} empty={!d?.risk_histogram?.length}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={d?.risk_histogram ?? []} margin={{ top: 8, right: 4, left: -20, bottom: 0 }}>
              <CartesianGrid vertical={false} strokeDasharray="3 3" />
              <XAxis dataKey="bucket" tickLine={false} interval={0} tick={{ fontSize: 10 }} tickFormatter={(v: string) => String(v).split('-')[0]} />
              <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ fillOpacity: 0.06 }} />
              <Bar dataKey="count" name="Scans" radius={[3, 3, 0, 0]}>
                {(d?.risk_histogram ?? []).map((b, i) => {
                  const lo = parseInt(String(b.bucket), 10)
                  return <Cell key={i} fill={lo >= 65 ? VERDICT_COLOR.phishing : lo >= 35 ? VERDICT_COLOR.suspicious : VERDICT_COLOR.legitimate} />
                })}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Top impersonated brands" loading={dist.isLoading} error={dist.error} empty={!d?.brands?.length}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={(d?.brands ?? []).slice(0, 8)} layout="vertical" margin={{ top: 0, right: 16, left: 8, bottom: 0 }}>
              <XAxis type="number" hide allowDecimals={false} />
              <YAxis type="category" dataKey="name" width={84} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ fillOpacity: 0.06 }} />
              <Bar dataKey="value" name="Scans" fill={VERDICT_COLOR.phishing} radius={[0, 3, 3, 0]} barSize={14} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <Card>
          <CardHeader title="Top hosting countries" subtitle="By scanned domain IP geolocation" />
          {dist.isLoading ? (
            <SkeletonRows rows={6} />
          ) : !d?.countries?.length ? (
            <EmptyState compact title="No geo data yet" />
          ) : (
            <div className="space-y-2">
              {(() => {
                const list = d.countries.slice(0, 8)
                const max = Math.max(...list.map((c) => c.value), 1)
                return list.map((c, i) => (
                  <div key={i} className="text-sm">
                    <div className="flex items-center justify-between">
                      <span className="truncate">
                        <span className="mr-1.5">{flagEmoji(c.code)}</span>
                        {c.name || c.code || 'Unknown'}
                      </span>
                      <span className="tnum text-xs text-zinc-500">{fmtNum(c.value)}</span>
                    </div>
                    <div className="mt-1 h-1 rounded-full bg-zinc-100 dark:bg-zinc-800">
                      <div className="h-full rounded-full bg-indigo-500" style={{ width: `${(c.value / max) * 100}%` }} />
                    </div>
                  </div>
                ))
              })()}
            </div>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2" padded={false}>
          <div className="p-4 pb-2">
            <CardHeader
              title={
                <span className="flex items-center gap-2">
                  Live scan feed
                  <span className="relative flex size-2">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex size-2 rounded-full bg-emerald-500" />
                  </span>
                </span>
              }
              subtitle="Auto-refreshes every 5 seconds"
              right={
                <div className="flex gap-3 text-xs text-zinc-500">
                  <span>
                    <span className="tnum font-semibold text-zinc-900 dark:text-zinc-100">{fmtNum(live.data?.scans_last_minute)}</span> / min
                  </span>
                  <span>
                    <span className="tnum font-semibold text-zinc-900 dark:text-zinc-100">{fmtNum(live.data?.scans_last_hour)}</span> / hour
                  </span>
                </div>
              }
            />
          </div>
          {live.error ? (
            <div className="p-4 pt-0">
              <ErrorBox error={live.error} />
            </div>
          ) : live.isLoading ? (
            <div className="p-4 pt-0">
              <SkeletonRows rows={6} />
            </div>
          ) : !live.data?.last_scans?.length ? (
            <EmptyState compact icon={<Radio className="size-5" />} title="No scans yet" description="Scan a URL to see it appear here." />
          ) : (
            <ul className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
              {live.data.last_scans.slice(0, 10).map((s: ScanSummary) => (
                <li key={s.id} onClick={() => nav(`/scans/${s.id}`)} className="flex cursor-pointer items-center gap-3 px-4 py-2 hover:bg-zinc-50 dark:hover:bg-zinc-800/40">
                  <div className="w-24 shrink-0">
                    <VerdictBadge verdict={s.verdict} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-xs text-zinc-800 dark:text-zinc-200" title={s.url}>
                      {truncate(s.url, 80)}
                    </div>
                    <div className="mt-0.5 flex items-center gap-2 text-[11px] text-zinc-500">
                      {s.country_code && <span>{flagEmoji(s.country_code)} {s.country_code}</span>}
                      {s.brand && <Chip tone="rose">{s.brand}</Chip>}
                      {s.blacklisted && <Chip tone="rose">blacklisted</Chip>}
                      {s.source && <span>via {s.source}</span>}
                    </div>
                  </div>
                  <RiskPill score={s.risk_score} />
                  <span className="hidden w-16 shrink-0 text-right text-xs text-zinc-500 sm:block">{fmtRel(s.created_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Model health" icon={<BrainCircuit className="size-4" />} right={<Link to="/model" className="text-xs text-indigo-600 hover:underline dark:text-indigo-400">Model Lab →</Link>} />
            {model.isLoading ? (
              <SkeletonRows rows={3} />
            ) : model.error ? (
              <ErrorBox error={model.error} />
            ) : (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="font-medium">{model.data?.best_model ?? '—'}</span>
                  <Chip tone={health.data?.model_loaded === false ? 'rose' : 'emerald'}>{health.data?.model_loaded === false ? 'not loaded' : 'loaded'}</Chip>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center">
                  {[
                    ['Accuracy', best?.accuracy],
                    ['F1', best?.f1],
                    ['ROC-AUC', best?.roc_auc],
                  ].map(([k, v]) => (
                    <div key={String(k)} className="rounded-md bg-zinc-50 py-2 dark:bg-zinc-800/50">
                      <div className="tnum text-base font-semibold">{v == null ? '—' : fmtPct(Number(v), 1)}</div>
                      <div className="label">{k}</div>
                    </div>
                  ))}
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-zinc-500">
                  <span>Version</span>
                  <span className="truncate text-right font-mono text-zinc-700 dark:text-zinc-300">{model.data?.version ?? health.data?.model_version ?? '—'}</span>
                  <span>Live predictions</span>
                  <span className="tnum text-right text-zinc-700 dark:text-zinc-300">{fmtCompact(model.data?.live?.predictions)}</span>
                  <span>Model agreement</span>
                  <span className="tnum text-right text-zinc-700 dark:text-zinc-300">{fmtPct(model.data?.live?.agreement_rate, 1, true)}</span>
                  <span>Feed entries</span>
                  <span className="tnum text-right text-zinc-700 dark:text-zinc-300">{fmtCompact(health.data?.feeds_entries)}</span>
                </div>
              </div>
            )}
          </Card>

          <Card padded={false}>
            <div className="p-4 pb-2">
              <CardHeader title="Recent alerts" icon={<Activity className="size-4" />} right={<Link to="/alerts" className="text-xs text-indigo-600 hover:underline dark:text-indigo-400">All →</Link>} />
            </div>
            {alerts.isLoading ? (
              <div className="p-4 pt-0">
                <SkeletonRows rows={3} />
              </div>
            ) : asList<Alert>(alerts.data).length === 0 ? (
              <EmptyState compact title="No alerts" description="Watchlist changes and critical detections appear here." />
            ) : (
              <ul className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
                {asList<Alert>(alerts.data)
                  .slice(0, 5)
                  .map((a) => (
                    <li key={a.id}>
                      <Link to={a.scan_id ? `/scans/${a.scan_id}` : '/alerts'} className="flex gap-2 px-4 py-2 hover:bg-zinc-50 dark:hover:bg-zinc-800/40">
                        <span className={cx('mt-1.5 size-1.5 shrink-0 rounded-full', sevColor[a.severity ?? 'info'] ?? 'bg-zinc-400')} />
                        <span className="min-w-0">
                          <span className={cx('block truncate text-sm', !a.read && 'font-medium')}>{a.title}</span>
                          <span className="block text-xs text-zinc-500">{fmtRel(a.created_at)}</span>
                        </span>
                      </Link>
                    </li>
                  ))}
              </ul>
            )}
          </Card>
        </div>
      </div>
    </div>
  )
}
