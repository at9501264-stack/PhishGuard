import { useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api, type NameValue } from '../api/client'
import { apiV2, nameValues, pivotHref, qk, THREAT_TYPE_LABEL, TIERS } from '../api/client_v2'
import { Card, CardHeader, PageHeader } from '../components/Card'
import { ChartCard, ChartTooltip, Legend } from '../components/ChartCard'
import { DataTable } from '../components/DataTable'
import { Kpi } from '../components/Kpi'
import { RangeSelect } from '../components/RangeSelect'
import { EmptyState } from '../components/EmptyState'
import { Skeleton } from '../components/Skeleton'
import { ErrorBox } from '../components/ui'
import { RiskPill } from '../components/VerdictBadge'
import { bucketFor, useRange } from '../lib/hooks'
import { PALETTE, VERDICT_COLOR, VERDICTS, VERDICT_LABEL, fmtDate, fmtMs, fmtNum, fmtPct, fmtTick, flagEmoji, titleCase, truncate } from '../lib/format'

const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
const TIER_COLOR: Record<string, string> = { Trusted: '#10b981', Favorable: '#84cc16', Neutral: '#64748b', Questionable: '#f59e0b', Untrusted: '#f43f5e' }
const THREAT_COLOR: Record<string, string> = { malware: '#f43f5e', social_engineering: '#ec4899', unwanted_software: '#f59e0b', none: '#10b981' }
const FUNNEL_COLORS = ['#6366f1', '#7c3aed', '#9333ea', '#c026d3', '#db2777', '#e11d48']
const threatLabel = (n: string) => (THREAT_TYPE_LABEL as Record<string, string>)[n] ?? titleCase(n)

function nv(list: NameValue[] | null | undefined): NameValue[] {
  return (list ?? []).filter((x) => x && x.name != null).map((x) => ({ name: String(x.name), value: Number(x.value) || 0 }))
}

function Donut({
  data,
  colorFor,
  labelFor = titleCase,
  onSelect,
}: {
  data: NameValue[]
  colorFor?: (name: string, i: number) => string
  labelFor?: (name: string) => string
  onSelect?: (name: string) => void
}) {
  const total = data.reduce((s, d) => s + d.value, 0)
  const col = (n: string, i: number) => colorFor?.(n, i) ?? PALETTE[i % PALETTE.length]
  return (
    <div className="flex h-full flex-col">
      <div className="relative min-h-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius="58%" outerRadius="85%" paddingAngle={1} stroke="none" isAnimationActive={false}>
              {data.map((d, i) => (
                <Cell key={d.name} fill={col(d.name, i)} cursor={onSelect ? 'pointer' : undefined} onClick={onSelect ? () => onSelect(d.name) : undefined} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip labelFormatter={(l) => labelFor(String(l))} />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="tnum text-xl font-semibold">{fmtNum(total)}</span>
          <span className="label">total</span>
        </div>
      </div>
      <div className="mt-2">
        <Legend items={data.map((d, i) => ({ label: labelFor(d.name), color: col(d.name, i), value: fmtNum(d.value) }))} />
      </div>
    </div>
  )
}

function HBar({
  data,
  color = '#6366f1',
  valueLabel = 'Count',
  onSelect,
}: {
  data: NameValue[]
  color?: string
  valueLabel?: string
  onSelect?: (name: string) => void
}) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 12, bottom: 0, left: 0 }}>
        <CartesianGrid horizontal={false} />
        <XAxis type="number" allowDecimals={false} />
        <YAxis type="category" dataKey="name" width={110} tickFormatter={(v: string) => truncate(String(v), 16)} />
        <Tooltip content={<ChartTooltip />} cursor={{ fillOpacity: 0.06 }} />
        <Bar dataKey="value" name={valueLabel} fill={color} radius={[0, 3, 3, 0]} isAnimationActive={false}>
          {onSelect && data.map((d) => <Cell key={d.name} fill={color} cursor="pointer" onClick={() => onSelect(d.name)} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

/** Detection funnel: centred bars sized against the first stage, with % of all scanned. */
function Funnel({ stages }: { stages: NameValue[] }) {
  const top = Math.max(1, stages[0]?.value ?? 0)
  return (
    <div className="flex h-full flex-col justify-center gap-2">
      {stages.map((s, i) => {
        return (
          <div key={`${s.name}-${i}`} className="grid grid-cols-[minmax(0,12rem)_1fr_5.5rem] items-center gap-3 text-xs">
            <span className="truncate text-zinc-600 dark:text-zinc-400" title={s.name}>
              {/[_-]/.test(s.name) ? titleCase(s.name) : s.name}
            </span>
            <div className="h-6 rounded bg-zinc-100 dark:bg-zinc-800/70">
              <div
                className="mx-auto h-full rounded"
                style={{ width: `${Math.max((s.value / top) * 100, 1.5)}%`, background: FUNNEL_COLORS[Math.min(i, FUNNEL_COLORS.length - 1)] }}
                title={`${s.name}: ${fmtNum(s.value)}`}
              />
            </div>
            <span className="tnum text-right">
              <span className="font-medium">{fmtNum(s.value)}</span>
              {i > 0 && <span className="ml-1.5 text-zinc-400">{fmtPct((s.value / top) * 100, 0, false)}</span>}
            </span>
          </div>
        )
      })}
    </div>
  )
}

function Heatmap({ cells }: { cells: { weekday: number; hour: number; count: number }[] }) {
  const grid = useMemo(() => {
    const g: number[][] = Array.from({ length: 7 }, () => Array(24).fill(0))
    for (const c of cells) {
      if (c.weekday >= 0 && c.weekday < 7 && c.hour >= 0 && c.hour < 24) g[c.weekday][c.hour] += Number(c.count) || 0
    }
    return g
  }, [cells])
  const max = Math.max(1, ...grid.flat())
  return (
    <div className="thin-scroll overflow-x-auto">
      <div className="min-w-[560px]">
        <div className="grid gap-[3px]" style={{ gridTemplateColumns: '36px repeat(24, minmax(0, 1fr))' }}>
          <div />
          {Array.from({ length: 24 }).map((_, h) => (
            <div key={h} className="tnum text-center text-[10px] text-zinc-400">
              {h % 3 === 0 ? h : ''}
            </div>
          ))}
          {grid.map((row, d) => (
            <div key={d} className="contents">
              <div className="flex items-center text-[11px] text-zinc-500">{WEEKDAYS[d]}</div>
              {row.map((v, h) => (
                <div
                  key={h}
                  title={`${WEEKDAYS[d]} ${String(h).padStart(2, '0')}:00 — ${v} scans`}
                  className="aspect-square rounded-[3px] bg-zinc-100 dark:bg-zinc-800/70"
                  style={v > 0 ? { background: `rgba(99,102,241,${0.15 + 0.85 * (v / max)})` } : undefined}
                />
              ))}
            </div>
          ))}
        </div>
        <div className="mt-3 flex items-center justify-end gap-2 text-[11px] text-zinc-500">
          <span>Less</span>
          {[0.15, 0.35, 0.55, 0.75, 1].map((o) => (
            <span key={o} className="size-3 rounded-[3px]" style={{ background: `rgba(99,102,241,${o})` }} />
          ))}
          <span>More</span>
          <span className="tnum ml-2">max {fmtNum(max)}</span>
        </div>
      </div>
    </div>
  )
}

export default function AnalyticsPage() {
  const [range, setRange] = useRange('pg-range-analytics')
  const bucket = bucketFor(range)
  const ts = useQuery({ queryKey: ['timeseries', range, bucket], queryFn: () => api.timeseries(range, bucket) })
  const nav = useNavigate()
  const dist = useQuery({ queryKey: qk.distribution(range), queryFn: () => apiV2.distribution(range) })
  const funnel = useQuery({ queryKey: qk.funnel(range), queryFn: () => apiV2.funnel(range) })
  const perf = useQuery({ queryKey: ['performance', range], queryFn: () => api.performance(range) })

  const series = (Array.isArray(ts.data) ? ts.data : []).map((p) => ({
    t: p.t,
    phishing: p.phishing ?? 0,
    suspicious: p.suspicious ?? 0,
    legitimate: p.legitimate ?? 0,
    total: p.total ?? 0,
    // backend sends avg_risk 0 for empty buckets; treat those as gaps
    avg_risk: !p.total || p.avg_risk == null ? null : Number(p.avg_risk),
  }))
  const d = dist.data
  const tlds = nv(d?.tlds).slice(0, 12)
  const sources = nv(d?.sources)
  const techniques = nv(d?.techniques)
  const ssl = nv(d?.ssl)
  const domainAge = (d?.domain_age ?? []).map((x) => ({ name: String(x.bucket), value: Number(x.count) || 0 }))
  const checksFailed = (d?.checks_failed ?? []).slice(0, 10).map((c) => ({ name: c.name || titleCase(c.id), value: Number(c.count) || 0 }))
  const countries = (d?.countries ?? []).slice(0, 15)
  const countryMax = Math.max(1, ...countries.map((c) => Number(c.value) || 0))
  const topDomains = (d?.top_domains ?? []).slice(0, 15)
  const heat = d?.heatmap ?? []
  const threatTypes = nameValues(d?.threat_types)
  const tierRank = (n: string) => ((TIERS as string[]).indexOf(n) + 6) % 6 // unknown tiers last
  const tiers = nameValues(d?.tiers).sort((a, b) => tierRank(a.name) - tierRank(b.name))
  const categories = nameValues(d?.categories)
    .sort((a, b) => b.value - a.value)
    .slice(0, 12)
  const funnelStages = nameValues(funnel.data)

  const p = perf.data
  const throughput = (p?.throughput_per_hour ?? []).map((x) => ({ t: x.t, count: Number(x.count) || 0 }))
  const errRates = (p?.check_error_rates ?? [])
    .map((x) => ({ name: titleCase(x.id), value: Number(x.rate) <= 1 ? Number(x.rate) * 100 : Number(x.rate) }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 12)

  const tick = (v: string) => fmtTick(String(v), bucket)

  return (
    <div className="space-y-4">
      <PageHeader title="Analytics" subtitle="Detection trends, threat distribution and engine performance" actions={<RangeSelect value={range} onChange={setRange} />} />

      <div className="grid gap-4 lg:grid-cols-3">
        <ChartCard
          className="lg:col-span-2"
          title="Scans over time"
          subtitle={`Stacked by verdict · per ${bucket}`}
          loading={ts.isLoading}
          error={ts.error}
          onRetry={() => ts.refetch()}
          empty={series.length === 0}
          height={260}
          right={<Legend items={VERDICTS.map((v) => ({ label: VERDICT_LABEL[v], color: VERDICT_COLOR[v] }))} />}
        >
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={series} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickFormatter={tick} minTickGap={24} />
              <YAxis allowDecimals={false} />
              <Tooltip content={<ChartTooltip labelFormatter={(l) => tick(String(l))} />} />
              {VERDICTS.map((v) => (
                <Area key={v} type="monotone" dataKey={v} name={VERDICT_LABEL[v]} stackId="1" stroke={VERDICT_COLOR[v]} fill={VERDICT_COLOR[v]} fillOpacity={0.25} isAnimationActive={false} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="Average risk trend" subtitle="Mean risk score per bucket" loading={ts.isLoading} error={ts.error} empty={series.every((s) => s.avg_risk == null)} height={260}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={series} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickFormatter={tick} minTickGap={24} />
              <YAxis domain={[0, 100]} />
              <Tooltip content={<ChartTooltip labelFormatter={(l) => tick(String(l))} valueFormatter={(v) => v.toFixed(1)} />} />
              <Line type="monotone" dataKey="avg_risk" name="Avg risk" stroke="#6366f1" strokeWidth={2} dot={false} connectNulls isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      <Card>
        <CardHeader title="Activity heatmap" subtitle="Scans by weekday × hour (UTC)" />
        {dist.error ? <ErrorBox error={dist.error} onRetry={() => dist.refetch()} /> : dist.isLoading ? <Skeleton className="h-48 w-full" /> : heat.length === 0 ? <EmptyState compact title="No activity in this range" /> : <Heatmap cells={heat} />}
      </Card>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <ChartCard title="Top-level domains" subtitle="Most scanned TLDs" loading={dist.isLoading} error={dist.error} empty={tlds.length === 0} height={260}>
          <HBar data={tlds} color="#6366f1" valueLabel="Scans" />
        </ChartCard>
        <ChartCard title="Scan sources" subtitle="Where scans originated" loading={dist.isLoading} error={dist.error} empty={sources.length === 0} height={260}>
          <Donut data={sources} />
        </ChartCard>
        <ChartCard title="Impersonation techniques" subtitle="How brands were spoofed" loading={dist.isLoading} error={dist.error} empty={techniques.length === 0} height={260}>
          <HBar data={techniques} color="#f43f5e" valueLabel="Scans" />
        </ChartCard>
        <ChartCard title="SSL status" subtitle="Certificate state of scanned sites" loading={dist.isLoading} error={dist.error} empty={ssl.length === 0} height={260}>
          <Donut
            data={ssl}
            colorFor={(n, i) => {
              const k = n.toLowerCase()
              if (k.includes('invalid') || k.includes('expired') || k.includes('self')) return '#f43f5e'
              if (k.includes('valid')) return '#10b981'
              if (k.includes('no') || k.includes('none') || k.includes('http')) return '#f59e0b'
              return PALETTE[i % PALETTE.length]
            }}
          />
        </ChartCard>
        <ChartCard title="Domain age distribution" subtitle="Age since WHOIS registration" loading={dist.isLoading} error={dist.error} empty={domainAge.length === 0} height={260}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={domainAge} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="name" interval={0} tick={{ fontSize: 10 }} tickFormatter={(v: string) => String(v).replace(/\s*days?$/, 'd').replace(/\s*months?$/, 'mo').replace(/\s*years?$/, 'y').replace(/\s+/g, '')} />
              <YAxis allowDecimals={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ fillOpacity: 0.06 }} />
              <Bar dataKey="value" name="Domains" fill="#06b6d4" radius={[3, 3, 0, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="Top failed checks" subtitle="Most frequent failing signals" loading={dist.isLoading} error={dist.error} empty={checksFailed.length === 0} height={260}>
          <HBar data={checksFailed} color="#f59e0b" valueLabel="Failures" />
        </ChartCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card padded={false}>
          <div className="p-4 pb-0">
            <CardHeader title="Countries" subtitle="Hosting location of scanned sites" />
          </div>
          <DataTable
            dense
            loading={dist.isLoading}
            error={dist.error}
            rows={countries}
            rowKey={(r, i) => `${r.code ?? r.name ?? 'x'}-${i}`}
            columns={[
              {
                key: 'country',
                header: 'Country',
                render: (r) => (
                  <span className="flex items-center gap-2">
                    <span>{flagEmoji(r.code)}</span>
                    <span className="truncate">{r.name || r.code || 'Unknown'}</span>
                  </span>
                ),
              },
              {
                key: 'bar',
                header: 'Share',
                width: '45%',
                render: (r) => (
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
                    <div className="h-full rounded-full bg-indigo-500" style={{ width: `${((Number(r.value) || 0) / countryMax) * 100}%` }} />
                  </div>
                ),
              },
              { key: 'value', header: 'Scans', align: 'right', render: (r) => fmtNum(r.value) },
            ]}
          />
        </Card>
        <Card padded={false}>
          <div className="p-4 pb-0">
            <CardHeader title="Top domains" subtitle="Most scanned registered domains" />
          </div>
          <DataTable
            dense
            loading={dist.isLoading}
            error={dist.error}
            rows={topDomains}
            rowKey={(r, i) => `${r.domain}-${i}`}
            columns={[
              {
                key: 'domain',
                header: 'Domain',
                render: (r) => (
                  <Link to={`/domains/${encodeURIComponent(r.domain)}`} className="font-mono text-xs text-indigo-600 hover:underline dark:text-indigo-400">
                    {truncate(r.domain, 40)}
                  </Link>
                ),
              },
              { key: 'count', header: 'Scans', align: 'right', render: (r) => fmtNum(r.count) },
              { key: 'risk', header: 'Avg risk', align: 'right', render: (r) => <RiskPill score={r.avg_risk} /> },
            ]}
          />
        </Card>
      </div>

      <div className="pt-2">
        <h2 className="text-sm font-semibold">Threat insights</h2>
        <p className="text-xs text-zinc-500">Threat types, reputation tiers, content categories and the detection funnel · click a slice or bar to open matching scans</p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <ChartCard title="Threat types" subtitle="Safe Browsing-style threat classification" loading={dist.isLoading} error={dist.error} onRetry={() => dist.refetch()} empty={threatTypes.length === 0} height={260}>
          <Donut data={threatTypes} labelFor={threatLabel} colorFor={(n, i) => THREAT_COLOR[n] ?? PALETTE[i % PALETTE.length]} onSelect={(n) => nav(pivotHref('threat_type', n))} />
        </ChartCard>
        <ChartCard title="Reputation tiers" subtitle="Scans per trust tier" loading={dist.isLoading} error={dist.error} empty={tiers.length === 0} height={260}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={tiers} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="name" interval={0} />
              <YAxis allowDecimals={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ fillOpacity: 0.06 }} />
              <Bar dataKey="value" name="Scans" radius={[3, 3, 0, 0]} isAnimationActive={false}>
                {tiers.map((t, i) => (
                  <Cell key={t.name} fill={TIER_COLOR[t.name] ?? PALETTE[i % PALETTE.length]} cursor="pointer" onClick={() => nav(pivotHref('tier', t.name))} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="Content categories" subtitle="What the scanned pages are about" loading={dist.isLoading} error={dist.error} empty={categories.length === 0} height={260}>
          <HBar data={categories} color="#8b5cf6" valueLabel="Scans" onSelect={(n) => nav(pivotHref('category', n))} />
        </ChartCard>
      </div>
      <ChartCard
        title="Detection funnel"
        subtitle="How many scans pass each detection stage · % = share of all scanned"
        loading={funnel.isLoading}
        error={funnel.error}
        onRetry={() => funnel.refetch()}
        empty={funnelStages.length === 0}
        height={Math.max(160, funnelStages.length * 40)}
      >
        <Funnel stages={funnelStages} />
      </ChartCard>

      <div className="pt-2">
        <h2 className="text-sm font-semibold">Performance</h2>
        <p className="text-xs text-zinc-500">Scan latency, throughput and per-check error rates</p>
      </div>
      {perf.error ? (
        <ErrorBox error={perf.error} onRetry={() => perf.refetch()} />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            <Kpi label="p50 latency" value={fmtMs(p?.p50_ms)} loading={perf.isLoading} />
            <Kpi label="p95 latency" value={fmtMs(p?.p95_ms)} loading={perf.isLoading} />
            <Kpi label="p99 latency" value={fmtMs(p?.p99_ms)} loading={perf.isLoading} />
            <Kpi label="Max latency" value={fmtMs(p?.max_ms)} loading={perf.isLoading} />
            <Kpi label="Errors" value={fmtNum(p?.errors)} loading={perf.isLoading} color={(p?.errors ?? 0) > 0 ? '#f43f5e' : undefined} />
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <ChartCard title="Throughput" subtitle="Scans per hour" loading={perf.isLoading} empty={throughput.length === 0} height={240}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={throughput} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="t" tickFormatter={(v: string) => fmtTick(String(v), 'hour')} minTickGap={24} />
                  <YAxis allowDecimals={false} />
                  <Tooltip content={<ChartTooltip labelFormatter={(l) => fmtDate(String(l))} />} cursor={{ fillOpacity: 0.06 }} />
                  <Bar dataKey="count" name="Scans" fill="#6366f1" radius={[2, 2, 0, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>
            <ChartCard title="Check error rates" subtitle="Share of runs where a check errored" loading={perf.isLoading} empty={errRates.length === 0} height={240}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={errRates} layout="vertical" margin={{ top: 0, right: 12, bottom: 0, left: 0 }}>
                  <CartesianGrid horizontal={false} />
                  <XAxis type="number" domain={[0, 'auto']} tickFormatter={(v: number) => `${v}%`} />
                  <YAxis type="category" dataKey="name" width={120} tickFormatter={(v: string) => truncate(String(v), 18)} />
                  <Tooltip content={<ChartTooltip valueFormatter={(v) => fmtPct(v, 1, false)} />} cursor={{ fillOpacity: 0.06 }} />
                  <Bar dataKey="value" name="Error rate" fill="#f43f5e" radius={[0, 3, 3, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>
          </div>
        </>
      )}
    </div>
  )
}
