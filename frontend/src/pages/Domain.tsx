import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CartesianGrid, Line, LineChart, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Eye, Globe, ScanSearch, Spline } from 'lucide-react'
import { api, type ScanSummary } from '../api/client'
import { Card, CardHeader, KV, PageHeader } from '../components/Card'
import { ChartCard, ChartTooltip } from '../components/ChartCard'
import { DataTable } from '../components/DataTable'
import { Kpi } from '../components/Kpi'
import { RiskPill, VerdictBadge } from '../components/VerdictBadge'
import { EmptyState } from '../components/EmptyState'
import { Skeleton } from '../components/Skeleton'
import { Button, ErrorBox } from '../components/ui'
import { useToast } from '../components/Toast'
import { ACCENT, VERDICT_COLOR, flagEmoji, fmtDate, fmtMs, fmtNum, fmtRel, riskColor, truncate } from '../lib/format'

export default function DomainPage() {
  const { domain = '' } = useParams()
  const nav = useNavigate()
  const toast = useToast()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['domain', domain], queryFn: () => api.domain(domain), enabled: !!domain })
  const d = q.data
  const scan = useMutation({
    mutationFn: () => api.scan(domain, true, 'web'),
    onSuccess: (r) => {
      qc.invalidateQueries()
      nav(`/scans/${r.id}`)
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Scan failed', 'error'),
  })
  const watch = useMutation({
    mutationFn: () => api.watchAdd({ target: domain, interval_minutes: 60, monitor_typosquats: true }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['watchlist'] })
      toast('Added to watchlist', 'success')
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Failed to add', 'error'),
  })

  const trend = (d?.risk_trend ?? []).map((p) => ({ ...p, risk: Number(p.risk) }))
  const latest = d?.latest
  const scans = d?.scans ?? []
  const counts = scans.reduce<Record<string, number>>((m, s) => ((m[s.verdict] = (m[s.verdict] ?? 0) + 1), m), {})

  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span className="flex items-center gap-2 font-mono">
            <Globe className="size-5 text-zinc-400" />
            {domain}
          </span>
        }
        subtitle="Domain intelligence aggregated across all scans"
        actions={
          <>
            <Link to={`/typosquat?domain=${encodeURIComponent(domain)}`}>
              <Button icon={<Spline className="size-3.5" />}>Typosquats</Button>
            </Link>
            <Button icon={<Eye className="size-3.5" />} loading={watch.isPending} onClick={() => watch.mutate()}>
              Watch
            </Button>
            <Button variant="primary" icon={<ScanSearch className="size-3.5" />} loading={scan.isPending} onClick={() => scan.mutate()}>
              Scan now
            </Button>
          </>
        }
      />
      {q.error && <ErrorBox error={q.error} onRetry={() => q.refetch()} />}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Kpi loading={q.isLoading} label="Scans" value={fmtNum(d?.scan_count ?? scans.length)} />
        <Kpi loading={q.isLoading} label="Avg risk" value={fmtNum(d?.avg_risk, 1)} color={riskColor(d?.avg_risk)} />
        <Kpi loading={q.isLoading} label="Latest verdict" value={latest ? <VerdictBadge verdict={latest.verdict} size="lg" /> : '—'} />
        <Kpi loading={q.isLoading} label="First seen" value={<span className="text-base">{fmtDate(d?.first_seen, false)}</span>} sub={fmtRel(d?.first_seen)} />
        <Kpi loading={q.isLoading} label="Last seen" value={<span className="text-base">{fmtDate(d?.last_seen, false)}</span>} sub={fmtRel(d?.last_seen)} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <ChartCard className="lg:col-span-2" title="Risk trend" subtitle="Risk score per scan over time" loading={q.isLoading} empty={trend.length === 0} height={240}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trend} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
              <ReferenceArea y1={65} y2={100} fill={VERDICT_COLOR.phishing} fillOpacity={0.06} />
              <ReferenceArea y1={35} y2={65} fill={VERDICT_COLOR.suspicious} fillOpacity={0.06} />
              <ReferenceArea y1={0} y2={35} fill={VERDICT_COLOR.legitimate} fillOpacity={0.06} />
              <CartesianGrid vertical={false} strokeDasharray="3 3" />
              <XAxis dataKey="t" tickFormatter={(t) => fmtDate(String(t), false)} minTickGap={30} tickLine={false} />
              <YAxis domain={[0, 100]} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip labelFormatter={(l) => fmtDate(String(l))} />} />
              <Line type="monotone" dataKey="risk" name="Risk" stroke={ACCENT} strokeWidth={2} dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>
        <Card>
          <CardHeader title="Latest scan intel" right={latest ? <Link className="text-xs text-indigo-600 hover:underline dark:text-indigo-400" to={`/scans/${latest.id}`}>Report →</Link> : null} />
          {q.isLoading ? (
            <Skeleton className="h-40 w-full" />
          ) : !latest ? (
            <EmptyState compact title="No scans yet" />
          ) : (
            <KV
              cols={1}
              rows={[
                ['IP', latest.domain_info?.ip ? <span className="font-mono">{latest.domain_info.ip}</span> : null],
                ['Hosting', latest.domain_info?.geo?.country_code ? `${flagEmoji(latest.domain_info.geo.country_code)} ${latest.domain_info.geo.country ?? latest.domain_info.geo.country_code} · ${latest.domain_info.geo.org ?? latest.domain_info.geo.isp ?? ''}` : null],
                ['Registrar', latest.domain_info?.whois?.registrar],
                ['Domain age', latest.domain_info?.whois?.age_days != null ? `${fmtNum(latest.domain_info.whois.age_days)} days` : null],
                ['SSL issuer', latest.ssl?.issuer],
                ['Brand target', latest.brand?.impersonated_brand],
                ['Verdict mix', Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(' · ') || null],
              ]}
            />
          )}
        </Card>
      </div>

      <Card padded={false}>
        <div className="p-4 pb-0">
          <CardHeader title={`Scans (${scans.length})`} />
        </div>
        <DataTable<ScanSummary>
          rows={scans}
          loading={q.isLoading}
          rowKey={(s) => s.id}
          onRowClick={(s) => nav(`/scans/${s.id}`)}
          columns={[
            { key: 'created_at', header: 'Time', render: (s) => <span className="whitespace-nowrap text-xs text-zinc-500">{fmtDate(s.created_at)}</span> },
            { key: 'url', header: 'URL', render: (s) => <span className="font-mono text-xs" title={s.url}>{truncate(s.url, 70)}</span> },
            { key: 'verdict', header: 'Verdict', render: (s) => <VerdictBadge verdict={s.verdict} /> },
            { key: 'risk', header: 'Risk', render: (s) => <RiskPill score={s.risk_score} /> },
            { key: 'source', header: 'Source', render: (s) => <span className="text-xs text-zinc-500">{s.source ?? '—'}</span> },
            { key: 'duration', header: 'Duration', align: 'right', render: (s) => <span className="text-xs">{fmtMs(s.duration_ms)}</span> },
          ]}
        />
      </Card>
    </div>
  )
}
