import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowDownRight, ArrowUpRight, Eye, History as HistoryIcon, Minus, Play, Plus, Trash2 } from 'lucide-react'
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, asList, type WatchItem } from '../api/client'
import { Card, CardHeader, PageHeader } from '../components/Card'
import { ChartTooltip } from '../components/ChartCard'
import { DataTable, type Column } from '../components/DataTable'
import { Drawer } from '../components/Modal'
import { EmptyState } from '../components/EmptyState'
import { SkeletonRows } from '../components/Skeleton'
import { useToast } from '../components/Toast'
import { Button, Chip, ErrorBox, Field, Input, Select, Toggle } from '../components/ui'
import { RiskPill, VerdictBadge } from '../components/VerdictBadge'
import { fmtDate, fmtRel, fmtTick } from '../lib/format'

const INTERVALS = [
  { v: 15, l: 'Every 15 min' },
  { v: 60, l: 'Hourly' },
  { v: 360, l: 'Every 6 h' },
  { v: 1440, l: 'Daily' },
  { v: 10080, l: 'Weekly' },
]

function intervalLabel(m: number | null | undefined) {
  if (m == null) return '—'
  const f = INTERVALS.find((i) => i.v === m)
  if (f) return f.l
  return m >= 60 ? `Every ${(m / 60).toFixed(m % 60 ? 1 : 0)} h` : `Every ${m} min`
}

function ChangeArrow({ change }: { change: WatchItem['change'] }) {
  if (change === 'up') return <ArrowUpRight className="size-4 text-rose-500" aria-label="Risk increased" />
  if (change === 'down') return <ArrowDownRight className="size-4 text-emerald-500" aria-label="Risk decreased" />
  if (change === 'same') return <Minus className="size-4 text-zinc-400" aria-label="No change" />
  return <span className="text-zinc-400">—</span>
}

function HistoryPanel({ item }: { item: WatchItem }) {
  const q = useQuery({ queryKey: ['watch-history', item.id], queryFn: () => api.watchHistory(item.id) })
  const checks = [...(q.data?.checks ?? [])].sort((a, b) => String(a.t).localeCompare(String(b.t)))
  const typos = q.data?.typosquats ?? []
  if (q.isLoading) return <SkeletonRows rows={6} />
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />
  return (
    <div className="space-y-5">
      <div>
        <div className="label mb-2">Risk over time</div>
        {checks.length < 1 ? (
          <EmptyState compact title="No checks yet" description="Run the monitor to record the first data point." />
        ) : (
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={checks} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="t" tickFormatter={(t) => fmtTick(String(t), 'day')} minTickGap={24} />
                <YAxis domain={[0, 100]} />
                <ReferenceLine y={35} stroke="#f59e0b" strokeDasharray="4 4" />
                <ReferenceLine y={65} stroke="#f43f5e" strokeDasharray="4 4" />
                <Tooltip content={<ChartTooltip labelFormatter={(l) => fmtDate(String(l))} />} />
                <Line type="monotone" dataKey="risk_score" name="Risk" stroke="#6366f1" strokeWidth={2} dot={{ r: 2 }} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
      <div>
        <div className="label mb-2">Checks</div>
        <DataTable
          dense
          rows={[...checks].reverse()}
          rowKey={(r, i) => `${r.t}-${i}`}
          columns={[
            { key: 't', header: 'Time', render: (r) => <span className="text-xs">{fmtDate(r.t)}</span> },
            { key: 'v', header: 'Verdict', render: (r) => <VerdictBadge verdict={r.verdict} /> },
            { key: 'r', header: 'Risk', render: (r) => <RiskPill score={r.risk_score} /> },
            {
              key: 's',
              header: '',
              align: 'right',
              render: (r) =>
                r.scan_id != null ? (
                  <Link to={`/scans/${r.scan_id}`} className="text-xs text-indigo-600 hover:underline dark:text-indigo-400">
                    Report
                  </Link>
                ) : null,
            },
          ]}
        />
      </div>
      {item.monitor_typosquats && (
        <div>
          <div className="label mb-2">Resolving typosquats</div>
          {typos.length === 0 ? (
            <EmptyState compact title="No typosquats detected" />
          ) : (
            <DataTable
              dense
              rows={typos}
              rowKey={(r, i) => `${r.domain}-${i}`}
              columns={[
                { key: 'd', header: 'Domain', render: (r) => <span className="font-mono text-xs">{r.domain ?? '—'}</span> },
                { key: 't', header: 'Technique', render: (r) => (r.technique ? <Chip>{r.technique}</Chip> : '—') },
                { key: 'ip', header: 'IP', render: (r) => <span className="font-mono text-xs">{r.ip ?? '—'}</span> },
              ]}
            />
          )}
        </div>
      )}
    </div>
  )
}

export default function WatchlistPage() {
  const qc = useQueryClient()
  const toast = useToast()
  const [target, setTarget] = useState('')
  const [label, setLabel] = useState('')
  const [interval, setInterval] = useState(60)
  const [typos, setTypos] = useState(false)
  const [selected, setSelected] = useState<WatchItem | null>(null)

  const q = useQuery({ queryKey: ['watchlist'], queryFn: api.watchlist, refetchInterval: 30_000 })
  const items = asList<WatchItem>(q.data)

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['watchlist'] })
    qc.invalidateQueries({ queryKey: ['alerts'] })
  }
  const add = useMutation({
    mutationFn: () => api.watchAdd({ target: target.trim(), interval_minutes: interval, monitor_typosquats: typos, label: label.trim() || undefined }),
    onSuccess: () => {
      toast('Added to watchlist', 'success')
      setTarget('')
      setLabel('')
      invalidate()
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Failed', 'error'),
  })
  const run = useMutation({
    mutationFn: (id: WatchItem['id']) => api.watchRun(id),
    onSuccess: (_d, id) => {
      toast('Check completed', 'success')
      invalidate()
      qc.invalidateQueries({ queryKey: ['watch-history', id] })
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Run failed', 'error'),
  })
  const remove = useMutation({
    mutationFn: (id: WatchItem['id']) => api.watchDelete(id),
    onSuccess: () => {
      toast('Removed', 'success')
      invalidate()
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Delete failed', 'error'),
  })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (target.trim()) add.mutate()
  }

  const columns: Column<WatchItem>[] = [
    {
      key: 'target',
      header: 'Target',
      render: (r) => (
        <div className="min-w-0 max-w-xs">
          <div className="truncate font-medium" title={r.target}>{r.label || r.target}</div>
          {r.label && <div className="truncate font-mono text-xs text-zinc-500">{r.target}</div>}
        </div>
      ),
    },
    { key: 'interval', header: 'Interval', render: (r) => <span className="text-xs text-zinc-600 dark:text-zinc-400">{intervalLabel(r.interval_minutes)}</span> },
    { key: 'typo', header: 'Typosquats', align: 'center', render: (r) => (r.monitor_typosquats ? <Chip tone="indigo">On</Chip> : <span className="text-xs text-zinc-400">Off</span>) },
    { key: 'verdict', header: 'Last verdict', render: (r) => <VerdictBadge verdict={r.last_verdict} /> },
    { key: 'risk', header: 'Last risk', render: (r) => <RiskPill score={r.last_risk} /> },
    { key: 'change', header: 'Δ', align: 'center', render: (r) => <ChangeArrow change={r.change} /> },
    { key: 'checked', header: 'Last checked', render: (r) => <span className="text-xs text-zinc-500" title={fmtDate(r.last_checked)}>{r.last_checked ? fmtRel(r.last_checked) : 'Never'}</span> },
    { key: 'alerts', header: 'Alerts', align: 'right', render: (r) => (r.alerts ? <Chip tone="rose">{r.alerts}</Chip> : <span className="text-zinc-400">0</span>) },
    {
      key: 'actions',
      header: '',
      align: 'right',
      render: (r) => (
        <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" variant="ghost" icon={<Play className="size-3.5" />} loading={run.isPending && run.variables === r.id} onClick={() => run.mutate(r.id)}>
            Run
          </Button>
          <Button size="sm" variant="ghost" icon={<HistoryIcon className="size-3.5" />} onClick={() => setSelected(r)}>
            History
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="text-rose-600 dark:text-rose-400"
            icon={<Trash2 className="size-3.5" />}
            onClick={() => {
              if (confirm(`Remove ${r.target} from the watchlist?`)) remove.mutate(r.id)
            }}
            aria-label="Delete"
          />
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-5">
      <PageHeader title="Watchlist" subtitle="Continuously monitor URLs and domains; get alerts on verdict changes and newly resolving typosquats." />
      <Card>
        <CardHeader title="Add target" icon={<Plus className="size-4" />} />
        <form onSubmit={submit} className="grid gap-3 md:grid-cols-[2fr_1.2fr_1fr_auto_auto] md:items-end">
          <Field label="URL or domain">
            <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com or https://login.example.com" required />
          </Field>
          <Field label="Label (optional)">
            <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Company login" />
          </Field>
          <Field label="Interval">
            <Select value={interval} onChange={(e) => setInterval(Number(e.target.value))}>
              {INTERVALS.map((i) => (
                <option key={i.v} value={i.v}>
                  {i.l}
                </option>
              ))}
            </Select>
          </Field>
          <div className="flex h-9 items-center">
            <Toggle checked={typos} onChange={setTypos} label="Monitor typosquats" />
          </div>
          <Button type="submit" variant="primary" loading={add.isPending} icon={<Plus className="size-4" />}>
            Add
          </Button>
        </form>
      </Card>
      <Card padded={false}>
        <div className="flex items-center justify-between px-4 pt-4">
          <CardHeader title="Monitored targets" subtitle={`${items.length} target${items.length === 1 ? '' : 's'} · auto-checked every 60 s when due`} />
        </div>
        <DataTable
          columns={columns}
          rows={items}
          rowKey={(r) => r.id}
          loading={q.isLoading}
          error={q.error}
          onRetry={() => q.refetch()}
          onRowClick={(r) => setSelected(r)}
          empty={<EmptyState icon={<Eye className="size-5" />} title="Nothing on the watchlist" description="Add a brand domain or suspicious URL above to start monitoring." />}
        />
      </Card>
      <Drawer open={!!selected} onClose={() => setSelected(null)} title={selected ? `History · ${selected.label || selected.target}` : ''}>
        {selected && <HistoryPanel item={selected} />}
      </Drawer>
    </div>
  )
}
