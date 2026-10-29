import { useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { ArrowLeft, Download, FileUp, Layers, Loader2 } from 'lucide-react'
import { api, asList, type BulkJob, type ScanSummary, type Verdict } from '../api/client'
import { Card, CardHeader, PageHeader } from '../components/Card'
import { ChartTooltip, Legend } from '../components/ChartCard'
import { DataTable } from '../components/DataTable'
import { RiskPill, VerdictBadge } from '../components/VerdictBadge'
import { EmptyState } from '../components/EmptyState'
import { Segmented } from '../components/RangeSelect'
import { Button, Chip, ErrorBox, Input, ProgressBar, Textarea } from '../components/ui'
import { useToast } from '../components/Toast'
import { VERDICTS, VERDICT_COLOR, VERDICT_LABEL, cx, downloadBlob, fmtDate, fmtMs, fmtNum, fmtRel, truncate } from '../lib/format'

const isRunning = (j?: BulkJob | null) => !!j && j.status !== 'done' && j.status !== 'completed' && j.status !== 'failed' && j.status !== 'error' && (j.done ?? 0) < (j.total ?? 0)

function statusTone(s?: string | null): 'emerald' | 'amber' | 'rose' | 'indigo' | 'zinc' {
  if (s === 'done' || s === 'completed') return 'emerald'
  if (s === 'failed' || s === 'error') return 'rose'
  if (s === 'running' || s === 'processing') return 'indigo'
  return 'zinc'
}

function VerdictBar({ counts, total }: { counts?: Partial<Record<Verdict, number>> | null; total: number }) {
  const sum = VERDICTS.reduce((s, v) => s + (counts?.[v] ?? 0), 0)
  if (!sum) return <span className="text-xs text-zinc-400">—</span>
  return (
    <div className="flex h-1.5 w-28 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800" title={VERDICTS.map((v) => `${VERDICT_LABEL[v]}: ${counts?.[v] ?? 0}`).join(' · ')}>
      {VERDICTS.map((v) => (
        <div key={v} style={{ width: `${((counts?.[v] ?? 0) / Math.max(total, sum)) * 100}%`, background: VERDICT_COLOR[v] }} />
      ))}
    </div>
  )
}

function JobDetail({ id }: { id: string }) {
  const nav = useNavigate()
  const [filter, setFilter] = useState<'all' | Verdict>('all')
  const q = useQuery({
    queryKey: ['bulk', id],
    queryFn: () => api.bulkJob(id),
    refetchInterval: (query) => (isRunning(query.state.data as BulkJob | undefined) ? 2000 : false),
  })
  const job = q.data
  const results = job?.results ?? []
  const counts = useMemo(() => {
    const c: Partial<Record<Verdict, number>> = { ...(job?.verdict_counts ?? {}) }
    if (!job?.verdict_counts) for (const r of results) c[r.verdict] = (c[r.verdict] ?? 0) + 1
    return c
  }, [job, results])
  const pie = VERDICTS.map((v) => ({ name: VERDICT_LABEL[v], value: counts[v] ?? 0, color: VERDICT_COLOR[v] })).filter((p) => p.value > 0)
  const shown = filter === 'all' ? results : results.filter((r) => r.verdict === filter)
  const total = job?.total ?? 0
  const done = job?.done ?? results.length

  const exportCsv = () => {
    const head = ['id', 'url', 'domain', 'verdict', 'risk_score', 'brand', 'country_code', 'blacklisted', 'created_at']
    const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
    const lines = [head.join(','), ...results.map((r) => head.map((h) => esc((r as unknown as Record<string, unknown>)[h])).join(','))]
    downloadBlob(`bulk-${id}.csv`, lines.join('\n'), 'text/csv')
  }

  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />
  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <Link to="/bulk" className="rounded p-1 text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800" aria-label="Back">
              <ArrowLeft className="size-4" />
            </Link>
            {job?.name || `Bulk job #${id}`}
          </span>
        }
        subtitle={job ? `Created ${fmtDate(job.created_at)} · ${fmtNum(total)} URLs` : 'Loading…'}
        actions={
          <>
            <Button icon={<Download className="size-3.5" />} disabled={!results.length} onClick={exportCsv}>
              CSV
            </Button>
            <Button icon={<Download className="size-3.5" />} disabled={!job} onClick={() => downloadBlob(`bulk-${id}.json`, JSON.stringify(job, null, 2))}>
              JSON
            </Button>
          </>
        }
      />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title="Progress" right={<Chip tone={statusTone(job?.status)}>{job?.status ?? '—'}</Chip>} />
          <div className="flex items-baseline gap-2">
            <span className="tnum text-3xl font-semibold">{fmtNum(done)}</span>
            <span className="tnum text-sm text-zinc-500">/ {fmtNum(total)} scanned</span>
            {isRunning(job) && <Loader2 className="size-4 animate-spin text-indigo-500" />}
          </div>
          <ProgressBar className="mt-3 h-2" value={done} max={total || 1} />
          <div className="mt-4 grid grid-cols-3 gap-2 text-center">
            {VERDICTS.map((v) => (
              <div key={v} className="rounded-md bg-zinc-50 py-2 dark:bg-zinc-800/50">
                <div className="tnum text-lg font-semibold" style={{ color: VERDICT_COLOR[v] }}>
                  {fmtNum(counts[v] ?? 0)}
                </div>
                <div className="label">{VERDICT_LABEL[v]}</div>
              </div>
            ))}
          </div>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Verdict distribution" right={<Legend items={pie.map((p) => ({ label: p.name, color: p.color, value: fmtNum(p.value) }))} />} />
          {pie.length === 0 ? (
            <EmptyState compact title="No results yet" />
          ) : (
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pie} dataKey="value" nameKey="name" innerRadius="55%" outerRadius="90%" paddingAngle={2} stroke="none">
                    {pie.map((p) => (
                      <Cell key={p.name} fill={p.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
      </div>
      <Card padded={false}>
        <div className="flex flex-wrap items-center justify-between gap-2 p-4 pb-2">
          <span className="text-sm font-semibold">Results ({fmtNum(shown.length)})</span>
          <Segmented<'all' | Verdict>
            value={filter}
            onChange={setFilter}
            options={[{ value: 'all', label: 'All' }, ...VERDICTS.map((v) => ({ value: v, label: VERDICT_LABEL[v] }))]}
          />
        </div>
        <DataTable<ScanSummary>
          rows={shown}
          loading={q.isLoading}
          rowKey={(r) => r.id}
          onRowClick={(r) => nav(`/scans/${r.id}`)}
          maxHeight={600}
          empty={<EmptyState compact title={isRunning(job) ? 'Scanning… results will appear here' : 'No results'} />}
          columns={[
            { key: 'url', header: 'URL', render: (r) => <span className="font-mono text-xs" title={r.url}>{truncate(r.url, 80)}</span> },
            { key: 'verdict', header: 'Verdict', render: (r) => <VerdictBadge verdict={r.verdict} /> },
            { key: 'risk', header: 'Risk', render: (r) => <RiskPill score={r.risk_score} /> },
            { key: 'brand', header: 'Brand', render: (r) => (r.brand ? <Chip tone="rose">{r.brand}</Chip> : <span className="text-zinc-400">—</span>) },
            { key: 'bl', header: 'Blacklist', render: (r) => (r.blacklisted ? <Chip tone="rose">listed</Chip> : <span className="text-xs text-zinc-400">no</span>) },
            { key: 'dur', header: 'Duration', align: 'right', render: (r) => <span className="text-xs">{fmtMs(r.duration_ms)}</span> },
          ]}
        />
      </Card>
    </div>
  )
}

export default function Bulk() {
  const { id } = useParams()
  if (id) return <JobDetail id={id} />
  return <BulkHome />
}

function BulkHome() {
  const nav = useNavigate()
  const toast = useToast()
  const qc = useQueryClient()
  const [mode, setMode] = useState<'paste' | 'upload'>('paste')
  const [text, setText] = useState('')
  const [name, setName] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const urls = useMemo(
    () =>
      [...new Set(text.split(/[\r\n]+/).map((l) => l.trim().split(/[,\s]/)[0]).filter((l) => l && !l.startsWith('#')))],
    [text],
  )

  const jobs = useQuery({
    queryKey: ['bulk'],
    queryFn: api.bulkJobs,
    refetchInterval: (query) => (asList<BulkJob>(query.state.data).some(isRunning) ? 2500 : 15000),
  })
  const create = useMutation({
    mutationFn: () => (mode === 'upload' && file ? api.bulkUpload(file, name || undefined) : api.bulkCreate(urls.slice(0, 500), name || undefined)),
    onSuccess: (r) => {
      toast('Bulk job started', 'success')
      qc.invalidateQueries({ queryKey: ['bulk'] })
      setText('')
      setFile(null)
      setName('')
      if (r?.job_id != null) nav(`/bulk/${r.job_id}`)
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Failed to start job', 'error'),
  })
  const list = asList<BulkJob>(jobs.data)
  const canSubmit = mode === 'paste' ? urls.length > 0 && urls.length <= 500 : !!file

  return (
    <div className="space-y-4">
      <PageHeader title="Bulk scan" subtitle="Scan up to 500 URLs at once. Jobs run in the background." />
      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader title="New job" right={<Segmented value={mode} onChange={setMode} options={[{ value: 'paste', label: 'Paste' }, { value: 'upload', label: 'Upload' }]} />} />
          <div className="space-y-3">
            <Input placeholder="Job name (optional)" value={name} onChange={(e) => setName(e.target.value)} />
            {mode === 'paste' ? (
              <>
                <Textarea rows={10} className="font-mono text-xs" placeholder={'One URL per line\nhttps://example.com\nhttp://suspicious-login.xyz/verify'} value={text} onChange={(e) => setText(e.target.value)} />
                <div className={cx('tnum text-xs', urls.length > 500 ? 'text-rose-600' : 'text-zinc-500')}>
                  {urls.length} unique URL{urls.length === 1 ? '' : 's'} {urls.length > 500 && '— maximum is 500'}
                </div>
              </>
            ) : (
              <div
                onClick={() => fileRef.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault()
                  setFile(e.dataTransfer.files?.[0] ?? null)
                }}
                className="flex cursor-pointer flex-col items-center gap-2 rounded-lg border-2 border-dashed border-zinc-200 px-4 py-10 text-center hover:border-indigo-400 dark:border-zinc-700"
              >
                <FileUp className="size-7 text-zinc-400" />
                {file ? (
                  <div className="text-sm font-medium">
                    {file.name} <span className="text-zinc-500">({fmtNum(file.size / 1024, 1)} KB)</span>
                  </div>
                ) : (
                  <>
                    <div className="text-sm font-medium">Drop a CSV or TXT file</div>
                    <div className="text-xs text-zinc-500">One URL per line, or a CSV with a “url” column</div>
                  </>
                )}
                <input ref={fileRef} type="file" accept=".csv,.txt,text/csv,text/plain" className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
              </div>
            )}
            <Button variant="primary" className="w-full" icon={<Layers className="size-4" />} loading={create.isPending} disabled={!canSubmit} onClick={() => create.mutate()}>
              Start bulk scan
            </Button>
          </div>
        </Card>

        <Card className="lg:col-span-3" padded={false}>
          <div className="p-4 pb-2">
            <CardHeader title="Jobs" subtitle="Auto-refreshes while jobs are running" />
          </div>
          <DataTable<BulkJob>
            rows={list}
            loading={jobs.isLoading}
            error={jobs.error}
            onRetry={() => jobs.refetch()}
            rowKey={(j) => j.id}
            onRowClick={(j) => nav(`/bulk/${j.id}`)}
            empty={<EmptyState compact icon={<Layers className="size-5" />} title="No bulk jobs yet" />}
            columns={[
              {
                key: 'name',
                header: 'Job',
                render: (j) => (
                  <div>
                    <div className="text-sm font-medium">{j.name || `Job #${j.id}`}</div>
                    <div className="text-[11px] text-zinc-500">{fmtRel(j.created_at)}</div>
                  </div>
                ),
              },
              { key: 'status', header: 'Status', render: (j) => <Chip tone={statusTone(j.status)}>{j.status ?? '—'}</Chip> },
              {
                key: 'progress',
                header: 'Progress',
                render: (j) => (
                  <div className="w-36">
                    <div className="tnum mb-1 text-[11px] text-zinc-500">
                      {fmtNum(j.done)} / {fmtNum(j.total)}
                    </div>
                    <ProgressBar value={j.done ?? 0} max={j.total || 1} />
                  </div>
                ),
              },
              { key: 'verdicts', header: 'Verdicts', render: (j) => <VerdictBar counts={j.verdict_counts} total={j.total ?? 0} /> },
              {
                key: 'phish',
                header: 'Phishing',
                align: 'right',
                render: (j) => <span className="tnum text-sm font-medium text-rose-600 dark:text-rose-400">{fmtNum(j.verdict_counts?.phishing ?? 0)}</span>,
              },
            ]}
          />
        </Card>
      </div>
    </div>
  )
}
