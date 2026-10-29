import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, Flag, ThumbsDown, ThumbsUp, Users } from 'lucide-react'
import { api, type Report } from '../api/client'
import { Card, CardHeader, PageHeader } from '../components/Card'
import { DataTable, Pagination, type Column } from '../components/DataTable'
import { EmptyState } from '../components/EmptyState'
import { Tabs } from '../components/Tabs'
import { useToast } from '../components/Toast'
import { Button, Chip, Field, Input, Select, Textarea } from '../components/ui'
import { fmtDate, fmtRel, safeGet, safeSet, truncate } from '../lib/format'

type Status = 'pending' | 'verified' | 'rejected'

function StatusChip({ status }: { status: Report['status'] }) {
  if (status === 'verified') return <Chip tone="rose">Verified phish</Chip>
  if (status === 'rejected') return <Chip tone="emerald">Rejected</Chip>
  return <Chip tone="amber">Pending</Chip>
}

export default function CommunityPage() {
  const qc = useQueryClient()
  const toast = useToast()
  const [tab, setTab] = useState<Status>('pending')
  const [page, setPage] = useState(1)
  const [url, setUrl] = useState('')
  const [label, setLabel] = useState<'phishing' | 'legitimate'>('phishing')
  const [brand, setBrand] = useState('')
  const [comment, setComment] = useState('')
  const [reporter, setReporter] = useState(() => safeGet('pg-reporter') ?? '')

  const q = useQuery({ queryKey: ['reports', tab, page], queryFn: () => api.reports(tab, page) })
  const counts = {
    pending: useQuery({ queryKey: ['reports', 'pending', 1], queryFn: () => api.reports('pending', 1) }).data?.total,
    verified: useQuery({ queryKey: ['reports', 'verified', 1], queryFn: () => api.reports('verified', 1) }).data?.total,
    rejected: useQuery({ queryKey: ['reports', 'rejected', 1], queryFn: () => api.reports('rejected', 1) }).data?.total,
  }
  const items = q.data?.items ?? []
  const total = q.data?.total ?? items.length
  const pageSize = q.data?.page_size ?? 25

  const submitM = useMutation({
    mutationFn: () => api.createReport({ url: url.trim(), label, brand: brand.trim() || undefined, comment: comment.trim() || undefined, reporter: reporter.trim() || undefined }),
    onSuccess: () => {
      toast('Report submitted — a scan was triggered', 'success')
      setUrl('')
      setBrand('')
      setComment('')
      qc.invalidateQueries({ queryKey: ['reports'] })
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Submit failed', 'error'),
  })
  const voteM = useMutation({
    mutationFn: ({ id, vote }: { id: Report['id']; vote: 'phishing' | 'legitimate' }) => api.vote(id, vote, reporter.trim() || undefined),
    onSuccess: (r) => {
      toast(`Vote recorded${r?.status && r.status !== 'pending' ? ` — report ${r.status}` : ''}`, 'success')
      qc.invalidateQueries({ queryKey: ['reports'] })
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Vote failed', 'error'),
  })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return
    safeSet('pg-reporter', reporter.trim())
    submitM.mutate()
  }

  const columns: Column<Report>[] = [
    {
      key: 'url',
      header: 'URL',
      render: (r) => (
        <div className="min-w-0 max-w-sm">
          <div className="truncate font-mono text-xs" title={r.url}>{r.url}</div>
          {r.comment && <div className="truncate text-xs text-zinc-500" title={r.comment}>{truncate(r.comment, 80)}</div>}
        </div>
      ),
    },
    { key: 'label', header: 'Claimed', render: (r) => <Chip tone={r.label === 'phishing' ? 'rose' : 'emerald'}>{r.label}</Chip> },
    { key: 'brand', header: 'Brand', render: (r) => r.brand || <span className="text-zinc-400">—</span> },
    { key: 'reporter', header: 'Reporter', render: (r) => <span className="text-xs">{r.reporter || 'anonymous'}</span> },
    { key: 'created', header: 'Submitted', render: (r) => <span className="text-xs text-zinc-500" title={fmtDate(r.created_at)}>{fmtRel(r.created_at)}</span> },
    { key: 'status', header: 'Status', render: (r) => <StatusChip status={r.status} /> },
    {
      key: 'votes',
      header: 'Votes',
      render: (r) => {
        const busy = voteM.isPending && voteM.variables?.id === r.id
        return (
          <div className="flex items-center gap-1">
            <button
              disabled={busy}
              onClick={() => voteM.mutate({ id: r.id, vote: 'phishing' })}
              className="inline-flex items-center gap-1 rounded border border-zinc-200 px-1.5 py-0.5 text-xs text-rose-600 hover:bg-rose-50 disabled:opacity-50 dark:border-zinc-700 dark:text-rose-400 dark:hover:bg-rose-950/40"
              title="Vote phishing"
            >
              <ThumbsDown className="size-3" /> <span className="tnum">{r.phishing_votes ?? 0}</span>
            </button>
            <button
              disabled={busy}
              onClick={() => voteM.mutate({ id: r.id, vote: 'legitimate' })}
              className="inline-flex items-center gap-1 rounded border border-zinc-200 px-1.5 py-0.5 text-xs text-emerald-600 hover:bg-emerald-50 disabled:opacity-50 dark:border-zinc-700 dark:text-emerald-400 dark:hover:bg-emerald-950/40"
              title="Vote legitimate"
            >
              <ThumbsUp className="size-3" /> <span className="tnum">{r.legitimate_votes ?? 0}</span>
            </button>
          </div>
        )
      },
    },
    {
      key: 'scan',
      header: '',
      align: 'right',
      render: (r) =>
        r.scan_id != null ? (
          <Link to={`/scans/${r.scan_id}`} className="inline-flex items-center gap-1 text-xs text-indigo-600 hover:underline dark:text-indigo-400">
            Scan <ExternalLink className="size-3" />
          </Link>
        ) : null,
    },
  ]

  return (
    <div className="space-y-5">
      <PageHeader title="Community reports" subtitle="PhishTank-style crowd verification. A report is verified at +3 net phishing votes and rejected at −3." />
      <Card>
        <CardHeader title="Submit a report" icon={<Flag className="size-4" />} />
        <form onSubmit={submit} className="grid gap-3 md:grid-cols-4">
          <div className="md:col-span-2">
            <Field label="Suspicious URL">
              <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" required />
            </Field>
          </div>
          <Field label="Label">
            <Select value={label} onChange={(e) => setLabel(e.target.value as 'phishing' | 'legitimate')}>
              <option value="phishing">Phishing</option>
              <option value="legitimate">Legitimate (false positive)</option>
            </Select>
          </Field>
          <Field label="Targeted brand">
            <Input value={brand} onChange={(e) => setBrand(e.target.value)} placeholder="PayPal" />
          </Field>
          <div className="md:col-span-3">
            <Field label="Comment">
              <Textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Where did you see it? (email, SMS…)" />
            </Field>
          </div>
          <div className="flex flex-col gap-3">
            <Field label="Your name (optional)">
              <Input value={reporter} onChange={(e) => setReporter(e.target.value)} placeholder="anonymous" />
            </Field>
            <Button type="submit" variant="primary" loading={submitM.isPending}>
              Submit report
            </Button>
          </div>
        </form>
      </Card>
      <Card padded={false}>
        <div className="px-4 pt-2">
          <Tabs
            value={tab}
            onChange={(t) => {
              setTab(t)
              setPage(1)
            }}
            tabs={[
              { id: 'pending', label: 'Pending', count: counts.pending },
              { id: 'verified', label: 'Verified', count: counts.verified },
              { id: 'rejected', label: 'Rejected', count: counts.rejected },
            ]}
          />
        </div>
        <DataTable
          columns={columns}
          rows={items}
          rowKey={(r) => r.id}
          loading={q.isLoading}
          error={q.error}
          onRetry={() => q.refetch()}
          empty={<EmptyState icon={<Users className="size-5" />} title={`No ${tab} reports`} />}
        />
        {total > pageSize && <Pagination page={page} pageSize={pageSize} total={total} onPage={setPage} />}
      </Card>
    </div>
  )
}
