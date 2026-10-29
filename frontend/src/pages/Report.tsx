import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeftRight,
  Brain,
  Boxes,
  Braces,
  Camera,
  ClipboardList,
  Clock,
  Code,
  Download,
  FileText,
  Flag,
  Globe,
  Link2,
  Lock,
  MapPin,
  Printer,
  RefreshCw,
  Share2,
  ShieldAlert,
  Tag,
  Trash2,
  Users,
  Workflow,
  X,
} from 'lucide-react'
import { api, ApiError, asList, type Report as CommunityReport, type ScanResult, type ScanSummary } from '../api/client'
import { apiV2 } from '../api/client_v2'
import { Card } from '../components/Card'
import type { TabDef } from '../components/Tabs'
import { Modal } from '../components/Modal'
import { RiskGauge } from '../components/RiskGauge'
import { VerdictBadge } from '../components/VerdictBadge'
import { Skeleton } from '../components/Skeleton'
import { EmptyState } from '../components/EmptyState'
import { Button, Chip, ErrorBox, Field, Input, Select, Textarea } from '../components/ui'
import { useToast } from '../components/Toast'
import { copyText, cx, downloadBlob, fmtDate, fmtMs, fmtPct, fmtRel, titleCase } from '../lib/format'
import { BrandTab, DomainTab, GeoTab, HttpTab, MlTab, RawTab, ReputationTab, ScreenshotTab, SslTab, SummaryTab } from './report/Sections'
import { AiSummaryCard, ContentTab, HeaderBadges, ResourcesTab } from './report/V2Sections'
import SourceTab from './report/SourceTab'
import GraphTab from './report/GraphTab'
import TimelineTab from './report/TimelineTab'
import RelatedScans from './report/RelatedScans'

type TabId =
  | 'summary' | 'ml' | 'domain' | 'geo' | 'ssl' | 'http' | 'content' | 'resources' | 'brand' | 'reputation'
  | 'screenshot' | 'source' | 'graph' | 'timeline' | 'raw'

/** Wrapping tab bar: the report has 15 tabs, so they wrap onto a second row instead of hiding behind a horizontal scroll. */
function ReportTabs({ tabs, value, onChange }: { tabs: TabDef<TabId>[]; value: TabId; onChange: (v: TabId) => void }) {
  return (
    <div data-report-tabs className="no-print flex flex-wrap gap-1 border-b border-zinc-200 pb-2 dark:border-zinc-800">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => onChange(t.id)}
          className={cx(
            'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors',
            value === t.id
              ? 'bg-indigo-50 text-indigo-700 ring-1 ring-inset ring-indigo-200 dark:bg-indigo-500/15 dark:text-indigo-300 dark:ring-indigo-500/30'
              : 'text-zinc-500 hover:bg-zinc-100 hover:text-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-200',
          )}
        >
          {t.icon}
          {t.label}
          {t.count != null && (
            <span className="tnum rounded bg-zinc-100 px-1.5 text-[11px] text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400">{t.count}</span>
          )}
        </button>
      ))}
    </div>
  )
}

function Stat({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="label">{label}</div>
      <div className="tnum mt-0.5 truncate text-base font-semibold">{value}</div>
      {sub && <div className="truncate text-xs text-zinc-500">{sub}</div>}
    </div>
  )
}

function ReportModal({ open, onClose, scan }: { open: boolean; onClose: () => void; scan: ScanResult }) {
  const [label, setLabel] = useState<'phishing' | 'legitimate'>(scan.verdict === 'legitimate' ? 'legitimate' : 'phishing')
  const [brand, setBrand] = useState(scan.brand?.impersonated_brand ?? '')
  const [comment, setComment] = useState('')
  const [reporter, setReporter] = useState('')
  const toast = useToast()
  const qc = useQueryClient()
  const m = useMutation({
    mutationFn: () => api.createReport({ url: scan.url, label, brand: brand || undefined, comment: comment || undefined, reporter: reporter || undefined }),
    onSuccess: () => {
      toast('Report submitted to the community', 'success')
      qc.invalidateQueries({ queryKey: ['reports'] })
      qc.invalidateQueries({ queryKey: ['scan', String(scan.id)] })
      onClose()
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Failed to submit report', 'error'),
  })
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Report this URL"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={m.isPending} onClick={() => m.mutate()}>
            Submit report
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="truncate rounded-md bg-zinc-50 px-3 py-2 font-mono text-xs dark:bg-zinc-800/60">{scan.url}</div>
        <Field label="Classification">
          <div className="grid grid-cols-2 gap-2">
            {(['phishing', 'legitimate'] as const).map((l) => (
              <button
                key={l}
                type="button"
                onClick={() => setLabel(l)}
                className={`rounded-md border px-3 py-2 text-sm font-medium ${label === l ? (l === 'phishing' ? 'border-rose-400 bg-rose-50 text-rose-700 dark:bg-rose-500/10 dark:text-rose-300' : 'border-emerald-400 bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300') : 'border-zinc-200 dark:border-zinc-700'}`}
              >
                {l === 'phishing' ? 'Phishing' : 'Legitimate (false positive)'}
              </button>
            ))}
          </div>
        </Field>
        <Field label="Targeted brand (optional)">
          <Input value={brand} onChange={(e) => setBrand(e.target.value)} placeholder="e.g. PayPal" />
        </Field>
        <Field label="Comment (optional)">
          <Textarea rows={3} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="How did you encounter this URL?" />
        </Field>
        <Field label="Your name (optional)">
          <Input value={reporter} onChange={(e) => setReporter(e.target.value)} />
        </Field>
      </div>
    </Modal>
  )
}

function TagsNotesModal({ open, onClose, scan }: { open: boolean; onClose: () => void; scan: ScanResult }) {
  const [tags, setTags] = useState<string[]>(scan.tags ?? [])
  const [input, setInput] = useState('')
  const [notes, setNotes] = useState(scan.notes ?? '')
  const toast = useToast()
  const qc = useQueryClient()
  useEffect(() => {
    if (open) {
      setTags(scan.tags ?? [])
      setNotes(scan.notes ?? '')
    }
  }, [open, scan.tags, scan.notes])
  const m = useMutation({
    mutationFn: () => {
      const extra = input.trim() ? [input.trim()] : []
      return api.patchScan(scan.id, { tags: [...new Set([...tags, ...extra])], notes: notes || null })
    },
    onSuccess: (r) => {
      qc.setQueryData(['scan', String(scan.id)], r)
      setInput('')
      toast('Tags & notes saved', 'success')
      onClose()
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Save failed', 'error'),
  })
  const add = () => {
    const t = input.trim().replace(/,$/, '')
    if (t && !tags.includes(t)) setTags([...tags, t])
    setInput('')
  }
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Tags & notes"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={m.isPending} onClick={() => m.mutate()}>
            Save
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Tags" hint="Press Enter or comma to add">
          <div className="flex min-h-9 flex-wrap items-center gap-1.5 rounded-md border border-zinc-200 px-2 py-1.5 dark:border-zinc-700">
            {tags.map((t) => (
              <Chip key={t} tone="indigo">
                {t}
                <button type="button" onClick={() => setTags(tags.filter((x) => x !== t))} aria-label={`Remove ${t}`}>
                  <X className="size-3" />
                </button>
              </Chip>
            ))}
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ',') {
                  e.preventDefault()
                  add()
                } else if (e.key === 'Backspace' && !input && tags.length) setTags(tags.slice(0, -1))
              }}
              className="min-w-24 flex-1 bg-transparent text-sm outline-none"
              placeholder="add tag…"
            />
          </div>
        </Field>
        <Field label="Analyst notes">
          <Textarea rows={5} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Investigation notes…" />
        </Field>
      </div>
    </Modal>
  )
}

function CompareModal({ open, onClose, scan, candidates }: { open: boolean; onClose: () => void; scan: ScanResult; candidates: ScanSummary[] }) {
  const [other, setOther] = useState<string>('')
  useEffect(() => {
    if (open && candidates.length && !other) setOther(String(candidates[0].id))
  }, [open, candidates, other])
  const q = useQuery({ queryKey: ['compare', String(scan.id), other], queryFn: () => api.compare(scan.id, other), enabled: open && !!other })
  const fmt = (v: unknown) => (v == null ? '—' : typeof v === 'object' ? JSON.stringify(v) : String(v))
  return (
    <Modal open={open} onClose={onClose} title="Compare with previous scan" wide>
      {candidates.length === 0 ? (
        <EmptyState compact title="No other scans of this domain" description="Rescan this URL later to compare results over time." />
      ) : (
        <div className="space-y-3">
          <Field label="Compare against">
            <Select value={other} onChange={(e) => setOther(e.target.value)}>
              {candidates.map((c) => (
                <option key={c.id} value={String(c.id)}>
                  #{c.id} · {fmtDate(c.created_at)} · {titleCase(c.verdict)} · risk {Math.round(c.risk_score)}
                </option>
              ))}
            </Select>
          </Field>
          {q.isLoading ? (
            <Skeleton className="h-40 w-full" />
          ) : q.error ? (
            <ErrorBox error={q.error} />
          ) : q.data ? (
            <>
              <div className="grid grid-cols-2 gap-3">
                {[q.data.a, q.data.b].map((s, i) => (
                  <Card key={i} className="!p-3">
                    <div className="label">{i === 0 ? 'This scan' : 'Previous scan'} · #{s?.id}</div>
                    <div className="mt-1 flex items-center gap-2">
                      <VerdictBadge verdict={s?.verdict} />
                      <span className="tnum text-lg font-semibold">{s?.risk_score != null ? Math.round(s.risk_score) : '—'}</span>
                    </div>
                    <div className="mt-1 text-xs text-zinc-500">{fmtDate(s?.created_at)}</div>
                  </Card>
                ))}
              </div>
              <div className="overflow-x-auto rounded-md border border-zinc-200 dark:border-zinc-800">
                <table className="w-full text-xs">
                  <thead className="bg-zinc-50 dark:bg-zinc-900">
                    <tr>
                      <th className="label px-3 py-2 text-left">Field</th>
                      <th className="label px-3 py-2 text-left">This scan</th>
                      <th className="label px-3 py-2 text-left">Previous</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(q.data.diff ?? []).length === 0 ? (
                      <tr>
                        <td colSpan={3} className="px-3 py-4 text-center text-zinc-500">
                          No differences
                        </td>
                      </tr>
                    ) : (
                      (q.data.diff ?? []).map((d, i) => (
                        <tr key={i} className="border-t border-zinc-100 dark:border-zinc-800">
                          <td className="px-3 py-1.5 font-mono">{d.field}</td>
                          <td className="max-w-60 truncate px-3 py-1.5" title={fmt(d.a)}>
                            {fmt(d.a)}
                          </td>
                          <td className="max-w-60 truncate px-3 py-1.5 text-zinc-500" title={fmt(d.b)}>
                            {fmt(d.b)}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </>
          ) : null}
        </div>
      )}
    </Modal>
  )
}

export default function Report() {
  const { id = '' } = useParams()
  const nav = useNavigate()
  const toast = useToast()
  const qc = useQueryClient()
  const [tab, setTab] = useState<TabId>('summary')
  const [reportOpen, setReportOpen] = useState(false)
  const [tagsOpen, setTagsOpen] = useState(false)
  const [compareOpen, setCompareOpen] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const q = useQuery({ queryKey: ['scan', id], queryFn: () => apiV2.getScan(id), enabled: !!id })
  const scan = q.data
  const domainName = scan?.domain ?? scan?.domain_info?.domain ?? null
  const dq = useQuery({ queryKey: ['domain', domainName], queryFn: () => api.domain(domainName!), enabled: !!domainName, retry: false })
  const settings = useQuery({ queryKey: ['settings'], queryFn: api.settings, staleTime: 60_000, retry: false })
  const sus = settings.data?.suspicious_threshold ?? 35
  const phish = settings.data?.phishing_threshold ?? 65

  const others = useMemo(() => (dq.data?.scans ?? []).filter((s) => String(s.id) !== String(scan?.id)), [dq.data, scan?.id])

  const rescan = useMutation({
    mutationFn: () => api.rescan(id),
    onSuccess: (r) => {
      qc.invalidateQueries()
      toast('Rescan complete', 'success')
      nav(`/scans/${r.id}`)
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Rescan failed', 'error'),
  })
  const del = useMutation({
    mutationFn: () => api.deleteScan(id),
    onSuccess: () => {
      qc.invalidateQueries()
      toast('Scan deleted', 'success')
      nav('/history')
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Delete failed', 'error'),
  })
  const vote = useMutation({
    mutationFn: async (v: 'phishing' | 'legitimate') => {
      // Find an existing community report for this URL; otherwise open one.
      if (!scan) throw new Error('Scan not loaded')
      // Reports store the normalized URL; search by domain so we are not limited to page 1.
      const opts = { q: scan.domain ?? undefined, page_size: 200 }
      const lists = await Promise.allSettled(['pending', 'verified', 'rejected'].map((s) => api.reports(s, 1, opts)))
      const all = lists.flatMap((r) => (r.status === 'fulfilled' ? asList<CommunityReport>(r.value) : []))
      const urls = new Set([scan.url, scan.normalized_url].filter(Boolean))
      const match = all.find((r) => urls.has(r.url) || (r.scan_id != null && String(r.scan_id) === String(scan.id)))
      if (match) return api.vote(match.id, v)
      return api.createReport({ url: scan.url, label: v, comment: 'Vote from scan report' })
    },
    onSuccess: () => {
      toast('Vote recorded', 'success')
      qc.invalidateQueries({ queryKey: ['scan', id] })
      qc.invalidateQueries({ queryKey: ['reports'] })
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Vote failed', 'error'),
  })

  if (q.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-2/3" />
        <Skeleton className="h-44 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    )
  }
  if (q.error || !scan) {
    const notFound = q.error instanceof ApiError && q.error.status === 404
    return (
      <EmptyState
        icon={<ShieldAlert className="size-5" />}
        title={notFound ? 'Scan not found' : 'Could not load scan'}
        description={q.error instanceof Error ? q.error.message : undefined}
        action={
          <div className="flex gap-2">
            <Button onClick={() => q.refetch()}>Retry</Button>
            <Link to="/history">
              <Button variant="primary">Back to history</Button>
            </Link>
          </div>
        }
      />
    )
  }

  const checks = scan.checks ?? []
  const failCount = checks.filter((c) => c.status === 'fail').length
  const listed = (scan.reputation?.sources ?? []).filter((s) => s.listed).length

  const tabs = [
    { id: 'summary' as const, label: 'Summary', icon: <ClipboardList className="size-4" />, count: checks.length || null },
    { id: 'ml' as const, label: 'ML Explanation', icon: <Brain className="size-4" /> },
    { id: 'domain' as const, label: 'Domain', icon: <Globe className="size-4" /> },
    { id: 'geo' as const, label: 'Geo & Hosting', icon: <MapPin className="size-4" /> },
    { id: 'ssl' as const, label: 'SSL', icon: <Lock className="size-4" /> },
    { id: 'http' as const, label: 'HTTP', icon: <Workflow className="size-4" /> },
    { id: 'content' as const, label: 'Content', icon: <FileText className="size-4" />, count: scan.http?.trackers?.length || null },
    { id: 'resources' as const, label: 'Resources', icon: <Boxes className="size-4" />, count: scan.http?.resources?.length || null },
    { id: 'brand' as const, label: 'Brand', icon: <Tag className="size-4" /> },
    { id: 'reputation' as const, label: 'Reputation', icon: <Users className="size-4" />, count: listed || null },
    { id: 'screenshot' as const, label: 'Screenshot', icon: <Camera className="size-4" /> },
    { id: 'source' as const, label: 'Source', icon: <Code className="size-4" /> },
    { id: 'graph' as const, label: 'Graph', icon: <Share2 className="size-4" /> },
    { id: 'timeline' as const, label: 'Timeline', icon: <Clock className="size-4" /> },
    { id: 'raw' as const, label: 'Raw JSON', icon: <Braces className="size-4" /> },
  ]

  const shareLink = `${window.location.origin}/scans/${scan.id}`

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="space-y-3">
        <div className="min-w-0">
          <div className="label mb-1 flex items-center gap-2">
            Scan report #{scan.id}
            {scan.source && <Chip>{scan.source}</Chip>}
          </div>
          <h1 className="break-all font-mono text-base font-medium text-zinc-900 sm:text-lg dark:text-zinc-50">{scan.url}</h1>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-zinc-500">
            {domainName && (
              <Link to={`/domains/${encodeURIComponent(domainName)}`} className="inline-flex items-center gap-1 text-indigo-600 hover:underline dark:text-indigo-400">
                <Globe className="size-3" />
                {domainName}
              </Link>
            )}
            {dq.data?.scan_count != null && (
              <span>
                · {dq.data.scan_count} {dq.data.scan_count === 1 ? 'scan' : 'scans'} of this domain
              </span>
            )}
            {(scan.tags ?? []).map((t) => (
              <Chip key={t} tone="indigo">
                {t}
              </Chip>
            ))}
          </div>
        </div>
        <div className="no-print flex flex-wrap gap-2">
          <Button icon={<RefreshCw className="size-3.5" />} loading={rescan.isPending} onClick={() => rescan.mutate()}>
            Rescan
          </Button>
          <Button icon={<Flag className="size-3.5" />} onClick={() => setReportOpen(true)}>
            Report
          </Button>
          <Button icon={<Tag className="size-3.5" />} onClick={() => setTagsOpen(true)}>
            Tags & notes
          </Button>
          <Button icon={<ArrowLeftRight className="size-3.5" />} onClick={() => setCompareOpen(true)} disabled={dq.isLoading} title={others.length ? `${others.length} other scans` : 'No other scans of this domain'}>
            Compare{others.length ? ` (${others.length})` : ''}
          </Button>
          <Button
            icon={<Download className="size-3.5" />}
            onClick={() => downloadBlob(`phishguard-scan-${scan.id}.json`, JSON.stringify(scan, null, 2))}
          >
            JSON
          </Button>
          <Button icon={<Printer className="size-3.5" />} onClick={() => window.print()}>
            Print
          </Button>
          <Button
            icon={<Link2 className="size-3.5" />}
            onClick={async () => toast((await copyText(shareLink)) ? 'Share link copied' : 'Copy failed', 'info')}
          >
            Share
          </Button>
          <Button variant="danger" icon={<Trash2 className="size-3.5" />} onClick={() => setConfirmDelete(true)} aria-label="Delete scan" />
        </div>
      </div>

      {/* Verdict summary */}
      <Card className="print-break">
        <div className="flex flex-col items-center gap-6 md:flex-row">
          <div className="flex shrink-0 flex-col items-center">
            <RiskGauge score={scan.risk_score} suspicious={sus} phishing={phish} />
          </div>
          <div className="w-full min-w-0 flex-1 space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <VerdictBadge verdict={scan.verdict} size="lg" icon />
              <span className="text-sm text-zinc-500">
                {scan.verdict === 'phishing'
                  ? 'High likelihood this URL is a phishing site. Do not enter credentials.'
                  : scan.verdict === 'suspicious'
                    ? 'Some risk indicators were found. Proceed with caution.'
                    : 'No significant phishing indicators detected.'}
              </span>
            </div>
            <HeaderBadges scan={scan} sus={sus} phish={phish} onEngines={() => setTab('reputation')} />
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
              <Stat label="Risk score" value={`${Math.round(scan.risk_score ?? 0)} / 100`} />
              <Stat label="Confidence" value={fmtPct(scan.confidence, 0, true)} />
              <Stat label="ML probability" value={fmtPct(scan.ml?.probability_phishing, 1, true)} sub={scan.ml?.model_name ?? undefined} />
              <Stat label="Failed checks" value={`${failCount} / ${checks.length}`} />
              <Stat label="Duration" value={fmtMs(scan.duration_ms)} />
              <Stat label="Scanned" value={fmtRel(scan.created_at)} sub={fmtDate(scan.created_at)} />
            </div>
            {scan.notes && <div className="rounded-md border-l-2 border-indigo-400 bg-zinc-50 px-3 py-2 text-sm text-zinc-700 dark:bg-zinc-800/40 dark:text-zinc-300">{scan.notes}</div>}
          </div>
        </div>
      </Card>

      <ReportTabs tabs={tabs} value={tab} onChange={setTab} />

      <div>
        {tab === 'summary' && (
          <div className="space-y-4">
            <AiSummaryCard scan={scan} />
            <SummaryTab scan={scan} />
            <RelatedScans scanId={scan.id} />
          </div>
        )}
        {tab === 'ml' && <MlTab scan={scan} />}
        {tab === 'domain' && <DomainTab scan={scan} />}
        {tab === 'geo' && <GeoTab scan={scan} />}
        {tab === 'ssl' && <SslTab scan={scan} />}
        {tab === 'http' && <HttpTab scan={scan} />}
        {tab === 'content' && <ContentTab scan={scan} />}
        {tab === 'resources' && <ResourcesTab scan={scan} />}
        {tab === 'brand' && <BrandTab scan={scan} />}
        {tab === 'reputation' && <ReputationTab scan={scan} onVote={(v) => vote.mutate(v)} voting={vote.isPending} />}
        {tab === 'screenshot' && <ScreenshotTab scan={scan} />}
        {tab === 'source' && <SourceTab scanId={scan.id} hasDom={(scan as { has_dom?: boolean | null }).has_dom} />}
        {tab === 'graph' &&
          (domainName ? <GraphTab domain={domainName} /> : <EmptyState compact title="No domain to graph" description="This scan has no domain name." />)}
        {tab === 'timeline' && <TimelineTab scanId={scan.id} />}
        {tab === 'raw' && <RawTab scan={scan} />}
      </div>

      <ReportModal open={reportOpen} onClose={() => setReportOpen(false)} scan={scan} />
      <TagsNotesModal open={tagsOpen} onClose={() => setTagsOpen(false)} scan={scan} />
      <CompareModal open={compareOpen} onClose={() => setCompareOpen(false)} scan={scan} candidates={others} />
      <Modal
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title="Delete scan?"
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button variant="danger" loading={del.isPending} onClick={() => del.mutate()}>
              Delete
            </Button>
          </>
        }
      >
        <p className="text-sm text-zinc-600 dark:text-zinc-400">This permanently removes scan #{scan.id} from history. This action is logged in the activity log.</p>
      </Modal>
    </div>
  )
}
