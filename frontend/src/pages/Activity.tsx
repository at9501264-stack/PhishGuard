import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import {
  Activity as ActivityIcon,
  Bell,
  ChevronDown,
  ChevronRight,
  Download,
  Eye,
  FileStack,
  Flag,
  RefreshCw,
  Rss,
  ScanSearch,
  Settings,
  ThumbsUp,
  Trash2,
} from 'lucide-react'
import { api, type EventItem } from '../api/client'
import { Card, PageHeader } from '../components/Card'
import { Pagination } from '../components/DataTable'
import { EmptyState } from '../components/EmptyState'
import { SkeletonRows } from '../components/Skeleton'
import { Chip, ErrorBox, Select } from '../components/ui'
import { cx, fmtDate, fmtRel, titleCase } from '../lib/format'

function iconFor(type: string) {
  const t = type.toLowerCase()
  if (t.includes('rescan')) return { Icon: RefreshCw, c: 'text-indigo-500' }
  if (t.includes('scan')) return { Icon: ScanSearch, c: 'text-indigo-500' }
  if (t.includes('delete')) return { Icon: Trash2, c: 'text-rose-500' }
  if (t.includes('vote')) return { Icon: ThumbsUp, c: 'text-emerald-500' }
  if (t.includes('report')) return { Icon: Flag, c: 'text-amber-500' }
  if (t.includes('bulk')) return { Icon: FileStack, c: 'text-cyan-500' }
  if (t.includes('watch')) return { Icon: Eye, c: 'text-violet-500' }
  if (t.includes('alert')) return { Icon: Bell, c: 'text-rose-500' }
  if (t.includes('setting')) return { Icon: Settings, c: 'text-zinc-500' }
  if (t.includes('feed')) return { Icon: Rss, c: 'text-orange-500' }
  if (t.includes('export')) return { Icon: Download, c: 'text-sky-500' }
  return { Icon: ActivityIcon, c: 'text-zinc-500' }
}

function hasMeta(m: unknown) {
  if (m == null) return false
  if (typeof m === 'object') return Object.keys(m as object).length > 0
  return String(m).length > 0
}

function Row({ e }: { e: EventItem }) {
  const [open, setOpen] = useState(false)
  const { Icon, c } = iconFor(e.type ?? '')
  const meta = hasMeta(e.meta)
  return (
    <li className="relative pb-4 pl-10 last:pb-0">
      <span className="absolute left-[15px] top-8 h-[calc(100%-2rem)] w-px bg-zinc-200 dark:bg-zinc-800" />
      <span className="absolute left-0 top-0.5 flex size-8 items-center justify-center rounded-full border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
        <Icon className={cx('size-4', c)} />
      </span>
      <div className="flex flex-wrap items-center gap-2">
        <Chip>{titleCase(e.type)}</Chip>
        <span className="text-xs text-zinc-500" title={fmtDate(e.created_at)}>
          {fmtDate(e.created_at)} · {fmtRel(e.created_at)}
        </span>
      </div>
      <div className="mt-1 break-words text-sm text-zinc-800 dark:text-zinc-200">{e.message || <span className="text-zinc-400">(no message)</span>}</div>
      {meta && (
        <>
          <button onClick={() => setOpen((o) => !o)} className="mt-1 inline-flex items-center gap-0.5 text-xs text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200">
            {open ? <ChevronDown className="size-3" /> : <ChevronRight className="size-3" />} Details
          </button>
          {open && (
            <pre className="thin-scroll mt-1 max-h-64 overflow-auto rounded-md border border-zinc-200 bg-zinc-50 p-2 font-mono text-[11px] text-zinc-700 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-300">
              {typeof e.meta === 'string' ? e.meta : JSON.stringify(e.meta, null, 2)}
            </pre>
          )}
        </>
      )}
    </li>
  )
}

export default function ActivityPage() {
  const [type, setType] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const q = useQuery({
    queryKey: ['events', type, page, pageSize],
    queryFn: () => api.events(type || undefined, page, pageSize),
    refetchInterval: 15_000,
    placeholderData: keepPreviousData, // keeps the filter options + rows on screen while a new page/filter loads
  })
  const items = q.data?.items ?? []
  const total = q.data?.total ?? items.length
  // Filter options come from the API (`types` = every distinct event type in the DB), never a hard-coded list.
  const apiTypes = q.data?.types?.filter(Boolean) ?? []
  const types = type && !apiTypes.includes(type) ? [type, ...apiTypes] : apiTypes

  return (
    <div className="space-y-5">
      <PageHeader
        title="Activity log"
        subtitle="Full audit trail: scans, rescans, deletions, reports, votes, bulk jobs, watchlist and settings changes, feed refreshes and exports."
        actions={
          <Select
            value={type}
            onChange={(e) => {
              setType(e.target.value)
              setPage(1)
            }}
            className="w-44"
          >
            <option value="">All event types</option>
            {types.map((t) => (
              <option key={t} value={t}>
                {titleCase(t)}
              </option>
            ))}
          </Select>
        }
      />
      <Card padded={false}>
        <div className="p-4">
          {q.error ? (
            <ErrorBox error={q.error} onRetry={() => q.refetch()} />
          ) : q.isLoading ? (
            <SkeletonRows rows={8} />
          ) : items.length === 0 ? (
            <EmptyState icon={<ActivityIcon className="size-5" />} title="No events" description={type ? `No “${titleCase(type)}” events recorded yet.` : 'Activity will appear here as you use PhishGuard.'} />
          ) : (
            <ol>
              {items.map((e) => (
                <Row key={e.id} e={e} />
              ))}
            </ol>
          )}
        </div>
        {total > 0 && (
          <Pagination
            page={page}
            pageSize={pageSize}
            total={total}
            onPage={setPage}
            onPageSize={(n) => {
              setPageSize(n)
              setPage(1)
            }}
          />
        )}
      </Card>
    </div>
  )
}
