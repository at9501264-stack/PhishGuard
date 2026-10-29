import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, Bell, Clock, Eye, Flag, Layers, RefreshCw, ScanSearch, ShieldAlert, ThumbsUp } from 'lucide-react'
import { apiV2, qk } from '../../api/client_v2'
import { EmptyState } from '../../components/EmptyState'
import { SkeletonRows } from '../../components/Skeleton'
import { ErrorBox } from '../../components/ui'
import { cx, fmtDate, fmtRel, parseDate, titleCase } from '../../lib/format'

type Icon = typeof Activity

const TONES = {
  indigo: 'bg-indigo-100 text-indigo-600 dark:bg-indigo-500/15 dark:text-indigo-400',
  emerald: 'bg-emerald-100 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-400',
  amber: 'bg-amber-100 text-amber-600 dark:bg-amber-500/15 dark:text-amber-400',
  rose: 'bg-rose-100 text-rose-600 dark:bg-rose-500/15 dark:text-rose-400',
  zinc: 'bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400',
}

/** Pick an icon + colour from the event type name (e.g. "scan_completed", "report_created", "alert"). */
function look(type: string): { Icon: Icon; tone: keyof typeof TONES } {
  const t = type.toLowerCase()
  if (t.includes('rescan') || t.includes('recheck')) return { Icon: RefreshCw, tone: 'indigo' }
  if (t.includes('phish') || t.includes('blacklist')) return { Icon: ShieldAlert, tone: 'rose' }
  if (t.includes('alert')) return { Icon: Bell, tone: 'amber' }
  if (t.includes('vote')) return { Icon: ThumbsUp, tone: 'emerald' }
  if (t.includes('report')) return { Icon: Flag, tone: 'amber' }
  if (t.includes('watch')) return { Icon: Eye, tone: 'indigo' }
  if (t.includes('bulk')) return { Icon: Layers, tone: 'indigo' }
  if (t.includes('scan')) return { Icon: ScanSearch, tone: 'indigo' }
  return { Icon: Activity, tone: 'zinc' }
}

/** Everything that happened to this scan, oldest first. */
export default function TimelineTab({ scanId }: { scanId: number }) {
  const q = useQuery({ queryKey: qk.scanTimeline(scanId), queryFn: () => apiV2.timeline(scanId) })
  const events = useMemo(
    () => [...(q.data ?? [])].sort((a, b) => (parseDate(a.created_at)?.getTime() ?? 0) - (parseDate(b.created_at)?.getTime() ?? 0)),
    [q.data],
  )

  if (q.isLoading) return <SkeletonRows rows={5} />
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />
  if (!events.length) return <EmptyState icon={<Clock className="size-5" />} title="No events recorded for this scan yet" />

  return (
    <ol className="relative ml-3 border-l border-zinc-200 dark:border-zinc-800">
      {events.map((e) => {
        const { Icon, tone } = look(e.type || '')
        const hasMeta = !!e.meta && Object.keys(e.meta).length > 0
        return (
          <li key={e.id} className="mb-5 ml-6 last:mb-0">
            <span className={cx('absolute -left-3 flex size-6 items-center justify-center rounded-full ring-4 ring-white dark:ring-zinc-900', TONES[tone])}>
              <Icon className="size-3.5" />
            </span>
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{titleCase(e.type) || 'Event'}</span>
              <time className="text-xs text-zinc-500" title={fmtDate(e.created_at)}>
                {fmtRel(e.created_at)}
              </time>
            </div>
            {e.message && <p className="mt-0.5 text-sm text-zinc-600 dark:text-zinc-400">{e.message}</p>}
            {hasMeta && (
              <details className="mt-1 text-xs">
                <summary className="cursor-pointer select-none text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300">Details</summary>
                <pre className="thin-scroll mt-1 max-h-64 overflow-auto rounded-md border border-zinc-200 bg-zinc-50 p-2 font-mono text-[11px] text-zinc-700 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-300">
                  {JSON.stringify(e.meta, null, 2)}
                </pre>
              </details>
            )}
          </li>
        )
      })}
    </ol>
  )
}
