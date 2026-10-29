import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Building, Network, Server } from 'lucide-react'
import { apiV2, qk, type ScanSummaryV2 } from '../../api/client_v2'
import { Card, CardHeader } from '../../components/Card'
import { VerdictBadge } from '../../components/VerdictBadge'
import { cx, fmtRel, hostOf } from '../../lib/format'

/** Rows shown per group before "Show all". */
const SHOW = 5
const COLS = ['', '', 'md:grid-cols-2', 'md:grid-cols-3']

/** Other scans sharing this scan's IP / ASN / registrar (G3). Renders nothing when there are none. */
export default function RelatedScans({ scanId }: { scanId: number }) {
  const q = useQuery({ queryKey: qk.scanSimilar(scanId), queryFn: () => apiV2.similar(scanId) })
  const d = q.data
  const notSelf = (list: ScanSummaryV2[] | null | undefined) => (list ?? []).filter((s) => s.id !== scanId)
  const groups = [
    { key: 'ip', title: 'Same IP address', Icon: Server, items: notSelf(d?.same_ip) },
    { key: 'asn', title: 'Same network (ASN)', Icon: Network, items: notSelf(d?.same_asn) },
    { key: 'registrar', title: 'Same registrar', Icon: Building, items: notSelf(d?.same_registrar) },
  ].filter((g) => g.items.length > 0)

  if (!groups.length) return null

  return (
    <Card>
      <CardHeader title="Related scans" subtitle="Other scanned sites that share this site's infrastructure" />
      <div className={cx('grid gap-4', COLS[groups.length])}>
        {groups.map((g) => (
          <Group key={g.key} title={g.title} Icon={g.Icon} items={g.items} />
        ))}
      </div>
    </Card>
  )
}

function Group({ title, Icon, items }: { title: string; Icon: typeof Server; items: ScanSummaryV2[] }) {
  const [all, setAll] = useState(false)
  const shown = all ? items : items.slice(0, SHOW)
  return (
    <div className="min-w-0">
      <div className="mb-1 flex items-center gap-1.5 text-xs font-medium text-zinc-500">
        <Icon className="size-3.5" />
        {title}
        <span className="tnum rounded bg-zinc-100 px-1.5 text-[11px] text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400">{items.length}</span>
      </div>
      <ul className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
        {shown.map((s) => (
          <li key={s.id}>
            <Link to={`/scans/${s.id}`} className="flex items-center gap-2 py-1.5 hover:text-indigo-600 dark:hover:text-indigo-400">
              <span className="min-w-0 flex-1 truncate font-mono text-xs" title={s.url}>
                {s.domain || hostOf(s.url)}
              </span>
              <VerdictBadge verdict={s.verdict} />
              <span className="w-14 shrink-0 text-right text-[11px] text-zinc-400">{fmtRel(s.created_at)}</span>
            </Link>
          </li>
        ))}
      </ul>
      {items.length > SHOW && (
        <button type="button" onClick={() => setAll(!all)} className="mt-1 text-xs text-indigo-600 hover:underline dark:text-indigo-400">
          {all ? 'Show less' : `Show all ${items.length}`}
        </button>
      )}
    </div>
  )
}
