import type { ReactNode } from 'react'
import { Card, CardHeader } from './Card'
import { EmptyState } from './EmptyState'
import { Skeleton } from './Skeleton'
import { ErrorBox } from './ui'
import { fmtNum } from '../lib/format'

export function ChartCard({
  title,
  subtitle,
  right,
  loading,
  error,
  empty,
  height = 240,
  children,
  className,
  onRetry,
}: {
  title: ReactNode
  subtitle?: ReactNode
  right?: ReactNode
  loading?: boolean
  error?: unknown
  empty?: boolean
  height?: number
  children: ReactNode
  className?: string
  onRetry?: () => void
}) {
  return (
    <Card className={className}>
      <CardHeader title={title} subtitle={subtitle} right={right} />
      {error ? (
        <ErrorBox error={error} onRetry={onRetry} />
      ) : loading ? (
        <div style={{ height }} className="w-full">
          <Skeleton className="h-full w-full" />
        </div>
      ) : empty ? (
        <div style={{ minHeight: Math.min(height, 200) }} className="flex items-center justify-center">
          <EmptyState compact title="No data for this range" />
        </div>
      ) : (
        <div style={{ height }} className="w-full min-w-0">
          {children}
        </div>
      )}
    </Card>
  )
}

interface TooltipPayloadItem {
  name?: string | number
  value?: number | string | (number | string)[]
  color?: string
  fill?: string
  stroke?: string
  dataKey?: string | number
  payload?: Record<string, unknown>
}

/** Shared Recharts tooltip. */
export function ChartTooltip({
  active,
  payload,
  label,
  labelFormatter,
  valueFormatter,
}: {
  active?: boolean
  payload?: TooltipPayloadItem[]
  label?: string | number
  labelFormatter?: (l: string | number) => ReactNode
  valueFormatter?: (v: number, name?: string) => ReactNode
}) {
  if (!active || !payload || payload.length === 0) return null
  return (
    <div className="rounded-md border border-zinc-200 bg-white/95 px-2.5 py-2 text-xs shadow-md backdrop-blur dark:border-zinc-700 dark:bg-zinc-900/95">
      {label !== undefined && label !== '' && (
        <div className="mb-1 font-medium text-zinc-700 dark:text-zinc-200">{labelFormatter ? labelFormatter(label) : String(label)}</div>
      )}
      <div className="space-y-0.5">
        {payload.map((p, i) => {
          const raw = Array.isArray(p.value) ? p.value.join(' – ') : p.value
          const num = typeof raw === 'number' ? raw : Number(raw)
          return (
            <div key={i} className="flex items-center justify-between gap-4">
              <span className="flex items-center gap-1.5 text-zinc-500 dark:text-zinc-400">
                <span className="size-2 rounded-sm" style={{ background: p.color ?? p.fill ?? p.stroke ?? '#6366f1' }} />
                {String(p.name ?? p.dataKey ?? '')}
              </span>
              <span className="tnum font-medium text-zinc-900 dark:text-zinc-100">
                {valueFormatter && !Number.isNaN(num) ? valueFormatter(num, String(p.name ?? '')) : typeof raw === 'number' ? fmtNum(raw, Number.isInteger(raw) ? 0 : 2) : String(raw ?? '')}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function Legend({ items }: { items: { label: ReactNode; color: string; value?: ReactNode }[] }) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1">
      {items.map((it, i) => (
        <span key={i} className="inline-flex items-center gap-1.5 text-xs text-zinc-600 dark:text-zinc-400">
          <span className="size-2 rounded-sm" style={{ background: it.color }} />
          {it.label}
          {it.value !== undefined && <span className="tnum font-medium text-zinc-900 dark:text-zinc-100">{it.value}</span>}
        </span>
      ))}
    </div>
  )
}
