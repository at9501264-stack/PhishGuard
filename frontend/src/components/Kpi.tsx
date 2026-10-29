import type { ReactNode } from 'react'
import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react'
import { Area, AreaChart, ResponsiveContainer } from 'recharts'
import { cx } from '../lib/format'
import { Skeleton } from './Skeleton'

export function Sparkline({ data, color = '#6366f1', height = 32 }: { data: number[]; color?: string; height?: number }) {
  if (!data || data.length < 2) return <div style={{ height }} />
  const id = `sp-${color.replace('#', '')}`
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data.map((v, i) => ({ i, v }))} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.25} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          </defs>
          <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.5} fill={`url(#${id})`} isAnimationActive={false} dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

/**
 * KPI tile. `delta` is a percentage change vs previous period.
 * `goodWhen` controls colouring: for phishing counts an increase is bad.
 */
export function Kpi({
  label,
  value,
  sub,
  delta,
  goodWhen = 'up',
  spark,
  color,
  icon,
  loading,
}: {
  label: ReactNode
  value: ReactNode
  sub?: ReactNode
  delta?: number | null
  goodWhen?: 'up' | 'down' | 'neutral'
  spark?: number[]
  color?: string
  icon?: ReactNode
  loading?: boolean
}) {
  let deltaEl: ReactNode = null
  if (delta != null && !Number.isNaN(delta)) {
    const up = delta > 0.05
    const down = delta < -0.05
    const good = goodWhen === 'neutral' ? null : goodWhen === 'up' ? up : down
    const bad = goodWhen === 'neutral' ? null : goodWhen === 'up' ? down : up
    const Icon = up ? ArrowUpRight : down ? ArrowDownRight : Minus
    deltaEl = (
      <span
        className={cx(
          'inline-flex items-center gap-0.5 rounded px-1 text-[11px] font-medium tnum',
          good ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400' : bad ? 'bg-rose-50 text-rose-700 dark:bg-rose-500/10 dark:text-rose-400' : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400',
        )}
        title="vs previous period"
      >
        <Icon className="size-3" />
        {Math.abs(delta).toFixed(1)}%
      </span>
    )
  }
  return (
    <div className="print-break flex min-w-0 flex-col rounded-lg border border-zinc-200 bg-white p-3.5 dark:border-zinc-800 dark:bg-zinc-900/60">
      <div className="flex items-center justify-between gap-2">
        <span className="label truncate">{label}</span>
        {icon && <span className="text-zinc-400">{icon}</span>}
      </div>
      {loading ? (
        <Skeleton className="mt-2 h-7 w-20" />
      ) : (
        <div className="mt-1.5 flex items-baseline gap-2">
          <span className="tnum text-2xl font-semibold tracking-tight" style={color ? { color } : undefined}>
            {value}
          </span>
          {deltaEl}
        </div>
      )}
      {sub && <div className="mt-0.5 truncate text-xs text-zinc-500">{sub}</div>}
      {spark && spark.length > 1 && (
        <div className="mt-2">
          <Sparkline data={spark} color={color ?? '#6366f1'} />
        </div>
      )}
    </div>
  )
}
