import type { ReactNode } from 'react'
import { cx } from '../lib/format'

export function Card({ children, className, padded = true }: { children: ReactNode; className?: string; padded?: boolean }) {
  return (
    <div
      className={cx(
        'print-break rounded-lg border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900/60',
        padded && 'p-4',
        className,
      )}
    >
      {children}
    </div>
  )
}

export function CardHeader({ title, subtitle, right, icon }: { title: ReactNode; subtitle?: ReactNode; right?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100">
          {icon && <span className="text-zinc-400">{icon}</span>}
          {title}
        </div>
        {subtitle && <div className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">{subtitle}</div>}
      </div>
      {right && <div className="flex flex-wrap items-center gap-2">{right}</div>}
    </div>
  )
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-50">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">{subtitle}</p>}
      </div>
      {actions && <div className="no-print flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

/** Key/value definition list used in report tabs. */
export function KV({ rows, cols = 2 }: { rows: [ReactNode, ReactNode][]; cols?: 1 | 2 | 3 }) {
  return (
    <dl className={cx('grid gap-x-6 gap-y-3', cols === 1 ? 'grid-cols-1' : cols === 2 ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3')}>
      {rows.map(([k, v], i) => (
        <div key={i} className="min-w-0">
          <dt className="label">{k}</dt>
          <dd className="mt-0.5 truncate text-sm text-zinc-800 tnum dark:text-zinc-200" title={typeof v === 'string' ? v : undefined}>
            {v === null || v === undefined || v === '' ? <span className="text-zinc-400">—</span> : v}
          </dd>
        </div>
      ))}
    </dl>
  )
}
