import type { ReactNode } from 'react'
import { cx } from '../lib/format'

export interface TabDef<T extends string = string> {
  id: T
  label: ReactNode
  icon?: ReactNode
  count?: number | null
}

export function Tabs<T extends string>({ tabs, value, onChange, className }: { tabs: TabDef<T>[]; value: T; onChange: (v: T) => void; className?: string }) {
  return (
    <div className={cx('no-print thin-scroll -mx-1 overflow-x-auto border-b border-zinc-200 dark:border-zinc-800', className)}>
      <div className="flex min-w-max gap-1 px-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => onChange(t.id)}
            className={cx(
              '-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm font-medium transition-colors',
              value === t.id
                ? 'border-indigo-500 text-zinc-900 dark:text-zinc-100'
                : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200',
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
    </div>
  )
}
