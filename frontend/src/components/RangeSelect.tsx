import type { Range } from '../api/client'
import { cx } from '../lib/format'

export const RANGES: Range[] = ['24h', '7d', '30d', '90d', 'all']

export function RangeSelect({ value, onChange }: { value: Range; onChange: (r: Range) => void }) {
  return <Segmented value={value} onChange={onChange} options={RANGES.map((r) => ({ value: r, label: r === 'all' ? 'All' : r }))} />
}

export function Segmented<T extends string>({ value, onChange, options }: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[] }) {
  return (
    <div className="inline-flex rounded-md border border-zinc-200 bg-white p-0.5 dark:border-zinc-800 dark:bg-zinc-900">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          className={cx(
            'rounded px-2.5 py-1 text-xs font-medium transition-colors',
            value === o.value
              ? 'bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900'
              : 'text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}
