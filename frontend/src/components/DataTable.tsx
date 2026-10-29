import type { ReactNode } from 'react'
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, ChevronsUpDown } from 'lucide-react'
import { cx, fmtNum } from '../lib/format'
import { EmptyState } from './EmptyState'
import { Skeleton } from './Skeleton'
import { ErrorBox } from './ui'

export interface Column<T> {
  key: string
  header: ReactNode
  render: (row: T, index: number) => ReactNode
  sortable?: boolean
  align?: 'left' | 'right' | 'center'
  className?: string
  width?: string | number
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  error,
  onRetry,
  onRowClick,
  sort,
  order,
  onSort,
  empty,
  dense,
  maxHeight,
}: {
  columns: Column<T>[]
  rows: T[] | null | undefined
  rowKey: (row: T, i: number) => string | number
  loading?: boolean
  error?: unknown
  onRetry?: () => void
  onRowClick?: (row: T) => void
  sort?: string
  order?: 'asc' | 'desc'
  onSort?: (key: string) => void
  empty?: ReactNode
  dense?: boolean
  maxHeight?: number
}) {
  if (error) return <ErrorBox error={error} onRetry={onRetry} />
  const list = rows ?? []
  return (
    <div className="thin-scroll w-full overflow-auto" style={maxHeight ? { maxHeight } : undefined}>
      <table className="w-full border-collapse text-sm">
        <thead className="sticky top-0 z-[1] bg-zinc-50/95 backdrop-blur dark:bg-zinc-900/95">
          <tr className="border-b border-zinc-200 dark:border-zinc-800">
            {columns.map((c) => {
              const active = sort === c.key
              return (
                <th
                  key={c.key}
                  style={c.width ? { width: c.width } : undefined}
                  className={cx(
                    'label whitespace-nowrap px-3 py-2 font-medium',
                    c.align === 'right' ? 'text-right' : c.align === 'center' ? 'text-center' : 'text-left',
                    c.sortable && onSort && 'cursor-pointer select-none hover:text-zinc-900 dark:hover:text-zinc-100',
                  )}
                  onClick={c.sortable && onSort ? () => onSort(c.key) : undefined}
                >
                  <span className="inline-flex items-center gap-1">
                    {c.header}
                    {c.sortable && onSort && (active ? order === 'asc' ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" /> : <ChevronsUpDown className="size-3 opacity-40" />)}
                  </span>
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {loading && list.length === 0
            ? Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} className="border-b border-zinc-100 dark:border-zinc-800/60">
                  {columns.map((c) => (
                    <td key={c.key} className="px-3 py-2.5">
                      <Skeleton className="h-4 w-full max-w-40" />
                    </td>
                  ))}
                </tr>
              ))
            : list.map((r, i) => (
                <tr
                  key={rowKey(r, i)}
                  onClick={onRowClick ? () => onRowClick(r) : undefined}
                  className={cx(
                    'border-b border-zinc-100 last:border-0 dark:border-zinc-800/60',
                    onRowClick && 'cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/40',
                  )}
                >
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      className={cx(
                        'px-3 tnum',
                        dense ? 'py-1.5' : 'py-2.5',
                        c.align === 'right' ? 'text-right' : c.align === 'center' ? 'text-center' : 'text-left',
                        c.className,
                      )}
                    >
                      {c.render(r, i)}
                    </td>
                  ))}
                </tr>
              ))}
        </tbody>
      </table>
      {!loading && list.length === 0 && (empty ?? <EmptyState compact title="Nothing to show" />)}
    </div>
  )
}

export function Pagination({ page, pageSize, total, onPage, onPageSize }: { page: number; pageSize: number; total: number; onPage: (p: number) => void; onPageSize?: (n: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(total, page * pageSize)
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-200 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-800">
      <span className="tnum">
        {fmtNum(from)}–{fmtNum(to)} of {fmtNum(total)}
      </span>
      <div className="flex items-center gap-2">
        {onPageSize && (
          <select
            value={pageSize}
            onChange={(e) => onPageSize(Number(e.target.value))}
            className="h-7 rounded border border-zinc-200 bg-white px-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900"
          >
            {[10, 25, 50, 100].map((n) => (
              <option key={n} value={n}>
                {n} / page
              </option>
            ))}
          </select>
        )}
        <button
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          className="rounded border border-zinc-200 p-1 disabled:opacity-40 dark:border-zinc-700"
          aria-label="Previous page"
        >
          <ChevronLeft className="size-3.5" />
        </button>
        <span className="tnum">
          {page} / {pages}
        </span>
        <button
          disabled={page >= pages}
          onClick={() => onPage(page + 1)}
          className="rounded border border-zinc-200 p-1 disabled:opacity-40 dark:border-zinc-700"
          aria-label="Next page"
        >
          <ChevronRight className="size-3.5" />
        </button>
      </div>
    </div>
  )
}
