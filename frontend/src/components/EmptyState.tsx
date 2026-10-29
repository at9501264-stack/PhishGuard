import type { ReactNode } from 'react'
import { Inbox } from 'lucide-react'
import { cx } from '../lib/format'

export function EmptyState({ title = 'No data yet', description, icon, action, compact }: { title?: ReactNode; description?: ReactNode; icon?: ReactNode; action?: ReactNode; compact?: boolean }) {
  return (
    <div className={cx('flex flex-col items-center justify-center text-center', compact ? 'py-6' : 'py-12')}>
      <div className="mb-2 rounded-full border border-zinc-200 p-2.5 text-zinc-400 dark:border-zinc-800">{icon ?? <Inbox className="size-5" />}</div>
      <div className="text-sm font-medium text-zinc-700 dark:text-zinc-300">{title}</div>
      {description && <div className="mt-1 max-w-sm text-xs text-zinc-500">{description}</div>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  )
}
