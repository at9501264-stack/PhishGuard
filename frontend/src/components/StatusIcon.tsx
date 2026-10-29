import { AlertTriangle, CheckCircle2, CircleSlash, Info, XCircle } from 'lucide-react'
import type { CheckStatus } from '../api/client'
import { cx } from '../lib/format'

export function StatusIcon({ status, className }: { status: CheckStatus | string | null | undefined; className?: string }) {
  const c = cx('size-4 shrink-0', className)
  switch (status) {
    case 'pass':
      return <CheckCircle2 className={cx(c, 'text-emerald-500')} />
    case 'warn':
      return <AlertTriangle className={cx(c, 'text-amber-500')} />
    case 'fail':
      return <XCircle className={cx(c, 'text-rose-500')} />
    case 'error':
      return <CircleSlash className={cx(c, 'text-zinc-400')} />
    default:
      return <Info className={cx(c, 'text-sky-500')} />
  }
}

export function BoolIcon({ value, invert }: { value: boolean | null | undefined; invert?: boolean }) {
  if (value == null) return <span className="text-zinc-400">—</span>
  const good = invert ? !value : value
  return good ? <CheckCircle2 className="size-4 text-emerald-500" /> : <XCircle className="size-4 text-rose-500" />
}
