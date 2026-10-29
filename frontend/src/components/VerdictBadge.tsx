import { ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import type { Verdict } from '../api/client'
import { VERDICT_LABEL, cx, isVerdict } from '../lib/format'

const styles: Record<Verdict, string> = {
  legitimate: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-400 dark:ring-emerald-500/30',
  suspicious: 'bg-amber-50 text-amber-700 ring-amber-600/20 dark:bg-amber-500/10 dark:text-amber-400 dark:ring-amber-500/30',
  phishing: 'bg-rose-50 text-rose-700 ring-rose-600/20 dark:bg-rose-500/10 dark:text-rose-400 dark:ring-rose-500/30',
}
const dots: Record<Verdict, string> = { legitimate: 'bg-emerald-500', suspicious: 'bg-amber-500', phishing: 'bg-rose-500' }

export function VerdictBadge({ verdict, size = 'sm', icon = false }: { verdict: Verdict | string | null | undefined; size?: 'sm' | 'lg'; icon?: boolean }) {
  if (!isVerdict(verdict)) return <span className="text-xs text-zinc-400">—</span>
  const Icon = verdict === 'legitimate' ? ShieldCheck : verdict === 'suspicious' ? ShieldQuestion : ShieldAlert
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 rounded-full font-medium ring-1 ring-inset',
        size === 'lg' ? 'px-3 py-1 text-sm' : 'px-2 py-0.5 text-[11px]',
        styles[verdict],
      )}
    >
      {icon ? <Icon className={size === 'lg' ? 'size-4' : 'size-3'} /> : <span className={cx('size-1.5 rounded-full', dots[verdict])} />}
      {VERDICT_LABEL[verdict]}
    </span>
  )
}

export function RiskPill({ score }: { score: number | null | undefined }) {
  if (score == null) return <span className="text-zinc-400">—</span>
  const c = score >= 65 ? 'text-rose-600 dark:text-rose-400' : score >= 35 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
  return (
    <span className="inline-flex items-center gap-2">
      <span className="h-1.5 w-12 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
        <span
          className="block h-full rounded-full"
          style={{ width: `${Math.max(2, Math.min(100, score))}%`, background: score >= 65 ? '#f43f5e' : score >= 35 ? '#f59e0b' : '#10b981' }}
        />
      </span>
      <span className={cx('tnum text-xs font-semibold', c)}>{Math.round(score)}</span>
    </span>
  )
}
