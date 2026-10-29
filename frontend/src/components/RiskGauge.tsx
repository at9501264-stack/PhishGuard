import { riskColor } from '../lib/format'

/** Semi-circular 0-100 gauge with verdict bands. */
export function RiskGauge({ score, size = 200, suspicious = 35, phishing = 65, label = 'Risk score' }: { score: number | null | undefined; size?: number; suspicious?: number; phishing?: number; label?: string }) {
  const s = Math.max(0, Math.min(100, Number(score ?? 0)))
  const w = size
  const h = size / 2 + 18
  const r = size / 2 - 14
  const cx = w / 2
  const cy = size / 2
  const pt = (v: number, rr = r) => {
    const a = Math.PI * (1 - v / 100)
    return [cx + rr * Math.cos(a), cy - rr * Math.sin(a)] as const
  }
  const arc = (from: number, to: number, rr = r) => {
    const [x1, y1] = pt(from, rr)
    const [x2, y2] = pt(to, rr)
    const large = to - from > 50 ? 1 : 0
    return `M ${x1} ${y1} A ${rr} ${rr} 0 ${large} 1 ${x2} ${y2}`
  }
  const color = riskColor(score, suspicious, phishing)
  const [nx, ny] = pt(s, r - 18)
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`${label} ${Math.round(s)} of 100`}>
      <path d={arc(0, 100)} className="stroke-zinc-100 dark:stroke-zinc-800" strokeWidth={14} fill="none" strokeLinecap="round" />
      <path d={arc(0, suspicious, r + 11)} stroke="#10b981" strokeOpacity={0.5} strokeWidth={3} fill="none" />
      <path d={arc(suspicious, phishing, r + 11)} stroke="#f59e0b" strokeOpacity={0.5} strokeWidth={3} fill="none" />
      <path d={arc(phishing, 100, r + 11)} stroke="#f43f5e" strokeOpacity={0.5} strokeWidth={3} fill="none" />
      {s > 0.5 && <path d={arc(0, s)} stroke={color} strokeWidth={14} fill="none" strokeLinecap="round" />}
      <line x1={cx} y1={cy} x2={nx} y2={ny} className="stroke-zinc-700 dark:stroke-zinc-300" strokeWidth={2} strokeLinecap="round" />
      <circle cx={cx} cy={cy} r={4} className="fill-zinc-700 dark:fill-zinc-300" />
      <text x={cx} y={cy - 22} textAnchor="middle" className="tnum fill-zinc-900 dark:fill-zinc-50" style={{ fontSize: size / 6, fontWeight: 600 }}>
        {score == null ? '—' : Math.round(s)}
      </text>
      <text x={14} y={h - 2} className="fill-zinc-400" style={{ fontSize: 10 }}>0</text>
      <text x={w - 14} y={h - 2} textAnchor="end" className="fill-zinc-400" style={{ fontSize: 10 }}>100</text>
      <text x={cx} y={h - 2} textAnchor="middle" className="fill-zinc-500" style={{ fontSize: 10, letterSpacing: 1 }}>
        {label.toUpperCase()}
      </text>
    </svg>
  )
}

/** Horizontal meter 0-1 or 0-100 */
export function Meter({ value, max = 1, color, label }: { value: number | null | undefined; max?: number; color?: string; label?: string }) {
  const v = Math.max(0, Math.min(1, Number(value ?? 0) / max))
  return (
    <div>
      {label && (
        <div className="mb-1 flex justify-between text-xs">
          <span className="text-zinc-500">{label}</span>
          <span className="tnum font-medium">{value == null ? '—' : `${Math.round(v * 100)}%`}</span>
        </div>
      )}
      <div className="h-2 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
        <div className="h-full rounded-full" style={{ width: `${v * 100}%`, background: color ?? riskColor(v * 100) }} />
      </div>
    </div>
  )
}
