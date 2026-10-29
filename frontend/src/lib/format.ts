import type { Verdict } from '../api/client'

export const VERDICTS: Verdict[] = ['legitimate', 'suspicious', 'phishing']

export const VERDICT_COLOR: Record<Verdict, string> = {
  legitimate: '#10b981', // emerald-500
  suspicious: '#f59e0b', // amber-500
  phishing: '#f43f5e', // rose-500
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  legitimate: 'Legitimate',
  suspicious: 'Suspicious',
  phishing: 'Phishing',
}

export const ACCENT = '#6366f1'

/** Categorical palette (indigo-led, distinguishable in both themes). */
export const PALETTE = ['#6366f1', '#06b6d4', '#8b5cf6', '#f59e0b', '#10b981', '#f43f5e', '#64748b', '#ec4899', '#84cc16', '#0ea5e9']

export function isVerdict(v: unknown): v is Verdict {
  return v === 'legitimate' || v === 'suspicious' || v === 'phishing'
}

export function riskColor(score: number | null | undefined, sus = 35, phish = 65): string {
  if (score == null || Number.isNaN(score)) return '#a1a1aa'
  if (score >= phish) return VERDICT_COLOR.phishing
  if (score >= sus) return VERDICT_COLOR.suspicious
  return VERDICT_COLOR.legitimate
}

export function fmtNum(n: number | null | undefined, digits = 0): string {
  if (n == null || Number.isNaN(Number(n))) return '—'
  return Number(n).toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits })
}

export function fmtCompact(n: number | null | undefined): string {
  if (n == null || Number.isNaN(Number(n))) return '—'
  return Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(Number(n))
}

/** Accepts a ratio (0-1) or percentage (>1) and returns "12.3%". */
export function fmtPct(n: number | null | undefined, digits = 1, isRatio?: boolean): string {
  if (n == null || Number.isNaN(Number(n))) return '—'
  const v = isRatio === true || (isRatio === undefined && Math.abs(n) <= 1) ? n * 100 : n
  return `${v.toFixed(digits)}%`
}

export function fmtMs(ms: number | null | undefined): string {
  if (ms == null || Number.isNaN(Number(ms))) return '—'
  if (ms >= 10000) return `${(ms / 1000).toFixed(1)} s`
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`
  return `${Math.round(ms)} ms`
}

export function parseDate(s: string | null | undefined): Date | null {
  if (!s) return null
  // Treat naive timestamps as UTC (SPEC: ISO-8601 UTC)
  const hasTz = /[zZ]|[+-]\d\d:?\d\d$/.test(s)
  const d = new Date(hasTz || s.length <= 10 ? s : `${s}Z`)
  return Number.isNaN(d.getTime()) ? null : d
}

export function fmtDate(s: string | null | undefined, withTime = true): string {
  const d = parseDate(s)
  if (!d) return '—'
  return d.toLocaleString(undefined, withTime
    ? { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }
    : { year: 'numeric', month: 'short', day: '2-digit' })
}

export function fmtRel(s: string | null | undefined): string {
  const d = parseDate(s)
  if (!d) return '—'
  const diff = (Date.now() - d.getTime()) / 1000
  const abs = Math.abs(diff)
  const suffix = diff >= 0 ? 'ago' : 'from now'
  if (abs < 45) return 'just now'
  if (abs < 3600) return `${Math.round(abs / 60)}m ${suffix}`
  if (abs < 86400) return `${Math.round(abs / 3600)}h ${suffix}`
  if (abs < 86400 * 30) return `${Math.round(abs / 86400)}d ${suffix}`
  return fmtDate(s, false)
}

/** Short axis label for a bucket timestamp. */
export function fmtTick(s: string, bucket: 'hour' | 'day' = 'day'): string {
  const d = parseDate(s)
  if (!d) return s
  return bucket === 'hour'
    ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

export function truncate(s: string | null | undefined, n = 60): string {
  if (!s) return ''
  return s.length > n ? `${s.slice(0, n - 1)}…` : s
}

export function titleCase(s: string | null | undefined): string {
  if (!s) return ''
  return s.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

export function hostOf(url: string): string {
  try {
    return new URL(/^[a-z]+:\/\//i.test(url) ? url : `http://${url}`).hostname
  } catch {
    return url
  }
}

export function flagEmoji(code: string | null | undefined): string {
  if (!code || code.length !== 2) return ''
  const cc = code.toUpperCase()
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}

export function downloadBlob(filename: string, content: string, type = 'application/json') {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    try {
      const ta = document.createElement('textarea')
      ta.value = text
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      ta.remove()
      return true
    } catch {
      return false
    }
  }
}

export function safeGet(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

export function safeSet(key: string, value: string) {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* ignore */
  }
}

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ')
}
