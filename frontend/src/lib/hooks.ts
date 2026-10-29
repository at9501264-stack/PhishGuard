import { useEffect, useState } from 'react'
import type { Range } from '../api/client'
import { safeGet, safeSet } from './format'

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}

/** Range selection persisted per-viewer. */
export function useRange(key = 'pg-range', initial: Range = '30d'): [Range, (r: Range) => void] {
  const [r, setR] = useState<Range>(() => {
    const v = safeGet(key)
    return v === '24h' || v === '7d' || v === '30d' || v === '90d' || v === 'all' ? v : initial
  })
  return [
    r,
    (n: Range) => {
      safeSet(key, n)
      setR(n)
    },
  ]
}

export function bucketFor(range: Range): 'hour' | 'day' {
  return range === '24h' || range === '7d' ? 'hour' : 'day'
}
