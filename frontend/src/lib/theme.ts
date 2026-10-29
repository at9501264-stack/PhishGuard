import { useCallback, useEffect, useState } from 'react'
import { safeGet, safeSet } from './format'

export type ThemePref = 'light' | 'dark' | 'system'

function systemDark() {
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches
  } catch {
    return false
  }
}

function apply(pref: ThemePref) {
  const dark = pref === 'dark' || (pref === 'system' && systemDark())
  document.documentElement.classList.toggle('dark', dark)
  return dark
}

export function useTheme() {
  const [pref, setPref] = useState<ThemePref>(() => {
    const v = safeGet('pg-theme')
    return v === 'light' || v === 'dark' ? v : 'system'
  })
  const [isDark, setIsDark] = useState(() => document.documentElement.classList.contains('dark'))

  useEffect(() => {
    setIsDark(apply(pref))
    if (pref !== 'system') return
    let mq: MediaQueryList | null = null
    try {
      mq = window.matchMedia('(prefers-color-scheme: dark)')
    } catch {
      return
    }
    const onChange = () => setIsDark(apply('system'))
    mq.addEventListener('change', onChange)
    return () => mq?.removeEventListener('change', onChange)
  }, [pref])

  const set = useCallback((p: ThemePref) => {
    safeSet('pg-theme', p)
    setPref(p)
  }, [])

  const cycle = useCallback(() => {
    set(pref === 'system' ? (isDark ? 'light' : 'dark') : pref === 'dark' ? 'light' : 'dark')
  }, [pref, isDark, set])

  return { pref, isDark, set, cycle }
}
