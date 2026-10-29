import { Suspense, useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  BarChart3,
  Bell,
  BookOpen,
  BrainCircuit,
  ChevronsLeft,
  ChevronsRight,
  Eye,
  FileStack,
  History,
  Info,
  LayoutDashboard,
  Loader2,
  Menu,
  Monitor,
  Moon,
  Network,
  Rss,
  ScanSearch,
  Search,
  Settings,
  ShieldCheck,
  Spline,
  Sun,
  Terminal,
  Users,
  X,
} from 'lucide-react'
import { api, asList, type Alert, type Health } from '../api/client'
import { cx, fmtRel, safeGet, safeSet } from '../lib/format'
import { useTheme } from '../lib/theme'
import { useToast } from '../components/Toast'
import { Skeleton } from '../components/Skeleton'

const NAV: { to: string; label: string; icon: typeof LayoutDashboard; end?: boolean }[] = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/scan', label: 'Scan', icon: ScanSearch },
  { to: '/history', label: 'History', icon: History },
  { to: '/bulk', label: 'Bulk Scan', icon: FileStack },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/graph', label: 'Graph', icon: Network },
  { to: '/model', label: 'Model Lab', icon: BrainCircuit },
  { to: '/watchlist', label: 'Watchlist', icon: Eye },
  { to: '/typosquat', label: 'Typosquat', icon: Spline },
  { to: '/community', label: 'Community', icon: Users },
  { to: '/feeds', label: 'Threat Feeds', icon: Rss },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  { to: '/activity', label: 'Activity Log', icon: Activity },
  { to: '/settings', label: 'Settings', icon: Settings },
]

function Brand({ collapsed }: { collapsed: boolean }) {
  return (
    <Link to="/" className="flex h-14 items-center gap-2 px-4">
      <span className="flex size-7 items-center justify-center rounded-md bg-indigo-600 text-white">
        <ShieldCheck className="size-4" />
      </span>
      {!collapsed && (
        <span className="leading-tight">
          <span className="block text-sm font-semibold tracking-tight">PhishGuard</span>
          <span className="block text-[10px] uppercase tracking-wider text-zinc-500">Risk analysis</span>
        </span>
      )}
    </Link>
  )
}

function NavItems({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const linkCls = ({ isActive }: { isActive: boolean }) =>
    cx(
      'group flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors',
      isActive
        ? 'bg-zinc-100 font-medium text-zinc-900 dark:bg-zinc-800/80 dark:text-zinc-50'
        : 'text-zinc-600 hover:bg-zinc-100/70 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800/50 dark:hover:text-zinc-100',
      collapsed && 'justify-center px-0',
    )
  return (
    <nav className="thin-scroll flex-1 space-y-0.5 overflow-y-auto px-2 py-2">
      {NAV.map((n) => (
        <NavLink key={n.to} to={n.to} end={n.end} className={linkCls} onClick={onNavigate} title={collapsed ? n.label : undefined}>
          <n.icon className="size-4 shrink-0" />
          {!collapsed && <span className="truncate">{n.label}</span>}
        </NavLink>
      ))}
      <div className="my-2 border-t border-zinc-200 dark:border-zinc-800" />
      <a
        href="/docs"
        target="_blank"
        rel="noreferrer"
        title={collapsed ? 'API Docs (Swagger)' : undefined}
        className={linkCls({ isActive: false })}
      >
        <BookOpen className="size-4 shrink-0" />
        {!collapsed && <span className="truncate">API Docs ↗</span>}
      </a>
      <NavLink to="/api-guide" className={linkCls} onClick={onNavigate} title={collapsed ? 'API Guide' : undefined}>
        <Terminal className="size-4 shrink-0" />
        {!collapsed && <span className="truncate">API Guide</span>}
      </NavLink>
    </nav>
  )
}

function HealthDot({ collapsed }: { collapsed: boolean }) {
  const { data, isError } = useQuery({ queryKey: ['health'], queryFn: api.health, refetchInterval: 30_000, retry: false })
  const ok = !isError && data && (data.status === 'ok' || data.status === 'healthy' || data.status === undefined)
  return (
    <div className={cx('flex items-center gap-2 border-t border-zinc-200 px-4 py-3 text-xs text-zinc-500 dark:border-zinc-800', collapsed && 'justify-center px-0')}>
      <span className={cx('size-2 rounded-full', ok ? 'bg-emerald-500' : isError ? 'bg-rose-500' : 'bg-zinc-400')} />
      {!collapsed && (
        <span className="truncate">
          {isError ? 'API offline' : ok ? `API online · model ${data?.model_version ?? '—'}` : 'Connecting…'}
        </span>
      )}
    </div>
  )
}

function QuickScan() {
  const [url, setUrl] = useState('')
  const nav = useNavigate()
  const toast = useToast()
  const qc = useQueryClient()
  const m = useMutation({
    mutationFn: (u: string) => api.scan(u, false, 'web'),
    onSuccess: (r) => {
      setUrl('')
      qc.invalidateQueries()
      nav(`/scans/${r.id}`)
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Scan failed', 'error'),
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const u = url.trim()
    if (u) m.mutate(u)
  }
  return (
    <form onSubmit={submit} className="relative w-full max-w-xl">
      <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-zinc-400" />
      <input
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="Quick scan a URL…  e.g. paypal-login.secure-verify.com"
        className="h-9 w-full rounded-md border border-zinc-200 bg-zinc-50 pl-8 pr-20 text-sm placeholder:text-zinc-400 focus:border-indigo-500 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 dark:border-zinc-800 dark:bg-zinc-900 dark:focus:bg-zinc-900"
      />
      <button
        type="submit"
        disabled={m.isPending || !url.trim()}
        className="absolute right-1 top-1 inline-flex h-7 items-center gap-1 rounded bg-indigo-600 px-2.5 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
      >
        {m.isPending ? <Loader2 className="size-3 animate-spin" /> : null}
        {m.isPending ? 'Scanning' : 'Scan'}
      </button>
    </form>
  )
}

const sevDot: Record<string, string> = { critical: 'bg-rose-500', warning: 'bg-amber-500', info: 'bg-sky-500' }

function AlertsBell() {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['alerts', 'bell'], queryFn: () => api.alerts(), refetchInterval: 20_000, retry: false })
  const list = asList<Alert>(data)
  const unread = list.filter((a) => !a.read)
  const readAll = useMutation({ mutationFn: api.alertsReadAll, onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }) })
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])
  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="relative rounded-md p-2 text-zinc-500 hover:bg-zinc-100 hover:text-zinc-900 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
        aria-label="Alerts"
      >
        <Bell className="size-4" />
        {unread.length > 0 && (
          <span className="tnum absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-rose-500 px-1 text-[10px] font-semibold text-white">
            {unread.length > 99 ? '99+' : unread.length}
          </span>
        )}
      </button>
      {open && (
        <div className="absolute right-0 z-40 mt-2 w-80 overflow-hidden rounded-lg border border-zinc-200 bg-white shadow-lg dark:border-zinc-800 dark:bg-zinc-900">
          <div className="flex items-center justify-between border-b border-zinc-200 px-3 py-2 dark:border-zinc-800">
            <span className="text-sm font-semibold">Alerts</span>
            <button
              className="text-xs text-indigo-600 hover:underline disabled:opacity-50 dark:text-indigo-400"
              disabled={unread.length === 0 || readAll.isPending}
              onClick={() => readAll.mutate()}
            >
              Mark all read
            </button>
          </div>
          <div className="thin-scroll max-h-80 overflow-y-auto">
            {list.length === 0 ? (
              <div className="px-3 py-6 text-center text-xs text-zinc-500">No alerts</div>
            ) : (
              list.slice(0, 8).map((a) => (
                <Link
                  key={a.id}
                  to={a.scan_id ? `/scans/${a.scan_id}` : '/alerts'}
                  onClick={() => setOpen(false)}
                  className={cx('flex gap-2 border-b border-zinc-100 px-3 py-2 last:border-0 hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-800/50', !a.read && 'bg-indigo-50/40 dark:bg-indigo-500/5')}
                >
                  <span className={cx('mt-1.5 size-1.5 shrink-0 rounded-full', sevDot[a.severity ?? 'info'] ?? 'bg-zinc-400')} />
                  <span className="min-w-0">
                    <span className="block truncate text-sm">{a.title}</span>
                    <span className="block truncate text-xs text-zinc-500">
                      {fmtRel(a.created_at)} {a.detail ? `· ${a.detail}` : ''}
                    </span>
                  </span>
                </Link>
              ))
            )}
          </div>
          <Link to="/alerts" onClick={() => setOpen(false)} className="block border-t border-zinc-200 px-3 py-2 text-center text-xs text-zinc-600 hover:bg-zinc-50 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800/50">
            View all alerts
          </Link>
        </div>
      )}
    </div>
  )
}

/** Shown when GET /api/health reports `cloud: true` (PHISHGUARD_CLOUD demo deployment). */
function DemoBanner() {
  const [hidden, setHidden] = useState(() => safeGet('pg-demo-banner') === 'dismissed')
  const { data } = useQuery({ queryKey: ['health'], queryFn: api.health, refetchInterval: 30_000, retry: false })
  if (hidden || !(data as (Health & { cloud?: boolean }) | undefined)?.cloud) return null
  const dismiss = () => {
    safeSet('pg-demo-banner', 'dismissed')
    setHidden(true)
  }
  return (
    <div className="no-print flex items-center gap-2 border-b border-amber-200 bg-amber-50 px-4 py-2 text-xs text-amber-800 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-300">
      <Info className="size-4 shrink-0" />
      <span className="flex-1">Demo mode - data resets periodically.</span>
      <button onClick={dismiss} className="rounded p-1 hover:bg-amber-100 dark:hover:bg-amber-500/20" aria-label="Dismiss demo banner">
        <X className="size-3.5" />
      </button>
    </div>
  )
}

/** Suspense fallback while a lazily loaded page chunk downloads. */
function PageSkeleton() {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Loading page">
      <Skeleton className="h-8 w-56" />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-72 w-full" />
    </div>
  )
}

function ThemeToggle() {
  const { pref, isDark, set } = useTheme()
  const next = pref === 'light' ? 'dark' : pref === 'dark' ? 'system' : 'light'
  const Icon = pref === 'system' ? Monitor : isDark ? Moon : Sun
  return (
    <button
      onClick={() => set(next)}
      className="rounded-md p-2 text-zinc-500 hover:bg-zinc-100 hover:text-zinc-900 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
      title={`Theme: ${pref} (click for ${next})`}
      aria-label="Toggle theme"
    >
      <Icon className="size-4" />
    </button>
  )
}

export function Layout() {
  const [collapsed, setCollapsed] = useState(() => safeGet('pg-sidebar') === 'collapsed')
  const [drawer, setDrawer] = useState(false)
  const loc = useLocation()
  useEffect(() => setDrawer(false), [loc.pathname])
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [loc.pathname])
  const toggle = () => {
    setCollapsed((c) => {
      safeSet('pg-sidebar', c ? 'expanded' : 'collapsed')
      return !c
    })
  }
  return (
    <div className="flex min-h-full">
      {/* Desktop sidebar */}
      <aside
        className={cx(
          'no-print sticky top-0 hidden h-screen shrink-0 flex-col border-r border-zinc-200 bg-white transition-[width] duration-200 md:flex dark:border-zinc-800 dark:bg-zinc-900/40',
          collapsed ? 'w-14' : 'w-56',
        )}
      >
        <Brand collapsed={collapsed} />
        <NavItems collapsed={collapsed} />
        <button
          onClick={toggle}
          className={cx('mx-2 mb-1 flex items-center gap-2 rounded-md px-2.5 py-1.5 text-xs text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800', collapsed && 'justify-center px-0')}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronsRight className="size-4" /> : <ChevronsLeft className="size-4" />}
          {!collapsed && 'Collapse'}
        </button>
        <HealthDot collapsed={collapsed} />
      </aside>

      {/* Mobile drawer */}
      {drawer && (
        <div className="no-print fixed inset-0 z-50 md:hidden">
          <div className="absolute inset-0 bg-zinc-950/40" onClick={() => setDrawer(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-64 flex-col border-r border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
            <div className="flex items-center justify-between pr-2">
              <Brand collapsed={false} />
              <button onClick={() => setDrawer(false)} className="rounded p-1.5 text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800" aria-label="Close menu">
                <X className="size-4" />
              </button>
            </div>
            <NavItems collapsed={false} onNavigate={() => setDrawer(false)} />
            <HealthDot collapsed={false} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="no-print sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-zinc-200 bg-white/80 px-3 backdrop-blur md:px-5 dark:border-zinc-800 dark:bg-zinc-950/80">
          <button onClick={() => setDrawer(true)} className="rounded-md p-2 text-zinc-500 hover:bg-zinc-100 md:hidden dark:hover:bg-zinc-800" aria-label="Open menu">
            <Menu className="size-4" />
          </button>
          <div className="flex min-w-0 flex-1">
            <QuickScan />
          </div>
          <AlertsBell />
          <ThemeToggle />
        </header>
        <DemoBanner />
        <main className="print-full mx-auto w-full max-w-[1400px] flex-1 px-4 py-5 md:px-6">
          <Suspense fallback={<PageSkeleton />}>
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  )
}
