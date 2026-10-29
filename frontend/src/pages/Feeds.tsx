import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Database, RefreshCw, Rss, Search } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, asList, type Feed, type FeedEntry } from '../api/client'
import { Card, CardHeader, PageHeader } from '../components/Card'
import { ChartCard, ChartTooltip, Legend } from '../components/ChartCard'
import { DataTable } from '../components/DataTable'
import { EmptyState } from '../components/EmptyState'
import { Skeleton } from '../components/Skeleton'
import { useToast } from '../components/Toast'
import { Button, Chip, ErrorBox, Input } from '../components/ui'
import { PALETTE, cx, fmtDate, fmtNum, fmtRel } from '../lib/format'

/** Normalise [{name,value}] | [{tld,count}] | [[name,count]] | {name: count} into NameValue[] */
function normalise(v: unknown, nameKeys: string[] = ['name', 'tld', 'domain', 'target']): { name: string; value: number }[] {
  if (!v) return []
  if (!Array.isArray(v) && typeof v === 'object') {
    return Object.entries(v as Record<string, unknown>).map(([name, value]) => ({ name, value: Number(value) || 0 }))
  }
  if (!Array.isArray(v)) return []
  return v
    .map((it) => {
      if (Array.isArray(it)) return { name: String(it[0]), value: Number(it[1]) || 0 }
      if (it && typeof it === 'object') {
        const o = it as Record<string, unknown>
        const nk = nameKeys.find((k) => o[k] != null)
        const value = Number(o.value ?? o.count ?? o.entries ?? 0) || 0
        return { name: String(nk ? o[nk] : '—'), value }
      }
      return { name: String(it), value: 0 }
    })
    .filter((x) => x.name)
}

function statusTone(s: string | null | undefined): 'emerald' | 'amber' | 'rose' | 'zinc' {
  const v = (s ?? '').toLowerCase()
  if (['ok', 'active', 'fresh', 'healthy', 'loaded'].includes(v)) return 'emerald'
  if (['stale', 'empty', 'pending', 'never'].includes(v)) return 'amber'
  if (v.includes('err') || v.includes('fail')) return 'rose'
  return 'zinc'
}

function FeedCard({ f }: { f: Feed }) {
  return (
    <Card>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Rss className="size-4 text-indigo-500" />
            <span className="truncate">{f.name}</span>
          </div>
          {f.url && (
            <a href={f.url} target="_blank" rel="noreferrer" className="mt-0.5 block truncate font-mono text-[11px] text-zinc-500 hover:underline" title={f.url}>
              {f.url}
            </a>
          )}
        </div>
        <Chip tone={statusTone(f.status)}>{f.status ?? 'unknown'}</Chip>
      </div>
      <div className="mt-3 flex items-end justify-between">
        <div>
          <div className="label">Entries</div>
          <div className="tnum text-xl font-semibold">{fmtNum(f.entries)}</div>
        </div>
        <div className="text-right">
          <div className="label">Updated</div>
          <div className="text-xs text-zinc-600 dark:text-zinc-400" title={fmtDate(f.last_updated)}>
            {f.last_updated ? fmtRel(f.last_updated) : 'Never'}
          </div>
        </div>
      </div>
    </Card>
  )
}

export default function FeedsPage() {
  const qc = useQueryClient()
  const toast = useToast()
  const [input, setInput] = useState('')
  const [term, setTerm] = useState('')
  const q = useQuery({ queryKey: ['feeds'], queryFn: api.feeds })
  const search = useQuery({ queryKey: ['feeds-search', term], queryFn: () => api.feedsSearch(term), enabled: term.length > 0 })
  const refresh = useMutation({
    mutationFn: api.feedsRefresh,
    onSuccess: (r) => {
      // Always HTTP 200: status is "ok" | "running" | "error: ..."
      const st = String(r?.status ?? 'ok')
      if (st.startsWith('error')) toast(`Feed refresh failed: ${st.replace(/^error:\s*/, '')}`, 'error')
      else if (st === 'running') toast('Refresh still running in the background', 'info')
      else toast('Feeds refreshed', 'success')
      qc.invalidateQueries({ queryKey: ['feeds'] })
      qc.invalidateQueries({ queryKey: ['health'] })
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Refresh failed', 'error'),
  })

  const feeds = q.data?.feeds ?? []
  const stats = q.data?.stats
  const byFeed = normalise(stats?.by_feed).length ? normalise(stats?.by_feed) : feeds.map((f) => ({ name: f.name, value: f.entries ?? 0 }))
  const tlds = normalise(stats?.top_domains_tlds).slice(0, 12)
  const targets = normalise(stats?.top_targets).slice(0, 10)
  const total = stats?.total_entries ?? byFeed.reduce((s, x) => s + x.value, 0)
  const entries = asList<FeedEntry>(search.data)

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTerm(input.trim())
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title="Threat feeds"
        subtitle="Local copies of public phishing/malware blocklists (OpenPhish, PhishTank, URLhaus …) used for reputation lookups."
        actions={
          <Button variant="primary" icon={<RefreshCw className={cx('size-4', refresh.isPending && 'animate-spin')} />} disabled={refresh.isPending} onClick={() => refresh.mutate()}>
            {refresh.isPending ? 'Refreshing…' : 'Refresh feeds'}
          </Button>
        }
      />
      {q.error && <ErrorBox error={q.error} onRetry={() => q.refetch()} />}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <div className="label">Total entries</div>
          {q.isLoading ? <Skeleton className="mt-2 h-7 w-24" /> : <div className="tnum mt-1 text-2xl font-semibold">{fmtNum(total)}</div>}
          <div className="mt-1 text-xs text-zinc-500">{feeds.length} feeds configured</div>
        </Card>
        {q.isLoading
          ? Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-28" />)
          : feeds.map((f) => <FeedCard key={f.name} f={f} />)}
      </div>
      {!q.isLoading && feeds.length === 0 && !q.error && (
        <Card>
          <EmptyState icon={<Database className="size-5" />} title="No feeds loaded" description="Click “Refresh feeds” to download the blocklists." />
        </Card>
      )}
      <div className="grid gap-4 lg:grid-cols-3">
        <ChartCard title="Entries by feed" loading={q.isLoading} empty={byFeed.length === 0} height={220}>
          <div className="flex h-full flex-col">
            <div className="min-h-0 flex-1">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={byFeed} dataKey="value" nameKey="name" innerRadius="55%" outerRadius="85%" paddingAngle={2} stroke="none" isAnimationActive={false}>
                    {byFeed.map((_, i) => (
                      <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <Legend items={byFeed.map((b, i) => ({ label: b.name, color: PALETTE[i % PALETTE.length], value: fmtCompactSafe(b.value) }))} />
          </div>
        </ChartCard>
        <ChartCard title="Top TLDs in feeds" loading={q.isLoading} empty={tlds.length === 0} height={220}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={tlds} margin={{ left: 0, right: 8 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="name" interval={0} angle={-30} textAnchor="end" height={40} />
              <YAxis allowDecimals={false} width={44} tickFormatter={(v: number) => fmtCompactSafe(v)} />
              <Tooltip content={<ChartTooltip />} cursor={{ fillOpacity: 0.05 }} />
              <Bar dataKey="value" name="Entries" fill="#6366f1" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="Top targeted brands" loading={q.isLoading} empty={targets.length === 0} height={220}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={targets} layout="vertical" margin={{ left: 10, right: 8 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" allowDecimals={false} tickFormatter={(v: number) => fmtCompactSafe(v)} />
              <YAxis type="category" dataKey="name" width={96} interval={0} tick={{ fontSize: 11 }} />
              <Tooltip content={<ChartTooltip />} cursor={{ fillOpacity: 0.05 }} />
              <Bar dataKey="value" name="Entries" fill="#f43f5e" radius={[0, 3, 3, 0]} barSize={10} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>
      <Card padded={false}>
        <div className="px-4 pt-4">
          <CardHeader title="Search feed entries" subtitle="Find a URL, domain or brand across all loaded feeds" />
          <form onSubmit={submit} className="mb-3 flex gap-2">
            <Input value={input} onChange={(e) => setInput(e.target.value)} placeholder="e.g. paypal, login-verify, .xyz" className="max-w-md" />
            <Button type="submit" icon={<Search className="size-4" />} loading={search.isFetching}>
              Search
            </Button>
          </form>
        </div>
        {term ? (
          <DataTable
            rows={entries}
            loading={search.isLoading}
            error={search.error}
            onRetry={() => search.refetch()}
            rowKey={(r, i) => `${r.url}-${i}`}
            maxHeight={480}
            columns={[
              { key: 'url', header: 'URL', render: (r) => <span className="block max-w-lg truncate font-mono text-xs" title={r.url}>{r.url}</span> },
              { key: 'domain', header: 'Domain', render: (r) => <span className="text-xs">{r.domain ?? '—'}</span> },
              { key: 'feed', header: 'Feed', render: (r) => (r.feed ? <Chip tone="indigo">{r.feed}</Chip> : '—') },
              { key: 'target', header: 'Target', render: (r) => r.target ?? <span className="text-zinc-400">—</span> },
            ]}
            empty={<EmptyState compact title={`No entries match “${term}”`} />}
          />
        ) : (
          <div className="px-4 pb-4 text-xs text-zinc-500">Enter a search term to query the feeds.</div>
        )}
      </Card>
    </div>
  )
}

function fmtCompactSafe(n: number) {
  return Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(n)
}
