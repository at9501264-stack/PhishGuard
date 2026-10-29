import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { ScanSearch, Spline } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/client'
import { Card, CardHeader, PageHeader } from '../components/Card'
import { ChartCard, ChartTooltip } from '../components/ChartCard'
import { DataTable } from '../components/DataTable'
import { EmptyState } from '../components/EmptyState'
import { Kpi } from '../components/Kpi'
import { useToast } from '../components/Toast'
import { Button, Chip, Input, Select, Toggle } from '../components/ui'
import { fmtNum, hostOf, titleCase } from '../lib/format'

export default function TyposquatPage() {
  const [params, setParams] = useSearchParams()
  const initial = params.get('domain') ?? ''
  const [input, setInput] = useState(initial)
  const [domain, setDomain] = useState(initial)
  const [onlyResolving, setOnlyResolving] = useState(false)
  const [technique, setTechnique] = useState('')
  const nav = useNavigate()
  const toast = useToast()

  useEffect(() => {
    const d = params.get('domain') ?? ''
    if (d && d !== domain) {
      setInput(d)
      setDomain(d)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params])

  const q = useQuery({ queryKey: ['typosquat', domain], queryFn: () => api.typosquat(domain), enabled: !!domain, staleTime: 5 * 60_000 })
  const all = q.data?.results ?? []

  const byTech = useMemo(() => {
    const m = new Map<string, { name: string; total: number; resolving: number }>()
    for (const r of all) {
      const k = r.technique || 'other'
      const e = m.get(k) ?? { name: k, total: 0, resolving: 0 }
      e.total++
      if (r.resolves) e.resolving++
      m.set(k, e)
    }
    return [...m.values()].sort((a, b) => b.total - a.total)
  }, [all])

  const rows = all.filter((r) => (!onlyResolving || r.resolves) && (!technique || r.technique === technique))
  const resolving = all.filter((r) => r.resolves).length

  const scan = useMutation({
    mutationFn: (d: string) => api.scan(d, false, 'web'),
    onSuccess: (r) => nav(`/scans/${r.id}`),
    onError: (e) => toast(e instanceof Error ? e.message : 'Scan failed', 'error'),
  })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const d = hostOf(input.trim()).replace(/^www\./, '')
    if (!d) return
    setDomain(d)
    setParams({ domain: d })
  }

  return (
    <div className="space-y-5">
      <PageHeader title="Typosquat finder" subtitle="Generate dnstwist-style permutations of a domain and check which ones resolve in DNS." />
      <Card>
        <form onSubmit={submit} className="flex flex-col gap-2 sm:flex-row">
          <Input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Brand domain, e.g. paypal.com" className="sm:max-w-md" />
          <Button type="submit" variant="primary" loading={q.isFetching} icon={<Spline className="size-4" />}>
            Generate
          </Button>
        </form>
        {q.isFetching && <p className="mt-2 text-xs text-zinc-500">Resolving permutations — this can take a few seconds…</p>}
      </Card>

      {!domain ? (
        <Card>
          <EmptyState icon={<Spline className="size-5" />} title="Enter a domain to begin" description="Techniques include omission, repetition, transposition, homoglyphs, bit-squatting, TLD swaps, hyphenation and more." />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Kpi label="Generated" value={fmtNum(q.data?.total_generated ?? all.length)} loading={q.isLoading} />
            <Kpi label="Checked" value={fmtNum(all.length)} loading={q.isLoading} />
            <Kpi label="Resolving" value={fmtNum(resolving)} color={resolving ? '#f43f5e' : undefined} loading={q.isLoading} />
            <Kpi label="Techniques" value={fmtNum(byTech.length)} loading={q.isLoading} />
          </div>
          <ChartCard title="Permutations by technique" subtitle="Total generated vs resolving" loading={q.isLoading} error={q.error} onRetry={() => q.refetch()} empty={byTech.length === 0} height={Math.max(200, byTech.length * 26)}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={byTech} layout="vertical" margin={{ left: 20, right: 16 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" allowDecimals={false} />
                <YAxis type="category" dataKey="name" width={110} tickFormatter={(v) => titleCase(String(v))} />
                <Tooltip content={<ChartTooltip />} cursor={{ fillOpacity: 0.05 }} />
                <Bar dataKey="total" name="Generated" fill="#6366f1" radius={[0, 3, 3, 0]} barSize={10} />
                <Bar dataKey="resolving" name="Resolving" fill="#f43f5e" radius={[0, 3, 3, 0]} barSize={10} />
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>
          <Card padded={false}>
            <div className="flex flex-wrap items-center justify-between gap-3 px-4 pt-4">
              <CardHeader title={`Permutations of ${domain}`} subtitle={`${rows.length} shown`} />
              <div className="mb-3 flex items-center gap-3">
                <Select value={technique} onChange={(e) => setTechnique(e.target.value)} className="w-44">
                  <option value="">All techniques</option>
                  {byTech.map((t) => (
                    <option key={t.name} value={t.name}>
                      {titleCase(t.name)} ({t.total})
                    </option>
                  ))}
                </Select>
                <Toggle checked={onlyResolving} onChange={setOnlyResolving} label="Resolving only" />
              </div>
            </div>
            <DataTable
              rows={rows}
              loading={q.isLoading}
              error={q.error}
              onRetry={() => q.refetch()}
              rowKey={(r, i) => `${r.domain}-${i}`}
              maxHeight={600}
              columns={[
                { key: 'domain', header: 'Domain', render: (r) => <span className="font-mono text-xs">{r.domain}</span> },
                { key: 'technique', header: 'Technique', render: (r) => <Chip>{titleCase(r.technique)}</Chip> },
                {
                  key: 'resolves',
                  header: 'Resolves',
                  render: (r) => (r.resolves ? <Chip tone="rose">Live</Chip> : r.resolves === false ? <span className="text-xs text-zinc-400">No</span> : <span className="text-zinc-400">—</span>),
                },
                { key: 'ip', header: 'IP', render: (r) => <span className="font-mono text-xs">{r.ip ?? '—'}</span> },
                {
                  key: 'scan',
                  header: '',
                  align: 'right',
                  render: (r) => (
                    <Button size="sm" variant="ghost" icon={<ScanSearch className="size-3.5" />} loading={scan.isPending && scan.variables === r.domain} disabled={scan.isPending} onClick={() => scan.mutate(r.domain)}>
                      Scan
                    </Button>
                  ),
                },
              ]}
              empty={<EmptyState compact title={onlyResolving ? 'No resolving permutations' : 'No permutations'} />}
            />
          </Card>
        </>
      )}
    </div>
  )
}
