import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, Download, FilterX, Search, SlidersHorizontal, Trash2, X } from 'lucide-react'
import {
  apiV2,
  CONTENT_CATEGORIES,
  PIVOT_FIELDS,
  THREAT_TYPE_LABEL,
  THREAT_TYPE_TONE,
  THREAT_TYPES,
  TIER_TONE,
  TIERS,
  threatTypeOf,
  tierOf,
  trustScoreOf,
  type ScanFiltersV2,
  type ScanSummaryV2,
} from '../api/client_v2'
import { Card, PageHeader } from '../components/Card'
import { DataTable, Pagination } from '../components/DataTable'
import { RiskPill, VerdictBadge } from '../components/VerdictBadge'
import { Modal } from '../components/Modal'
import { EmptyState } from '../components/EmptyState'
import { Button, Chip, Input, Select } from '../components/ui'
import { useToast } from '../components/Toast'
import { useDebounced } from '../lib/hooks'
import { flagEmoji, fmtDate, fmtMs, fmtRel, titleCase, truncate } from '../lib/format'

const SOURCES = ['web', 'api', 'bulk', 'text', 'qr', 'watch', 'extension', 'community']
const BASIC_KEYS = ['q', 'verdict', 'source', 'tld', 'brand', 'min_risk', 'max_risk', 'date_from', 'date_to'] as const
/** v2 pivot filters kept for the mini project (all synced with the URL, e.g. /history?ip=1.2.3.4). */
const PIVOT_KEYS = ['ip', 'asn', 'registrar', 'category', 'threat_type', 'tier'] as const
const FILTER_KEYS = [...BASIC_KEYS, ...PIVOT_KEYS]
type PivotKey = (typeof PIVOT_KEYS)[number]

const PIVOT_META = Object.fromEntries(PIVOT_FIELDS.map((f) => [f.key, f])) as Record<string, { label: string; placeholder: string }>
const LABEL: Record<string, string> = {
  q: 'Search',
  verdict: 'Verdict',
  source: 'Source',
  tld: 'TLD',
  brand: 'Brand',
  min_risk: 'Risk ≥',
  max_risk: 'Risk ≤',
  date_from: 'From',
  date_to: 'To',
  ...Object.fromEntries(PIVOT_KEYS.map((k) => [k, PIVOT_META[k]?.label ?? titleCase(k)])),
}

/** Dropdown options for the enum-like pivots; the rest are free text. */
const PIVOT_OPTIONS: Partial<Record<PivotKey, { value: string; label: string }[]>> = {
  category: CONTENT_CATEGORIES.map((c) => ({ value: c, label: titleCase(c) })),
  threat_type: THREAT_TYPES.map((t) => ({ value: t, label: THREAT_TYPE_LABEL[t] })),
  tier: TIERS.map((t) => ({ value: t, label: t })),
}

const valueLabel = (k: string, v: string) =>
  k === 'threat_type' ? (THREAT_TYPE_LABEL as Record<string, string>)[v] ?? titleCase(v) : k === 'category' ? titleCase(v) : v

const dash = <span className="text-zinc-400">—</span>

export default function History() {
  const [sp, setSp] = useSearchParams()
  const nav = useNavigate()
  const toast = useToast()
  const qc = useQueryClient()
  const [search, setSearch] = useState(sp.get('q') ?? '')
  const dq = useDebounced(search, 350)
  const [toDelete, setToDelete] = useState<ScanSummaryV2 | null>(null)
  const [advOpen, setAdvOpen] = useState(() => PIVOT_KEYS.some((k) => !!sp.get(k)))

  const get = (k: string) => sp.get(k) ?? ''
  const page = Number(sp.get('page') ?? 1) || 1
  const pageSize = Number(sp.get('page_size') ?? 25) || 25
  const sort = sp.get('sort') ?? 'created_at'
  const order = (sp.get('order') as 'asc' | 'desc') ?? 'desc'

  const update = (patch: Record<string, string | number | null>) => {
    const n = new URLSearchParams(sp)
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === '') n.delete(k)
      else n.set(k, String(v))
    }
    if (!('page' in patch)) n.delete('page')
    setSp(n, { replace: true })
  }

  const filters: ScanFiltersV2 = {
    q: dq || undefined,
    verdict: get('verdict') || undefined,
    source: get('source') || undefined,
    tld: get('tld') || undefined,
    brand: get('brand') || undefined,
    min_risk: get('min_risk') || undefined,
    max_risk: get('max_risk') || undefined,
    date_from: get('date_from') || undefined,
    date_to: get('date_to') || undefined,
    ip: get('ip') || undefined,
    asn: get('asn') || undefined,
    registrar: get('registrar') || undefined,
    category: get('category') || undefined,
    threat_type: get('threat_type') || undefined,
    tier: get('tier') || undefined,
    sort,
    order,
    page,
    page_size: pageSize,
  }

  const q = useQuery({ queryKey: ['scans', filters], queryFn: () => apiV2.scans(filters), placeholderData: keepPreviousData })
  const del = useMutation({
    mutationFn: (id: string | number) => apiV2.deleteScan(id),
    onSuccess: () => {
      toast('Scan deleted', 'success')
      setToDelete(null)
      qc.invalidateQueries({ queryKey: ['scans'] })
      qc.invalidateQueries({ queryKey: ['overview'] })
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Delete failed', 'error'),
  })

  const onSort = (key: string) => {
    if (key !== 'created_at' && key !== 'risk_score') return
    update({ sort: key, order: sort === key && order === 'desc' ? 'asc' : 'desc' })
  }
  const activeFilters = FILTER_KEYS.filter((k) => (k === 'q' ? !!dq : !!get(k)))
  const activePivots = PIVOT_KEYS.filter((k) => !!get(k)).length

  const removeFilter = (k: string) => {
    if (k === 'q') setSearch('')
    else update({ [k]: null })
  }
  const clearAll = () => {
    setSearch('')
    update(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])))
  }
  /** Row chips double as pivots: click to filter History by that value. */
  const pivotChip = (k: PivotKey, value: string, label: string, tone: Parameters<typeof Chip>[0]['tone']) => (
    <button
      title={`Show all scans with ${LABEL[k].toLowerCase()} ${label}`}
      onClick={(e) => {
        e.stopPropagation()
        update({ [k]: value })
      }}
    >
      <Chip tone={tone} className="whitespace-nowrap hover:opacity-80">
        {label}
      </Chip>
    </button>
  )

  return (
    <div className="space-y-4">
      <PageHeader
        title="Scan history"
        subtitle={q.data ? `${q.data.total.toLocaleString()} scans match` : 'All analysed URLs'}
        actions={
          <>
            <a href={apiV2.exportUrl('csv', filters)} download>
              <Button icon={<Download className="size-3.5" />}>CSV</Button>
            </a>
            <a href={apiV2.exportUrl('json', filters)} download>
              <Button icon={<Download className="size-3.5" />}>JSON</Button>
            </a>
          </>
        }
      />

      <Card className="!p-3">
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-8">
          <div className="relative col-span-2">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-zinc-400" />
            <Input
              className="pl-8"
              placeholder="Search URL or domain…"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                if (page !== 1) update({ page: null })
              }}
            />
          </div>
          <Select value={get('verdict')} onChange={(e) => update({ verdict: e.target.value })}>
            <option value="">All verdicts</option>
            <option value="phishing">Phishing</option>
            <option value="suspicious">Suspicious</option>
            <option value="legitimate">Legitimate</option>
          </Select>
          <Select value={get('source')} onChange={(e) => update({ source: e.target.value })}>
            <option value="">All sources</option>
            {SOURCES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
          <Input placeholder="TLD (e.g. com)" value={get('tld')} onChange={(e) => update({ tld: e.target.value.replace(/^\./, '') })} />
          <div className="flex items-center gap-1">
            <Input type="number" min={0} max={100} placeholder="Risk ≥" value={get('min_risk')} onChange={(e) => update({ min_risk: e.target.value })} />
            <Input type="number" min={0} max={100} placeholder="≤" value={get('max_risk')} onChange={(e) => update({ max_risk: e.target.value })} />
          </div>
          <Input type="date" title="From date" value={get('date_from')} onChange={(e) => update({ date_from: e.target.value })} />
          <Input type="date" title="To date" value={get('date_to')} onChange={(e) => update({ date_to: e.target.value })} />
        </div>

        <div className="mt-2">
          <button
            className="inline-flex items-center gap-1.5 text-xs font-medium text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100"
            onClick={() => setAdvOpen((o) => !o)}
            aria-expanded={advOpen}
          >
            <SlidersHorizontal className="size-3.5" />
            Advanced filters
            {activePivots > 0 && <Chip tone="indigo">{activePivots}</Chip>}
            <ChevronDown className={`size-3.5 transition-transform ${advOpen ? 'rotate-180' : ''}`} />
          </button>
          {advOpen && (
            <div className="mt-2 grid grid-cols-1 gap-2 rounded-md border border-zinc-200 p-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 dark:border-zinc-800">
              {PIVOT_KEYS.map((k) => {
                const opts = PIVOT_OPTIONS[k]
                return (
                  <label key={k} className="block space-y-1">
                    <span className="label">{LABEL[k]}</span>
                    {opts ? (
                      <Select value={get(k)} onChange={(e) => update({ [k]: e.target.value })}>
                        <option value="">Any</option>
                        {opts.map((o) => (
                          <option key={o.value} value={o.value}>
                            {o.label}
                          </option>
                        ))}
                      </Select>
                    ) : (
                      <Input placeholder={PIVOT_META[k]?.placeholder} value={get(k)} onChange={(e) => update({ [k]: e.target.value })} />
                    )}
                  </label>
                )
              })}
            </div>
          )}
        </div>

        {activeFilters.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {activeFilters.map((k) => (
              <Chip key={k} tone="indigo">
                {LABEL[k]}: {k === 'q' ? dq : valueLabel(k, get(k))}
                <button onClick={() => removeFilter(k)} className="-mr-0.5 rounded hover:bg-indigo-200/60 dark:hover:bg-indigo-800/60" aria-label={`Remove ${LABEL[k]} filter`}>
                  <X className="size-3" />
                </button>
              </Chip>
            ))}
            <button className="inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100" onClick={clearAll}>
              <FilterX className="size-3.5" /> Clear all
            </button>
          </div>
        )}
      </Card>

      <Card padded={false}>
        <DataTable<ScanSummaryV2>
          rows={q.data?.items}
          loading={q.isLoading}
          error={q.error}
          onRetry={() => q.refetch()}
          rowKey={(s) => s.id}
          onRowClick={(s) => nav(`/scans/${s.id}`)}
          sort={sort}
          order={order}
          onSort={onSort}
          empty={<EmptyState title="No scans found" description={activeFilters.length ? 'Try clearing some filters.' : 'Scan a URL to start building history.'} />}
          columns={[
            {
              key: 'created_at',
              header: 'Time',
              sortable: true,
              render: (s) => (
                <span className="whitespace-nowrap text-xs text-zinc-500" title={fmtDate(s.created_at)}>
                  {fmtRel(s.created_at)}
                </span>
              ),
            },
            {
              key: 'url',
              header: 'URL',
              render: (s) => (
                <div className="min-w-0 max-w-[16rem]">
                  <div className="truncate font-mono text-xs text-zinc-800 dark:text-zinc-200" title={s.url}>
                    {truncate(s.url, 80)}
                  </div>
                  <div className="truncate text-[11px] text-zinc-500">{s.domain}</div>
                </div>
              ),
            },
            { key: 'verdict', header: 'Verdict', render: (s) => <VerdictBadge verdict={s.verdict} /> },
            { key: 'risk_score', header: 'Risk', sortable: true, render: (s) => <RiskPill score={s.risk_score} /> },
            {
              key: 'trust',
              header: 'Trust',
              align: 'right',
              render: (s) => {
                const t = trustScoreOf(s)
                return t == null ? dash : <span className="tnum text-xs font-medium">{Math.round(t)}</span>
              },
            },
            {
              key: 'tier',
              header: 'Tier',
              render: (s) => {
                const t = tierOf(s)
                return t ? pivotChip('tier', t, t, TIER_TONE[t]) : dash
              },
            },
            {
              key: 'threat_type',
              header: 'Threat type',
              render: (s) => {
                const t = threatTypeOf(s)
                return t && t !== 'none' ? pivotChip('threat_type', t, THREAT_TYPE_LABEL[t], THREAT_TYPE_TONE[t]) : dash
              },
            },
            { key: 'brand', header: 'Brand', render: (s) => (s.brand ? <Chip tone="rose">{s.brand}</Chip> : dash) },
            {
              key: 'geo',
              header: 'Country',
              render: (s) => (s.country_code ? <span className="text-xs">{flagEmoji(s.country_code)} {s.country_code}</span> : dash),
            },
            { key: 'bl', header: 'Blacklist', render: (s) => (s.blacklisted ? <Chip tone="rose">listed</Chip> : <span className="text-xs text-zinc-400">no</span>) },
            { key: 'source', header: 'Source', render: (s) => <span className="text-xs text-zinc-500">{s.source ?? '—'}</span> },
            { key: 'dur', header: 'Duration', align: 'right', render: (s) => <span className="whitespace-nowrap text-xs text-zinc-500">{fmtMs(s.duration_ms)}</span> },
            {
              key: 'actions',
              header: '',
              align: 'right',
              render: (s) => (
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    setToDelete(s)
                  }}
                  className="rounded p-1 text-zinc-400 hover:bg-rose-50 hover:text-rose-600 dark:hover:bg-rose-950/40"
                  aria-label="Delete scan"
                >
                  <Trash2 className="size-3.5" />
                </button>
              ),
            },
          ]}
        />
        <Pagination
          page={page}
          pageSize={pageSize}
          total={q.data?.total ?? 0}
          onPage={(p) => update({ page: p })}
          onPageSize={(n) => update({ page_size: n })}
        />
      </Card>

      <Modal
        open={!!toDelete}
        onClose={() => setToDelete(null)}
        title="Delete scan?"
        footer={
          <>
            <Button variant="ghost" onClick={() => setToDelete(null)}>
              Cancel
            </Button>
            <Button variant="danger" loading={del.isPending} onClick={() => toDelete && del.mutate(toDelete.id)}>
              Delete
            </Button>
          </>
        }
      >
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          Permanently delete scan #{toDelete?.id}?<span className="mt-1 block truncate font-mono text-xs">{toDelete?.url}</span>
        </p>
      </Modal>
    </div>
  )
}
