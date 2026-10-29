import { useMemo, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { ExternalLink, Network, Search, X } from 'lucide-react'
import { apiV2, qk, type GraphNode, type GraphParams } from '../api/client_v2'
import ForceGraph from '../components/ForceGraph'
import { Card, PageHeader } from '../components/Card'
import { EmptyState } from '../components/EmptyState'
import { Skeleton } from '../components/Skeleton'
import { RiskPill, VerdictBadge } from '../components/VerdictBadge'
import { Button, Chip, ErrorBox, Input } from '../components/ui'
import { cx } from '../lib/format'

const GRAPH_HEIGHT = 560

const TYPE_LABEL: Record<string, string> = {
  domain: 'Domain',
  url: 'URL',
  redirect: 'Redirect',
  ip: 'IP address',
  asn: 'ASN',
  ns: 'Name server',
  registrar: 'Registrar',
  brand: 'Brand',
  country: 'Country',
  favicon: 'Favicon',
  tracker: 'Tracker',
}

const linkBtn =
  'inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors border-zinc-200 bg-white text-zinc-800 hover:bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:bg-zinc-800'
const linkBtnPrimary =
  'inline-flex h-8 items-center gap-1.5 rounded-md border border-transparent bg-indigo-600 px-2.5 text-xs font-medium text-white shadow-sm hover:bg-indigo-500'

/** Node ids are "<type>:<value>"; the value is what the pivots use (label can be prettier, e.g. "AS15169 Google LLC"). */
function nodeValue(n: GraphNode): string {
  const i = n.id.indexOf(':')
  return i >= 0 ? n.id.slice(i + 1) : n.label
}

/** Backend adds `scan_id` (latest scan) to domain/url nodes; it is not part of the typed contract. */
function scanIdOf(n: GraphNode): string | number | null {
  const v = (n as GraphNode & { scan_id?: string | number | null }).scan_id
  return v == null || v === '' ? null : v
}

function domainOf(n: GraphNode): string | null {
  const v = nodeValue(n)
  if (n.type === 'domain' || n.type === 'redirect') return v
  if (n.type !== 'url') return null
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : `http://${v}`).hostname || null
  } catch {
    return null
  }
}

/** Accept a pasted URL or a bare domain. */
function cleanDomain(s: string): string {
  return s
    .trim()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    .split(/[/?#]/)[0]
    .replace(/:\d+$/, '')
    .replace(/\.$/, '')
    .toLowerCase()
}

export default function Graph() {
  const [sp, setSp] = useSearchParams()
  const domain = cleanDomain(sp.get('domain') ?? '')
  const depth: 1 | 2 = sp.get('depth') === '1' ? 1 : 2
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const params: GraphParams = domain ? { domain, depth } : {}
  const g = useQuery({ queryKey: qk.graph(params), queryFn: () => apiV2.graph(params), placeholderData: keepPreviousData })
  const nodes = useMemo(() => g.data?.nodes ?? [], [g.data])
  const edges = useMemo(() => g.data?.edges ?? [], [g.data])

  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes])
  const sel = selectedId ? (byId.get(selectedId) ?? null) : null
  const neighbors = useMemo(() => {
    if (!sel) return []
    const out: { node: GraphNode; type: string }[] = []
    for (const e of edges) {
      const other = e.source === sel.id ? e.target : e.target === sel.id ? e.source : null
      const node = other ? byId.get(other) : undefined
      if (node) out.push({ node, type: String(e.type ?? '') })
    }
    return out.sort((a, b) => String(a.node.type).localeCompare(String(b.node.type)) || a.node.label.localeCompare(b.node.label))
  }, [sel, edges, byId])

  const update = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(sp)
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v)
      else next.delete(k)
    }
    setSp(next)
  }
  const showDomain = (d: string | null) => {
    setSelectedId(null)
    update({ domain: d })
  }
  const onSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    showDomain(cleanDomain(String(new FormData(e.currentTarget).get('domain') ?? '')) || null)
  }

  let body
  if (g.isError && !g.data) body = <ErrorBox error={g.error} onRetry={() => g.refetch()} />
  else if (nodes.length === 0)
    body = (
      <Card>
        <EmptyState
          icon={<Network className="h-5 w-5" />}
          title={domain ? `No relationships for ${domain}` : 'No graph data yet'}
          description={
            domain
              ? 'This domain has not been scanned yet, or no infrastructure was recorded for it.'
              : 'Scan a few URLs and their shared IPs, ASNs, name servers and registrars will appear here.'
          }
          action={
            <Link to={domain ? `/scan?url=${encodeURIComponent(domain)}` : '/scan'} className={linkBtnPrimary}>
              {domain ? 'Scan it now' : 'Scan a URL'}
            </Link>
          }
        />
      </Card>
    )
  else body = <ForceGraph nodes={nodes} edges={edges} height={GRAPH_HEIGHT} onNodeClick={(n) => setSelectedId(n.id)} />

  return (
    <div className="space-y-4">
      <PageHeader
        title="Relationship graph"
        subtitle="How scanned domains connect through shared IPs, ASNs, name servers, registrars, brands and redirects."
      />

      <Card>
        <form onSubmit={onSubmit} className="flex flex-wrap items-center gap-2">
          <div className="relative w-full min-w-0 sm:w-auto sm:max-w-md sm:flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" />
            <Input key={domain} name="domain" defaultValue={domain} placeholder="Search a domain, e.g. example.com" aria-label="Domain" className="w-full pl-8" />
          </div>
          <Button type="submit" variant="primary" icon={<Network className="h-4 w-4" />}>
            Show graph
          </Button>
          {domain && (
            <Button type="button" variant="ghost" icon={<X className="h-4 w-4" />} onClick={() => showDomain(null)}>
              Global view
            </Button>
          )}
          <div className="ml-auto flex items-center gap-2 text-xs text-zinc-500">
            <span>Depth</span>
            <div role="group" aria-label="Depth" className="inline-flex overflow-hidden rounded-md border border-zinc-200 dark:border-zinc-700">
              {([1, 2] as const).map((d) => (
                <button
                  key={d}
                  type="button"
                  aria-pressed={depth === d}
                  title={d === 1 ? 'Direct infrastructure only' : 'Also domains sharing that infrastructure'}
                  onClick={() => update({ depth: String(d) })}
                  className={cx(
                    'h-7 px-3 text-xs font-medium transition-colors',
                    depth === d ? 'bg-indigo-600 text-white' : 'bg-white text-zinc-600 hover:bg-zinc-50 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800',
                  )}
                >
                  {d}
                </button>
              ))}
            </div>
          </div>
        </form>
        <p className="mt-2 text-xs text-zinc-500">
          {domain ? (
            <>
              Centered on <span className="font-mono text-zinc-700 dark:text-zinc-300">{domain}</span> · depth {depth}{' '}
              {depth === 2 ? '(includes domains that share its infrastructure)' : '(direct infrastructure only)'}
              {g.isFetching && !g.isPending && <span className="ml-2 text-indigo-500">updating…</span>}
            </>
          ) : (
            <>
              Global view: the most recent and highest-risk domains. Search a domain to focus on it.
              {g.isFetching && !g.isPending && <span className="ml-2 text-indigo-500">updating…</span>}
            </>
          )}
        </p>
      </Card>

      {g.isError && g.data && <ErrorBox error={g.error} onRetry={() => g.refetch()} />}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0" style={g.isPending ? { height: GRAPH_HEIGHT } : undefined}>
          {g.isPending ? <Skeleton className="h-full w-full rounded-md" /> : body}
        </div>

        <Card className="self-start">
          {!sel ? (
            <div className="py-8 text-center text-sm text-zinc-500">
              <Network className="mx-auto mb-2 h-5 w-5 text-zinc-400" />
              Click a node to see its details and pivots.
            </div>
          ) : (
            <NodePanel
              node={sel}
              neighbors={neighbors}
              currentDomain={domain}
              onClose={() => setSelectedId(null)}
              onSelect={(n) => setSelectedId(n.id)}
              onGraphDomain={(d) => showDomain(d)}
            />
          )}
        </Card>
      </div>
    </div>
  )
}

function NodePanel({
  node,
  neighbors,
  currentDomain,
  onClose,
  onSelect,
  onGraphDomain,
}: {
  node: GraphNode
  neighbors: { node: GraphNode; type: string }[]
  currentDomain: string
  onClose: () => void
  onSelect: (n: GraphNode) => void
  onGraphDomain: (d: string) => void
}) {
  const value = nodeValue(node)
  const scanId = scanIdOf(node)
  const dom = domainOf(node)
  const site = node.type === 'domain' || node.type === 'url'
  const pivot: Record<string, [string, string]> = {
    ip: ['ip', 'Scans on this IP'],
    asn: ['asn', 'Scans in this ASN'],
    registrar: ['registrar', 'Scans with this registrar'],
    brand: ['q', 'Scans mentioning this brand'],
  }
  const p = pivot[node.type]
  const shown = neighbors.slice(0, 15)

  return (
    <div className="space-y-3 text-sm">
      <div className="flex items-start justify-between gap-2">
        <Chip tone="indigo">{TYPE_LABEL[node.type] ?? node.type}</Chip>
        <button type="button" onClick={onClose} aria-label="Close details" className="rounded p-0.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 dark:hover:bg-zinc-800">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div>
        <div className="break-all font-mono text-sm font-medium text-zinc-900 dark:text-zinc-100">{node.label || value}</div>
        {node.label && node.label !== value && <div className="mt-0.5 break-all font-mono text-xs text-zinc-500">{value}</div>}
      </div>

      <dl className="grid grid-cols-2 gap-x-3 gap-y-2 text-xs">
        {site && (
          <div>
            <dt className="text-zinc-500">Verdict</dt>
            <dd className="mt-0.5">{node.verdict ? <VerdictBadge verdict={node.verdict} /> : <span className="text-zinc-400">—</span>}</dd>
          </div>
        )}
        {node.risk != null && (
          <div>
            <dt className="text-zinc-500">Risk</dt>
            <dd className="mt-0.5">
              <RiskPill score={node.risk} />
            </dd>
          </div>
        )}
        <div>
          <dt className="text-zinc-500">Scans</dt>
          <dd className="mt-0.5 tabular-nums text-zinc-800 dark:text-zinc-200">{node.count ?? '—'}</dd>
        </div>
        <div>
          <dt className="text-zinc-500">Connections</dt>
          <dd className="mt-0.5 tabular-nums text-zinc-800 dark:text-zinc-200">{neighbors.length}</dd>
        </div>
      </dl>

      <div className="flex flex-wrap gap-2">
        {scanId != null && (
          <Link to={`/scans/${encodeURIComponent(String(scanId))}`} className={linkBtnPrimary}>
            <ExternalLink className="h-3.5 w-3.5" /> Open latest report
          </Link>
        )}
        {dom && (
          <Link to={`/domains/${encodeURIComponent(dom)}`} className={linkBtn}>
            Domain profile
          </Link>
        )}
        {dom && dom !== currentDomain && (
          <button type="button" onClick={() => onGraphDomain(dom)} className={linkBtn}>
            <Network className="h-3.5 w-3.5" /> Graph this domain
          </button>
        )}
        {p && (
          <Link to={`/history?${p[0]}=${encodeURIComponent(value)}`} className={linkBtn}>
            {p[1]}
          </Link>
        )}
      </div>

      {neighbors.length > 0 && (
        <div>
          <div className="mb-1 text-xs font-medium text-zinc-500">Connected to</div>
          <ul className="divide-y divide-zinc-100 rounded-md border border-zinc-200 dark:divide-zinc-800 dark:border-zinc-800">
            {shown.map(({ node: n, type }, i) => (
              <li key={`${n.id}-${type}-${i}`}>
                <button
                  type="button"
                  onClick={() => onSelect(n)}
                  className="flex w-full items-center gap-2 px-2 py-1.5 text-left hover:bg-zinc-50 dark:hover:bg-zinc-800/50"
                >
                  <span className="shrink-0 text-[10px] uppercase tracking-wide text-zinc-400">{TYPE_LABEL[n.type] ?? n.type}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-700 dark:text-zinc-300" title={n.label}>
                    {n.label || n.id}
                  </span>
                  <span className="shrink-0 text-[10px] text-zinc-400">{type.replace(/_/g, ' ')}</span>
                </button>
              </li>
            ))}
          </ul>
          {neighbors.length > shown.length && <div className="mt-1 text-xs text-zinc-400">+{neighbors.length - shown.length} more</div>}
        </div>
      )}
    </div>
  )
}
