import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Network } from 'lucide-react'
import { apiV2, qk, type GraphNode, type GraphParams } from '../../api/client_v2'
import ForceGraph from '../../components/ForceGraph'
import { EmptyState } from '../../components/EmptyState'
import { Skeleton } from '../../components/Skeleton'
import { ErrorBox } from '../../components/ui'

/** Relationship graph around the scanned domain (G4), 2 hops deep. */
export default function GraphTab({ domain }: { domain: string }) {
  const navigate = useNavigate()
  const params: GraphParams = { domain, depth: 2 }
  const q = useQuery({ queryKey: qk.graph(params), queryFn: () => apiV2.graph(params), enabled: !!domain })

  // Hand ForceGraph copies so a simulation that mutates nodes/edges can't corrupt the query cache.
  const nodes = useMemo(() => (q.data?.nodes ?? []).map((n) => ({ ...n })), [q.data])
  const edges = useMemo(() => (q.data?.edges ?? []).map((e) => ({ ...e })), [q.data])

  const onNodeClick = (n: GraphNode) => {
    const label = n.label || n.id
    if (n.type === 'domain') navigate(`/domains/${encodeURIComponent(label)}`)
    else if (n.type === 'ip') navigate(`/history?ip=${encodeURIComponent(label)}`)
  }

  if (!domain) return <EmptyState icon={<Network className="size-5" />} title="No domain to graph" />
  if (q.isLoading) return <Skeleton className="h-[480px] w-full" />
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />
  if (!nodes.length) {
    return (
      <EmptyState
        icon={<Network className="size-5" />}
        title="No relationships found yet"
        description="Once more sites are scanned, shared IPs, ASNs, name servers and registrars will link them here."
      />
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-zinc-500">
        <span>
          Infrastructure around <span className="font-mono text-zinc-700 dark:text-zinc-300">{domain}</span> (2 hops) ·{' '}
          <span className="tnum">{nodes.length}</span> nodes · <span className="tnum">{edges.length}</span> links
        </span>
        <span>Click a domain to open it, or an IP to see every scan hosted on it.</span>
      </div>
      <ForceGraph nodes={nodes} edges={edges} height={480} onNodeClick={onNodeClick} />
    </div>
  )
}
