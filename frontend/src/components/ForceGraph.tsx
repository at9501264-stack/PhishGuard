import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react'
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from 'd3-force'
import type { Simulation, SimulationLinkDatum, SimulationNodeDatum } from 'd3-force'
import type { GraphEdge, GraphNode } from '../api/client_v2'

/**
 * Relationship graph (G4): SVG + d3-force simulation.
 * Wheel = zoom, drag background = pan, drag node = move it, click node = onNodeClick.
 * Domain/url nodes are filled by verdict; infrastructure nodes by type. Size grows with `count`.
 */

type SimNode = SimulationNodeDatum & { id: string; data: GraphNode; r: number }
type SimLink = SimulationLinkDatum<SimNode> & { type: string; key: string }
type View = { x: number; y: number; k: number }
type Drag = { node?: SimNode; sx: number; sy: number; vx: number; vy: number; moved: boolean }
type VerdictKey = 'legitimate' | 'suspicious' | 'phishing'

const TYPE_ORDER = ['domain', 'url', 'redirect', 'ip', 'asn', 'ns', 'registrar', 'brand', 'country', 'favicon', 'tracker']
const TYPE_LABEL: Record<string, string> = {
  domain: 'Domain',
  url: 'URL',
  redirect: 'Redirect',
  ip: 'IP',
  asn: 'ASN',
  ns: 'Name server',
  registrar: 'Registrar',
  brand: 'Brand',
  country: 'Country',
  favicon: 'Favicon',
  tracker: 'Tracker',
}
const TYPE_COLOR: Record<string, string> = {
  domain: '#6366f1', // indigo
  url: '#8b5cf6', // violet
  redirect: '#a855f7', // purple
  ip: '#0ea5e9', // sky
  asn: '#14b8a6', // teal
  ns: '#64748b', // slate
  registrar: '#f97316', // orange
  brand: '#ec4899', // pink
  country: '#84cc16', // lime
  favicon: '#eab308', // yellow
  tracker: '#06b6d4', // cyan
}
const EDGE_COLOR: Record<string, string> = {
  resolves_to: '#0ea5e9',
  in_asn: '#14b8a6',
  uses_ns: '#64748b',
  registered_with: '#f97316',
  impersonates: '#f43f5e',
  redirects_to: '#a855f7',
  located_in: '#84cc16',
  scanned_as: '#6366f1',
  has_favicon: '#eab308',
  has_tracker: '#06b6d4',
}
const VERDICT_COLOR: Record<VerdictKey, string> = { legitimate: '#10b981', suspicious: '#f59e0b', phishing: '#f43f5e' }
const VERDICT_LABEL: Record<VerdictKey, string> = { legitimate: 'Legitimate', suspicious: 'Suspicious', phishing: 'Phishing' }

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))
const src = (l: SimLink) => l.source as SimNode
const tgt = (l: SimLink) => l.target as SimNode
const isSite = (t: string) => t === 'domain' || t === 'url'
const short = (s: string) => (s.length > 28 ? `${s.slice(0, 26)}…` : s)

function verdictOf(n: GraphNode): VerdictKey | null {
  const v = String(n.verdict ?? '').toLowerCase()
  if (v.includes('phish') || v.includes('malic')) return 'phishing'
  if (v.includes('susp')) return 'suspicious'
  if (v.includes('legit') || v === 'safe' || v === 'clean' || v === 'benign') return 'legitimate'
  if (n.risk == null) return null
  return n.risk >= 65 ? 'phishing' : n.risk >= 35 ? 'suspicious' : 'legitimate'
}

function fillOf(n: GraphNode): string {
  const v = isSite(n.type) ? verdictOf(n) : null
  return v ? VERDICT_COLOR[v] : (TYPE_COLOR[n.type] ?? '#a1a1aa')
}

function radiusOf(n: GraphNode): number {
  const c = Math.max(1, Number(n.count) || 1)
  const base = n.type === 'domain' ? 7 : n.type === 'url' ? 6 : 5
  return Math.min(22, base + Math.sqrt(c - 1) * 2.5)
}

function Swatch({ type }: { type: string }) {
  const color = TYPE_COLOR[type] ?? '#a1a1aa'
  const shape = type === 'url' ? 'rounded-[3px]' : 'rounded-full'
  // domain/url are filled by verdict, so their type is shown as a coloured ring
  return isSite(type) ? (
    <span className={`inline-block h-2.5 w-2.5 border-2 ${shape}`} style={{ borderColor: color }} />
  ) : (
    <span className={`inline-block h-2.5 w-2.5 ${shape}`} style={{ background: color }} />
  )
}

export default function ForceGraph(props: { nodes: GraphNode[]; edges: GraphEdge[]; height?: number; onNodeClick?: (n: GraphNode) => void }) {
  const { nodes, edges, height = 480, onNodeClick } = props
  const list = Array.isArray(nodes) ? nodes : []
  const links = Array.isArray(edges) ? edges : []
  const empty = list.length === 0

  const wrapRef = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const simRef = useRef<Simulation<SimNode, SimLink> | null>(null)
  const dragRef = useRef<Drag | null>(null)
  const [layout, setLayout] = useState<{ nodes: SimNode[]; links: SimLink[] }>({ nodes: [], links: [] })
  const [, setTick] = useState(0)
  const [view, setView] = useState<View>({ x: 0, y: 0, k: 1 })
  const [width, setWidth] = useState(0)
  const [hover, setHover] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)

  // Only rebuild the simulation when the graph content changes (not on every new array identity).
  const sig = useMemo(
    () => list.map((n) => n?.id).join('|') + '#' + links.map((e) => `${e?.source}>${e?.target}:${e?.type}`).join('|'),
    [list, links],
  )

  const fitTo = (ns: SimNode[]) => {
    const w = wrapRef.current?.clientWidth || 600
    if (!ns.length) return
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity
    for (const n of ns) {
      x0 = Math.min(x0, (n.x ?? 0) - n.r)
      y0 = Math.min(y0, (n.y ?? 0) - n.r)
      x1 = Math.max(x1, (n.x ?? 0) + n.r)
      y1 = Math.max(y1, (n.y ?? 0) + n.r)
    }
    const k = clamp(Math.min((w - 48) / Math.max(1, x1 - x0), (height - 72) / Math.max(1, y1 - y0)), 0.2, 1.6)
    setView({ k, x: -((x0 + x1) / 2) * k, y: -((y0 + y1) / 2) * k })
  }

  // Build / rebuild the simulation; stop it on change and on unmount.
  useEffect(() => {
    const old = new Map((simRef.current?.nodes() ?? []).map((n) => [n.id, n]))
    simRef.current?.stop()
    const byId = new Map<string, SimNode>()
    for (const d of list) {
      if (!d || d.id == null || byId.has(String(d.id))) continue
      const o = old.get(String(d.id))
      byId.set(String(d.id), { id: String(d.id), data: d, r: radiusOf(d), x: o?.x, y: o?.y })
    }
    const seen = new Set<string>()
    const simLinks: SimLink[] = []
    for (const e of links) {
      const s = String(e?.source)
      const t = String(e?.target)
      const key = `${s}>${t}:${e?.type}`
      if (s === t || !byId.has(s) || !byId.has(t) || seen.has(key)) continue // d3 throws on unknown ids
      seen.add(key)
      simLinks.push({ source: s, target: t, type: String(e.type ?? ''), key })
    }
    const simNodes = [...byId.values()]
    const sim = forceSimulation<SimNode, SimLink>(simNodes)
      .force(
        'link',
        forceLink<SimNode, SimLink>(simLinks)
          .id((d) => d.id)
          .distance((l) => 34 + src(l).r + tgt(l).r)
          .strength(0.5),
      )
      .force('charge', forceManyBody<SimNode>().strength((d) => -40 - d.r * 8).distanceMax(420))
      .force('collide', forceCollide<SimNode>((d) => d.r + 4))
      .force('x', forceX<SimNode>(0).strength(0.05))
      .force('y', forceY<SimNode>(0).strength(0.05))
      .stop()
    sim.tick(160) // warm up so the first paint is already laid out, then let it settle visibly
    sim.on('tick', () => setTick((t) => t + 1))
    simRef.current = sim
    setLayout({ nodes: simNodes, links: simLinks })
    fitTo(simNodes)
    sim.restart()
    return () => {
      sim.stop()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig])

  // Track container width (graph is centred in it).
  useEffect(() => {
    const el = wrapRef.current
    if (!el) return
    setWidth(el.clientWidth)
    const ro = new ResizeObserver(() => setWidth(el.clientWidth))
    ro.observe(el)
    return () => ro.disconnect()
  }, [empty])

  // Wheel zoom around the cursor (native listener so preventDefault works - React's is passive).
  useEffect(() => {
    const el = svgRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const rect = el.getBoundingClientRect()
      const px = e.clientX - rect.left - rect.width / 2
      const py = e.clientY - rect.top - rect.height / 2
      setView((v) => {
        const k = clamp(v.k * Math.exp(-e.deltaY * 0.0015), 0.15, 4)
        return { k, x: px - ((px - v.x) / v.k) * k, y: py - ((py - v.y) / v.k) * k }
      })
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [empty])

  const byId = useMemo(() => new Map(layout.nodes.map((n) => [n.id, n])), [layout])
  const adj = useMemo(() => {
    const m = new Map<string, Set<string>>()
    for (const l of layout.links) {
      const s = src(l).id
      const t = tgt(l).id
      if (!m.has(s)) m.set(s, new Set())
      if (!m.has(t)) m.set(t, new Set())
      m.get(s)!.add(t)
      m.get(t)!.add(s)
    }
    return m
  }, [layout])
  const legendTypes = useMemo(() => {
    const present = new Set(layout.nodes.map((n) => String(n.data.type)))
    return [...TYPE_ORDER.filter((t) => present.has(t)), ...[...present].filter((t) => !TYPE_ORDER.includes(t))]
  }, [layout])
  const hasVerdicts = layout.nodes.some((n) => isSite(n.data.type) && verdictOf(n.data))

  if (empty) {
    return (
      <div
        className="flex items-center justify-center rounded-md border border-dashed border-zinc-300 text-sm text-zinc-500 dark:border-zinc-700"
        style={{ height }}
      >
        No relationships to show
      </div>
    )
  }

  const w = width || 600
  const toGraph = (cx: number, cy: number) => {
    const rect = svgRef.current!.getBoundingClientRect()
    return { x: (cx - rect.left - rect.width / 2 - view.x) / view.k, y: (cy - rect.top - rect.height / 2 - view.y) / view.k }
  }
  const onDown = (e: PointerEvent<Element>, node?: SimNode) => {
    if (e.button !== 0) return
    e.stopPropagation()
    svgRef.current?.setPointerCapture(e.pointerId)
    dragRef.current = { node, sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y, moved: false }
  }
  const onMove = (e: PointerEvent<SVGSVGElement>) => {
    const d = dragRef.current
    if (!d) return
    const dx = e.clientX - d.sx
    const dy = e.clientY - d.sy
    if (!d.moved && Math.hypot(dx, dy) < 4) return
    if (!d.moved) {
      d.moved = true
      setHover(null)
      if (d.node) simRef.current?.alphaTarget(0.3).restart()
    }
    if (d.node) {
      const p = toGraph(e.clientX, e.clientY)
      d.node.fx = p.x
      d.node.fy = p.y
    } else {
      setView((v) => ({ ...v, x: d.vx + dx, y: d.vy + dy }))
    }
  }
  const onUp = (e: PointerEvent<SVGSVGElement>) => {
    const d = dragRef.current
    dragRef.current = null
    if (svgRef.current?.hasPointerCapture(e.pointerId)) svgRef.current.releasePointerCapture(e.pointerId)
    if (!d) return
    if (d.node && d.moved) {
      simRef.current?.alphaTarget(0)
      d.node.fx = null
      d.node.fy = null
    } else if (d.node) {
      setSelected(d.node.id)
      onNodeClick?.(d.node.data)
    } else if (!d.moved) {
      setSelected(null)
    }
  }
  const onKey = (e: KeyboardEvent<SVGGElement>, n: SimNode) => {
    if (e.key !== 'Enter' && e.key !== ' ') return
    e.preventDefault()
    setSelected(n.id)
    onNodeClick?.(n.data)
  }
  const zoomBy = (f: number) =>
    setView((v) => {
      const k = clamp(v.k * f, 0.15, 4)
      return { k, x: v.x * (k / v.k), y: v.y * (k / v.k) }
    })

  const focus = hover ?? (selected && byId.has(selected) ? selected : null)
  const focusSet = focus ? new Set([focus, ...(adj.get(focus) ?? [])]) : null
  const showAllLabels = layout.nodes.length <= 35 || view.k >= 1.4
  const tipNode = hover ? byId.get(hover) : undefined
  let tip = null
  if (tipNode) {
    const d = tipNode.data
    const v = isSite(d.type) ? verdictOf(d) : null
    const sx = w / 2 + view.x + (tipNode.x ?? 0) * view.k
    const sy = height / 2 + view.y + (tipNode.y ?? 0) * view.k
    tip = (
      <div
        className="pointer-events-none absolute z-10 w-60 rounded-md border border-zinc-200 bg-white/95 px-2.5 py-2 text-xs shadow-lg dark:border-zinc-700 dark:bg-zinc-900/95"
        style={{ left: clamp(sx > w - 260 ? sx - 252 : sx + 14, 4, Math.max(4, w - 244)), top: clamp(sy + 14, 4, Math.max(4, height - 90)) }}
      >
        <div className="break-all font-mono text-[11px] font-medium text-zinc-900 dark:text-zinc-100">{d.label || d.id}</div>
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-zinc-500 dark:text-zinc-400">
          <span>{TYPE_LABEL[d.type] ?? d.type}</span>
          {v && <span style={{ color: VERDICT_COLOR[v] }}>{VERDICT_LABEL[v]}</span>}
          {d.risk != null && <span className="tabular-nums">risk {Math.round(d.risk)}</span>}
          {d.count != null && <span className="tabular-nums">{d.count} scan{d.count === 1 ? '' : 's'}</span>}
          <span className="tabular-nums">{adj.get(d.id)?.size ?? 0} links</span>
        </div>
      </div>
    )
  }

  const ctl =
    'flex h-7 w-8 items-center justify-center text-sm text-zinc-600 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800'

  return (
    <div
      ref={wrapRef}
      className="relative select-none overflow-hidden rounded-md border border-zinc-200 bg-zinc-50/60 text-zinc-500 dark:border-zinc-800 dark:bg-zinc-950/40"
      style={{ height }}
    >
      <svg
        ref={svgRef}
        width="100%"
        height={height}
        className="block cursor-grab active:cursor-grabbing"
        style={{ touchAction: 'none' }}
        onPointerDown={(e) => onDown(e)}
        onPointerMove={onMove}
        onPointerUp={onUp}
        onPointerCancel={onUp}
      >
        <g transform={`translate(${w / 2 + view.x},${height / 2 + view.y}) scale(${view.k})`}>
          <g>
            {layout.links.map((l) => {
              const s = src(l)
              const t = tgt(l)
              const on = focus ? s.id === focus || t.id === focus : null
              return (
                <line
                  key={l.key}
                  x1={s.x}
                  y1={s.y}
                  x2={t.x}
                  y2={t.y}
                  stroke={EDGE_COLOR[l.type] ?? 'currentColor'}
                  strokeOpacity={on == null ? 0.45 : on ? 0.95 : 0.08}
                  strokeWidth={on ? 1.75 : 1}
                  vectorEffect="non-scaling-stroke"
                />
              )
            })}
          </g>
          <g>
            {layout.nodes.map((n) => {
              const d = n.data
              const site = isSite(d.type)
              const inFocus = focusSet?.has(n.id) ?? false
              const shapeProps = {
                fill: fillOf(d),
                strokeWidth: site ? 2.5 : 1.5,
                vectorEffect: 'non-scaling-stroke' as const,
                ...(site ? { stroke: TYPE_COLOR[d.type] } : { className: 'stroke-white dark:stroke-zinc-900' }),
              }
              const label = showAllLabels || inFocus || (d.type === 'domain' && view.k >= 0.9)
              return (
                <g
                  key={n.id}
                  transform={`translate(${n.x ?? 0},${n.y ?? 0})`}
                  opacity={focusSet && !inFocus ? 0.2 : 1}
                  className="cursor-pointer outline-none"
                  role="button"
                  tabIndex={0}
                  aria-label={`${TYPE_LABEL[d.type] ?? d.type} ${d.label || d.id}`}
                  onPointerDown={(e) => onDown(e, n)}
                  onPointerEnter={() => !dragRef.current?.moved && setHover(n.id)}
                  onPointerLeave={() => setHover((h) => (h === n.id ? null : h))}
                  onFocus={() => setHover(n.id)}
                  onBlur={() => setHover((h) => (h === n.id ? null : h))}
                  onKeyDown={(e) => onKey(e, n)}
                >
                  {n.id === selected && (
                    <circle r={n.r + 5} fill="none" stroke="currentColor" strokeWidth={2} vectorEffect="non-scaling-stroke" className="text-indigo-500" />
                  )}
                  {d.type === 'url' ? (
                    <rect x={-n.r} y={-n.r} width={n.r * 2} height={n.r * 2} rx={n.r * 0.3} {...shapeProps} />
                  ) : (
                    <circle r={n.r} {...shapeProps} />
                  )}
                  {label && (
                    <text
                      y={n.r + 12 / view.k}
                      textAnchor="middle"
                      fontSize={11 / view.k}
                      strokeWidth={3 / view.k}
                      paintOrder="stroke"
                      className="pointer-events-none fill-zinc-700 stroke-white dark:fill-zinc-200 dark:stroke-zinc-950"
                    >
                      {short(d.label || d.id)}
                    </text>
                  )}
                </g>
              )
            })}
          </g>
        </g>
      </svg>

      <div className="pointer-events-none absolute left-2 top-2 rounded bg-white/80 px-1.5 py-0.5 text-[11px] tabular-nums text-zinc-500 dark:bg-zinc-900/80 dark:text-zinc-400">
        {layout.nodes.length} nodes · {layout.links.length} edges
        <span className="hidden sm:inline"> · scroll to zoom, drag to pan</span>
      </div>

      <div className="absolute right-2 top-2 flex flex-col divide-y divide-zinc-200 overflow-hidden rounded-md border border-zinc-200 bg-white/90 shadow-sm dark:divide-zinc-700 dark:border-zinc-700 dark:bg-zinc-900/90">
        <button type="button" className={ctl} onClick={() => zoomBy(1.3)} aria-label="Zoom in" title="Zoom in">
          +
        </button>
        <button type="button" className={ctl} onClick={() => zoomBy(1 / 1.3)} aria-label="Zoom out" title="Zoom out">
          −
        </button>
        <button type="button" className={`${ctl} text-[10px] font-medium`} onClick={() => fitTo(layout.nodes)} aria-label="Fit to view" title="Fit to view">
          FIT
        </button>
      </div>

      <div className="pointer-events-none absolute bottom-2 left-2 right-2 flex">
        <div className="pointer-events-auto flex max-w-full flex-wrap items-center gap-x-3 gap-y-1 rounded-md border border-zinc-200 bg-white/90 px-2 py-1 text-[11px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-900/90 dark:text-zinc-400">
          {legendTypes.map((t) => (
            <span key={t} className="inline-flex items-center gap-1">
              <Swatch type={t} />
              {TYPE_LABEL[t] ?? t}
            </span>
          ))}
          {hasVerdicts && <span className="h-3 w-px bg-zinc-300 dark:bg-zinc-700" />}
          {hasVerdicts &&
            (Object.keys(VERDICT_COLOR) as VerdictKey[]).map((v) => (
              <span key={v} className="inline-flex items-center gap-1">
                <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: VERDICT_COLOR[v] }} />
                {VERDICT_LABEL[v]}
              </span>
            ))}
        </div>
      </div>

      {tip}
    </div>
  )
}
