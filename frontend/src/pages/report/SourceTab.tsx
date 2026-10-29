import { useDeferredValue, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Check, ChevronDown, ChevronUp, Copy, FileCode, Search, TextWrap } from 'lucide-react'
import { apiV2, qk, type DomSnapshot } from '../../api/client_v2'
import { EmptyState } from '../../components/EmptyState'
import { SkeletonRows } from '../../components/Skeleton'
import { Button, ErrorBox, Input } from '../../components/ui'
import { copyText, cx, fmtNum } from '../../lib/format'

/** Lines rendered at first / per "show more" click (keeps a 500 KB page snappy). */
const PAGE = 500
/** Stop collecting search hits after this many (count shows "5000+"). */
const MAX_MATCHES = 5000

type Match = { line: number; start: number }

function fmtSize(bytes: number): string {
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${(bytes / 1024).toFixed(1)} KB`
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** Page-source viewer (G1). The HTML is shown as plain text only - it is never rendered or injected. */
export default function SourceTab({ scanId, hasDom }: { scanId: number; hasDom?: boolean | null }) {
  // Skip the request (and its 404) when the scan says it has no DOM snapshot.
  const q = useQuery({ queryKey: qk.scanDom(scanId), queryFn: () => apiV2.dom(scanId), staleTime: Infinity, enabled: hasDom !== false })

  if (q.isLoading) return <SkeletonRows rows={8} />
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />
  if (!q.data?.html) {
    return (
      <EmptyState
        icon={<FileCode className="size-5" />}
        title="No page source saved for this scan"
        description="The site may have been unreachable or blocked, or the scan was made before page-source capture existed. Re-scan to capture it."
      />
    )
  }
  return <SourceViewer dom={q.data} />
}

function SourceViewer({ dom }: { dom: DomSnapshot }) {
  const lines = useMemo(() => dom.html.split(/\r?\n/), [dom.html])
  const [query, setQuery] = useState('')
  const term = useDeferredValue(query.trim())
  const [cur, setCur] = useState(0)
  const [wrap, setWrap] = useState(() => lines.some((l) => l.length > 2000))
  const [limit, setLimit] = useState(PAGE)
  const [copied, setCopied] = useState(false)
  const boxRef = useRef<HTMLDivElement>(null)
  const curRef = useRef<HTMLElement>(null)

  // All matches (case-insensitive) + index of the first match on each line.
  const { matches, firstOnLine } = useMemo(() => {
    const matches: Match[] = []
    const firstOnLine = new Map<number, number>()
    if (term) {
      const re = new RegExp(escapeRegExp(term), 'gi')
      for (let i = 0; i < lines.length && matches.length < MAX_MATCHES; i++) {
        re.lastIndex = 0
        let m: RegExpExecArray | null
        while ((m = re.exec(lines[i])) && matches.length < MAX_MATCHES) {
          if (!firstOnLine.has(i)) firstOnLine.set(i, matches.length)
          matches.push({ line: i, start: m.index })
        }
      }
    }
    return { matches, firstOnLine }
  }, [lines, term])

  const active = matches.length ? Math.min(cur, matches.length - 1) : -1
  // Always render far enough to show the active match.
  const shown = Math.min(lines.length, Math.max(limit, active >= 0 ? matches[active].line + 1 : 0))

  // Scroll the active match into the middle of the viewer (without moving the page).
  useEffect(() => {
    const box = boxRef.current
    const el = curRef.current
    if (!box || !el || active < 0) return
    const b = box.getBoundingClientRect()
    const r = el.getBoundingClientRect()
    box.scrollTop += r.top - b.top - box.clientHeight / 2
    if (r.left < b.left + 56 || r.right > b.right) box.scrollLeft += r.left - b.left - box.clientWidth / 2
  }, [active, term, wrap])

  const step = (dir: 1 | -1) => {
    if (!matches.length) return
    setCur((active + dir + matches.length) % matches.length)
  }

  const copy = async () => {
    if (await copyText(dom.html)) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }
  }

  const renderLine = (text: string, i: number): ReactNode => {
    let k = firstOnLine.get(i)
    if (k === undefined) return text
    const parts: ReactNode[] = []
    let pos = 0
    for (; k < matches.length && matches[k].line === i; k++) {
      const { start } = matches[k]
      if (start > pos) parts.push(text.slice(pos, start))
      const isCur = k === active
      parts.push(
        <mark
          key={k}
          ref={isCur ? curRef : undefined}
          className={cx('rounded-sm text-inherit', isCur ? 'bg-orange-400 text-zinc-950 ring-1 ring-orange-500' : 'bg-yellow-200 dark:bg-yellow-500/40')}
        >
          {text.slice(start, start + term.length)}
        </mark>,
      )
      pos = start + term.length
    }
    if (pos < text.length) parts.push(text.slice(pos))
    return parts
  }

  const countLabel = !term
    ? null
    : matches.length === 0
      ? 'No matches'
      : `${fmtNum(active + 1)} / ${fmtNum(matches.length)}${matches.length >= MAX_MATCHES ? '+' : ''}`

  return (
    <div className="space-y-2">
      {/* toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-48 flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-zinc-400" />
          <Input
            value={query}
            placeholder="Search the page source (Enter = next, Shift+Enter = previous)"
            className="pl-8"
            onChange={(e) => {
              setQuery(e.target.value)
              setCur(0)
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault()
                step(e.shiftKey ? -1 : 1)
              } else if (e.key === 'Escape') {
                setQuery('')
              }
            }}
          />
        </div>
        {countLabel && <span className="tnum min-w-20 text-center text-xs text-zinc-500">{countLabel}</span>}
        <Button size="sm" variant="secondary" icon={<ChevronUp className="size-3.5" />} disabled={!matches.length} onClick={() => step(-1)} title="Previous match" aria-label="Previous match" />
        <Button size="sm" variant="secondary" icon={<ChevronDown className="size-3.5" />} disabled={!matches.length} onClick={() => step(1)} title="Next match" aria-label="Next match" />
        <Button size="sm" variant={wrap ? 'primary' : 'secondary'} icon={<TextWrap className="size-3.5" />} onClick={() => setWrap(!wrap)} aria-pressed={wrap}>
          Wrap
        </Button>
        <Button size="sm" variant="secondary" icon={copied ? <Check className="size-3.5 text-emerald-500" /> : <Copy className="size-3.5" />} onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>

      {/* size / truncation note */}
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-zinc-500">
        <span className="tnum">{fmtNum(lines.length)} lines</span>
        <span className="tnum">{fmtSize(dom.size || dom.html.length)}</span>
        {dom.source && <span>captured via {dom.source}</span>}
        {dom.truncated && <span className="text-amber-600 dark:text-amber-400">Truncated: only the first 500 KB were stored</span>}
        <span>Shown as plain text; the page is never rendered.</span>
      </div>

      {/* viewer */}
      <div ref={boxRef} className="thin-scroll max-h-[600px] overflow-auto rounded-md border border-zinc-200 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-950">
        <div className={cx('py-1 font-mono text-xs leading-5 text-zinc-800 dark:text-zinc-200', wrap ? 'w-full' : 'w-max min-w-full')}>
          {lines.slice(0, shown).map((text, i) => (
            <div key={i} className="flex hover:bg-zinc-100 dark:hover:bg-zinc-900">
              <span className="tnum sticky left-0 w-12 shrink-0 select-none border-r border-zinc-200 bg-zinc-50 pr-2 text-right text-zinc-400 dark:border-zinc-800 dark:bg-zinc-950">
                {i + 1}
              </span>
              <span className={cx('pl-3 pr-4', wrap ? 'min-w-0 flex-1 whitespace-pre-wrap break-all' : 'whitespace-pre')}>{renderLine(text, i)}</span>
            </div>
          ))}
        </div>
      </div>

      {shown < lines.length && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-500">
          <span className="tnum">
            Showing lines 1-{fmtNum(shown)} of {fmtNum(lines.length)}
          </span>
          <Button size="sm" variant="secondary" onClick={() => setLimit(shown + PAGE * 2)}>
            Show {fmtNum(Math.min(PAGE * 2, lines.length - shown))} more
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setLimit(lines.length)}>
            Show all
          </Button>
        </div>
      )}
    </div>
  )
}
