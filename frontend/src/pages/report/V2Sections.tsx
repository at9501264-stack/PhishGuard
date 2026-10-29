// v2 report pieces (FE-REPORT-A): header badges, AI summary + factors, Content tab, Resources tab,
// reputation engines card and pivot links. Every v2 field is optional - older scans don't have them.
import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ExternalLink, Sparkles, ThumbsDown, ThumbsUp } from 'lucide-react'
import {
  THREAT_TYPE_LABEL,
  THREAT_TYPE_TONE,
  TIER_TONE,
  UNTESTED_LABEL,
  engineRatioOf,
  isLexicalOnly,
  pivotHref,
  threatTypeOf,
  tierOf,
  trustScoreOf,
  type ContentInfo,
  type NegativeFactor,
  type PivotField,
  type ScanResultV2,
} from '../../api/client_v2'
import { Card, CardHeader, KV } from '../../components/Card'
import { DataTable } from '../../components/DataTable'
import { EmptyState } from '../../components/EmptyState'
import { Chip, ProgressBar } from '../../components/ui'
import { cx, fmtNum, fmtPct, titleCase } from '../../lib/format'

/** A value that links to History filtered by it, e.g. /history?ip=1.2.3.4. */
export function PivotLink({ field, value, children }: { field: PivotField; value: string | number | null | undefined; children?: ReactNode }) {
  if (value == null || value === '') return null
  return (
    <Link to={pivotHref(field, value)} title={`Show all scans with this ${field.replace('_', ' ')}`} className="text-indigo-600 hover:underline dark:text-indigo-400">
      {children ?? String(value)}
    </Link>
  )
}

// ---------------------------------------------------------------- header badges
export function HeaderBadges({ scan, sus, phish, onEngines }: { scan: ScanResultV2; sus?: number; phish?: number; onEngines?: () => void }) {
  const trust = trustScoreOf(scan)
  const tier = tierOf(scan, sus, phish)
  const threat = threatTypeOf(scan)
  const ratio = engineRatioOf(scan)
  return (
    <div className="flex flex-wrap items-center gap-2">
      {trust != null && (
        <Chip tone={tier ? TIER_TONE[tier] : 'zinc'}>
          Trust score <span className="tnum font-semibold">{Math.round(trust)}/100</span>
        </Chip>
      )}
      {tier && (
        <Link to={pivotHref('tier', tier)} className="hover:opacity-80" title="Show all scans in this tier">
          <Chip tone={TIER_TONE[tier]}>Tier: {tier}</Chip>
        </Link>
      )}
      {isLexicalOnly(scan) && <Chip tone="amber">{UNTESTED_LABEL}</Chip>}
      {threat && (
        <Link to={pivotHref('threat_type', threat)} className="hover:opacity-80" title="Show all scans with this threat type">
          <Chip tone={THREAT_TYPE_TONE[threat]}>{THREAT_TYPE_LABEL[threat]}</Chip>
        </Link>
      )}
      {ratio && ratio.total > 0 && (
        <button type="button" onClick={onEngines} className="hover:opacity-80" title="Open the Reputation tab">
          <Chip tone={ratio.flagged > 0 ? 'rose' : 'emerald'}>
            <span className="tnum font-semibold">
              {ratio.flagged}/{ratio.total}
            </span>{' '}
            engines flagged
          </Chip>
        </button>
      )}
    </div>
  )
}

// ---------------------------------------------------------------- AI summary + factors
function FactorList({ title, items, positive }: { title: string; items: NegativeFactor[]; positive?: boolean }) {
  return (
    <div>
      <div className={cx('label mb-2 flex items-center gap-1.5', positive ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400')}>
        {positive ? <ThumbsUp className="size-3.5" /> : <ThumbsDown className="size-3.5" />}
        {title} ({items.length})
      </div>
      {items.length === 0 ? (
        <div className="text-xs text-zinc-400">None found</div>
      ) : (
        <ul className="space-y-2">
          {items.map((f, i) => (
            <li key={`${f.id}-${i}`} className="flex gap-2 text-sm">
              <span className={cx('mt-1.5 size-1.5 shrink-0 rounded-full', positive ? 'bg-emerald-500' : 'bg-rose-500')} />
              <span className="min-w-0">
                <span className="font-medium">{f.name}</span>
                {f.severity && (
                  <Chip tone={f.severity === 'high' ? 'rose' : f.severity === 'medium' ? 'amber' : 'zinc'} className="ml-1.5 align-middle">
                    {f.severity}
                  </Chip>
                )}
                {f.detail && <span className="block break-words text-xs text-zinc-500">{f.detail}</span>}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export function AiSummaryCard({ scan }: { scan: ScanResultV2 }) {
  const text = scan.summary || (scan.summary_points ?? []).join(' ')
  const pos = scan.factors?.positive ?? []
  const neg = scan.factors?.negative ?? []
  if (!text && pos.length === 0 && neg.length === 0) return null
  return (
    <Card>
      <CardHeader title="AI summary" subtitle="Plain-English explanation of this result" right={<Sparkles className="size-4 text-indigo-400" />} />
      {text && <p className="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">{text}</p>}
      {(pos.length > 0 || neg.length > 0) && (
        <div className="mt-4 grid gap-4 border-t border-zinc-100 pt-4 md:grid-cols-2 dark:border-zinc-800">
          <FactorList title="Negative factors" items={neg} />
          <FactorList title="Positive factors" items={pos} positive />
        </div>
      )}
    </Card>
  )
}

// ---------------------------------------------------------------- reputation engines
export function EnginesCard({ scan }: { scan: ScanResultV2 }) {
  const engines = scan.reputation?.engines ?? []
  const ratio = engineRatioOf(scan)
  if (engines.length === 0) return null
  return (
    <Card className="lg:col-span-3">
      <CardHeader title="Detection engines" subtitle={ratio ? `${ratio.flagged} of ${ratio.total} engines with an answer flag this URL` : undefined} />
      <DataTable
        rows={engines}
        rowKey={(e, i) => `${e.name}-${i}`}
        dense
        columns={[
          { key: 'name', header: 'Engine', render: (e) => <span className="font-medium">{e.name}</span> },
          { key: 'type', header: 'Type', render: (e) => <span className="text-xs text-zinc-500">{e.type ? titleCase(e.type) : '—'}</span> },
          {
            key: 'listed',
            header: 'Result',
            render: (e) =>
              e.listed === true ? (
                <Chip tone="rose">{e.category && e.category !== 'clean' ? titleCase(e.category) : 'Flagged'}</Chip>
              ) : e.listed === false ? (
                <Chip tone="emerald">Clean</Chip>
              ) : (
                <Chip>No answer</Chip>
              ),
          },
          { key: 'detail', header: 'Detail', render: (e) => <span className="text-xs text-zinc-500">{e.detail || '—'}</span> },
        ]}
      />
    </Card>
  )
}

// ---------------------------------------------------------------- Content tab
export function ContentTab({ scan }: { scan: ScanResultV2 }) {
  const c: ContentInfo = scan.content ?? {}
  const trackers = scan.http?.trackers ?? []
  const cats = [...(c.categories ?? [])].sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
  const maxScore = Math.max(1, ...cats.map((k) => k.score ?? 0))
  const lang = c.language_name || c.language
  const parked = c.parked?.parked
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader title="Page content" subtitle="Category, language and parked-domain detection" />
        {Object.keys(c).length === 0 ? (
          <EmptyState compact title="No content analysis" description="Older scans and lexical-only scans have no page content data." />
        ) : (
          <KV
            rows={[
              ['Category', c.category ? <PivotLink field="category" value={c.category}>{titleCase(c.category)}</PivotLink> : null],
              ['Category confidence', c.category_confidence != null ? fmtPct(c.category_confidence, 0, true) : null],
              [
                'Language',
                lang ? (
                  <span>
                    {lang}
                    {c.language_name && c.language ? <span className="text-zinc-400"> ({c.language})</span> : null}
                    {c.translate_url && (
                      <a href={c.translate_url} target="_blank" rel="noreferrer noopener" className="ml-2 inline-flex items-center gap-1 text-xs text-indigo-600 hover:underline dark:text-indigo-400">
                        Translate <ExternalLink className="size-3" />
                      </a>
                    )}
                  </span>
                ) : null,
              ],
              ['Parked domain', parked == null ? null : parked ? <Chip tone="amber">Parked</Chip> : <Chip tone="emerald">Not parked</Chip>],
              ['Parked reason', parked ? c.parked?.reason || null : null],
              ['Word count', c.word_count != null ? fmtNum(c.word_count) : null],
            ]}
          />
        )}
      </Card>
      <Card>
        <CardHeader title="Category scores" subtitle="How strongly the page text matches each category" />
        {cats.length === 0 ? (
          <EmptyState compact title="No category scores" />
        ) : (
          <div className="space-y-2.5">
            {cats.map((k) => (
              <div key={k.name}>
                <div className="mb-1 flex items-baseline justify-between text-xs">
                  <PivotLink field="category" value={k.name}>
                    {titleCase(k.name)}
                  </PivotLink>
                  <span className="tnum text-zinc-500">{maxScore > 1 ? fmtNum(k.score, 1) : fmtPct(k.score, 0, true)}</span>
                </div>
                <ProgressBar value={k.score ?? 0} max={maxScore} color={k.name === c.category ? '#6366f1' : '#a1a1aa'} />
              </div>
            ))}
          </div>
        )}
      </Card>
      <Card className="lg:col-span-2">
        <CardHeader title={`Trackers (${trackers.length})`} subtitle="Analytics and advertising IDs found in the page" />
        {trackers.length === 0 ? (
          <EmptyState compact title="No trackers found" />
        ) : (
          <ul className="flex flex-wrap gap-2">
            {trackers.map((t, i) => (
              <li key={`${t.id}-${i}`} className="inline-flex items-center gap-2 rounded-md border border-zinc-200 px-2.5 py-1.5 text-xs dark:border-zinc-700">
                <span className="font-medium">{titleCase(t.type || 'other')}</span>
                <span className="font-mono text-zinc-500">{t.id}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}

// ---------------------------------------------------------------- Resources tab
function Tile({ label, value }: { label: string; value: ReactNode }) {
  return (
    <Card className="!p-3">
      <div className="label">{label}</div>
      <div className="tnum mt-0.5 text-xl font-semibold">{value}</div>
    </Card>
  )
}

function PartyChip({ third }: { third?: boolean | null }) {
  if (third == null) return <span className="text-xs text-zinc-400">—</span>
  return third ? <Chip tone="amber">3rd party</Chip> : <Chip>1st party</Chip>
}

export function ResourcesTab({ scan }: { scan: ScanResultV2 }) {
  const [type, setType] = useState('all')
  const res = scan.http?.resources ?? []
  const doms = [...(scan.http?.contacted_domains ?? [])].sort((a, b) => (b.count ?? 0) - (a.count ?? 0))
  const types = [...new Set(res.map((r) => r.type || 'other'))].sort()
  const shown = type === 'all' ? res : res.filter((r) => (r.type || 'other') === type)
  if (res.length === 0 && doms.length === 0) {
    return <EmptyState title="No resources recorded" description="Older scans and lexical-only scans don't list page resources." />
  }
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Tile label="Resources" value={fmtNum(res.length)} />
        <Tile label="Third-party resources" value={fmtNum(res.filter((r) => r.third_party).length)} />
        <Tile label="Contacted domains" value={fmtNum(doms.length)} />
        <Tile label="Third-party domains" value={fmtNum(doms.filter((d) => d.third_party).length)} />
      </div>
      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader title="Contacted domains" subtitle="Hosts the page loads content from" />
          <DataTable
            rows={doms}
            rowKey={(d, i) => `${d.domain}-${i}`}
            dense
            empty={<EmptyState compact title="No contacted domains" />}
            columns={[
              { key: 'domain', header: 'Domain', render: (d) => <span className="break-all font-mono text-xs">{d.domain}</span> },
              { key: 'count', header: 'Requests', align: 'right', render: (d) => <span className="tnum">{fmtNum(d.count ?? 0)}</span> },
              { key: 'party', header: 'Party', render: (d) => <PartyChip third={d.third_party} /> },
            ]}
          />
        </Card>
        <Card className="lg:col-span-3">
          <CardHeader
            title={`Resources (${shown.length})`}
            subtitle="Scripts, styles, images, frames and forms referenced by the page"
            right={
              <select value={type} onChange={(e) => setType(e.target.value)} className="no-print h-7 rounded border border-zinc-200 bg-white px-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900" aria-label="Filter by type">
                <option value="all">All types</option>
                {types.map((t) => (
                  <option key={t} value={t}>
                    {titleCase(t)}
                  </option>
                ))}
              </select>
            }
          />
          <DataTable
            rows={shown}
            rowKey={(r, i) => `${r.url}-${i}`}
            dense
            empty={<EmptyState compact title="No resources of this type" />}
            columns={[
              { key: 'type', header: 'Type', render: (r) => <Chip tone="indigo">{r.type || 'other'}</Chip> },
              {
                key: 'url',
                header: 'URL',
                render: (r) => (
                  <span className="block max-w-md truncate font-mono text-xs" title={r.url}>
                    {r.url}
                  </span>
                ),
              },
              { key: 'party', header: 'Party', render: (r) => <PartyChip third={r.third_party} /> },
            ]}
          />
        </Card>
      </div>
    </div>
  )
}
