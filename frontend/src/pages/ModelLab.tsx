import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Award, BrainCircuit } from 'lucide-react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend as RLegend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api, type ModelMetrics } from '../api/client'
import { Card, CardHeader, KV, PageHeader } from '../components/Card'
import { ChartCard, ChartTooltip, Legend } from '../components/ChartCard'
import { Kpi } from '../components/Kpi'
import { EmptyState } from '../components/EmptyState'
import { Skeleton } from '../components/Skeleton'
import { Chip, ErrorBox, ProgressBar } from '../components/ui'
import { PALETTE, cx, fmtDate, fmtNum, fmtPct, titleCase, truncate } from '../lib/format'

type MetricKey = 'accuracy' | 'precision' | 'recall' | 'f1' | 'roc_auc'
const METRICS: { key: MetricKey; label: string }[] = [
  { key: 'accuracy', label: 'Accuracy' },
  { key: 'precision', label: 'Precision' },
  { key: 'recall', label: 'Recall' },
  { key: 'f1', label: 'F1' },
  { key: 'roc_auc', label: 'ROC-AUC' },
]

/** Normalise a metric to a 0-1 ratio (backend may send percentages). */
function ratio(v: number | null | undefined): number | null {
  if (v == null || Number.isNaN(Number(v))) return null
  const n = Number(v)
  return n > 1 ? n / 100 : n
}

function pct(v: number | null | undefined, digits = 2) {
  const r = ratio(v)
  return r == null ? '—' : fmtPct(r, digits, true)
}

function zipCurve(xs: number[] | undefined, ys: number[] | undefined): { x: number; y: number }[] {
  if (!Array.isArray(xs) || !Array.isArray(ys)) return []
  const n = Math.min(xs.length, ys.length)
  const out: { x: number; y: number }[] = []
  for (let i = 0; i < n; i++) {
    const x = Number(xs[i])
    const y = Number(ys[i])
    if (Number.isFinite(x) && Number.isFinite(y)) out.push({ x, y })
  }
  return out.sort((a, b) => a.x - b.x)
}

/* ---- Newer metrics.json keys (realistic eval, composition, scheme variants). All optional: read defensively. ---- */
type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)
const obj = (v: unknown): Obj | null => (isObj(v) ? v : null)
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v : null)

type EvalKey = 'f1' | 'precision' | 'recall' | 'https_phish_recall' | 'fpr' | 'roc_auc'
const EVAL_COLS: { key: EvalKey; label: string; hint: string; lower?: boolean }[] = [
  { key: 'f1', label: 'F1', hint: 'F1 score on the realistic held-out set' },
  { key: 'precision', label: 'Precision', hint: 'Share of flagged URLs that really are phishing' },
  { key: 'recall', label: 'Recall', hint: 'Share of phishing URLs caught' },
  { key: 'https_phish_recall', label: 'HTTPS recall', hint: 'Recall on phishing URLs served over https://' },
  { key: 'fpr', label: 'FPR', hint: 'False-positive rate: legitimate URLs flagged as phishing (lower is better)', lower: true },
  { key: 'roc_auc', label: 'ROC-AUC', hint: 'Area under the ROC curve' },
]
const F1_COLOR = '#6366f1'
const FPR_COLOR = '#f43f5e'

const CLASS_META: Record<string, { label: string; color: string }> = {
  phishing: { label: 'Phishing', color: '#f43f5e' },
  legitimate: { label: 'Legitimate', color: '#10b981' },
}
const SOURCE_LABEL: Record<string, string> = {
  phishtank: 'PhishTank',
  phishing_database: 'Phishing.Database',
  openphish: 'OpenPhish',
  phiusiil: 'PhiUSIIL',
  phiusiil_aug: 'PhiUSIIL (augmented)',
  tranco_aug: 'Tranco (augmented)',
  tranco_subdomain: 'Tranco sub-domains',
  sitemap_train: 'Sitemap deep links',
  sitemap_eval: 'Sitemap deep links',
}
const sourceLabel = (k: string) => SOURCE_LABEL[k] ?? titleCase(k)
const humanize = (k: string) => {
  const s = k.replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}
/** "Support Vector Machine" -> "SVM"; single words are kept. */
const abbr = (name: string) => {
  const words = name.split(/\s+/).filter(Boolean)
  return words.length > 1 ? words.map((w) => w[0]).join('').toUpperCase() : truncate(name, 10)
}
/** First sentence only (a period must be followed by whitespace/end, so "Phishing.Database" stays intact). */
const firstSentence = (s: string) => s.match(/^.*?[.!?](?=\s|$)/)?.[0] ?? s

function ConfusionMatrix({ model, color }: { model: ModelMetrics; color: string }) {
  const cm = model.confusion_matrix
  const ok = Array.isArray(cm) && cm.length === 2 && Array.isArray(cm[0]) && Array.isArray(cm[1])
  const tn = ok ? Number(cm[0][0]) || 0 : 0
  const fp = ok ? Number(cm[0][1]) || 0 : 0
  const fn = ok ? Number(cm[1][0]) || 0 : 0
  const tp = ok ? Number(cm[1][1]) || 0 : 0
  const max = Math.max(1, tn, fp, fn, tp)
  const total = tn + fp + fn + tp
  const cell = (v: number, label: string, good: boolean) => (
    <div
      className="flex aspect-[4/3] flex-col items-center justify-center rounded-md border border-zinc-200 dark:border-zinc-800"
      style={{ background: good ? `rgba(16,185,129,${0.08 + 0.5 * (v / max)})` : `rgba(244,63,94,${0.06 + 0.5 * (v / max)})` }}
    >
      <span className="tnum text-lg font-semibold">{fmtNum(v)}</span>
      <span className="text-[10px] uppercase tracking-wider text-zinc-600 dark:text-zinc-300">{label}</span>
      {total > 0 && <span className="tnum text-[10px] text-zinc-500">{((v / total) * 100).toFixed(1)}%</span>}
    </div>
  )
  return (
    <Card>
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
        <span className="size-2 rounded-sm" style={{ background: color }} />
        {model.name}
      </div>
      {!ok ? (
        <EmptyState compact title="No confusion matrix" />
      ) : (
        <div className="grid grid-cols-[auto_1fr_1fr] gap-1.5 text-xs">
          <div />
          <div className="label text-center">Pred. legit</div>
          <div className="label text-center">Pred. phish</div>
          <div className="label flex items-center [writing-mode:vertical-rl] rotate-180 justify-center">Legit</div>
          {cell(tn, 'TN', true)}
          {cell(fp, 'FP', false)}
          <div className="label flex items-center [writing-mode:vertical-rl] rotate-180 justify-center">Phish</div>
          {cell(fn, 'FN', false)}
          {cell(tp, 'TP', true)}
        </div>
      )}
    </Card>
  )
}

export default function ModelLabPage() {
  const q = useQuery({ queryKey: ['model'], queryFn: api.model })
  const info = q.data
  const models = useMemo(() => (info?.models ?? []).filter((m) => m && m.name), [info])
  const best = info?.best_model ?? null
  const colorOf = (name: string) => PALETTE[Math.max(0, models.findIndex((m) => m.name === name)) % PALETTE.length]

  // best value per column
  const bestOf = useMemo(() => {
    const r: Record<string, number | null> = {}
    const higher: (keyof ModelMetrics)[] = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc', 'cv_f1_mean']
    const lower: (keyof ModelMetrics)[] = ['train_time_s', 'predict_time_ms']
    for (const k of higher) {
      const vals = models.map((m) => Number(m[k])).filter((v) => Number.isFinite(v))
      r[k] = vals.length ? Math.max(...vals) : null
    }
    for (const k of lower) {
      const vals = models.map((m) => Number(m[k])).filter((v) => Number.isFinite(v))
      r[k] = vals.length ? Math.min(...vals) : null
    }
    return r
  }, [models])

  const grouped = METRICS.map((mt) => {
    const row: Record<string, string | number | null> = { metric: mt.label }
    for (const m of models) {
      const v = ratio(m[mt.key])
      row[m.name] = v == null ? null : +(v * 100).toFixed(2)
    }
    return row
  })

  const roc = models.map((m) => ({ name: m.name, data: zipCurve(m.roc_curve?.fpr, m.roc_curve?.tpr) }))
  const pr = models.map((m) => ({ name: m.name, data: zipCurve(m.pr_curve?.recall, m.pr_curve?.precision) }))
  const hasRoc = roc.some((c) => c.data.length > 1)
  const hasPr = pr.some((c) => c.data.length > 1)

  const importance = (info?.feature_importance ?? [])
    .filter((f) => f && f.feature)
    .map((f) => ({ name: f.label || f.feature, value: Number(f.importance) || 0 }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 20)

  const fstats = (info?.feature_stats ?? []).filter((f) => f && f.feature).slice(0, 20)
  const fstatsChart = fstats.map((f) => ({ name: f.label || f.feature, phishing: Number(f.mean_phishing) || 0, legitimate: Number(f.mean_legitimate) || 0 }))

  const ds = info?.dataset
  const live = info?.live

  // ---- newer metrics.json keys; each section below renders only when its data exists ----
  const extra: Obj = isObj(info) ? (info as unknown as Obj) : {}

  // Realistic evaluation (modern_eval / modern_eval_info)
  const evalMap = obj(extra.modern_eval)
  const evalInfo = obj(extra.modern_eval_info)
  const modelOrder = models.map((m) => m.name)
  const rankOf = (n: string) => {
    const i = modelOrder.indexOf(n)
    return i < 0 ? modelOrder.length : i
  }
  const evalRows = evalMap
    ? Object.entries(evalMap)
        .filter((e): e is [string, Obj] => !!e[0] && isObj(e[1]))
        .sort((a, b) => rankOf(a[0]) - rankOf(b[0]))
    : []
  const evalBestOf: Partial<Record<EvalKey, number>> = {}
  for (const c of EVAL_COLS) {
    const vals = evalRows.map(([, r]) => num(r[c.key])).filter((v): v is number => v != null)
    if (vals.length) evalBestOf[c.key] = c.lower ? Math.min(...vals) : Math.max(...vals)
  }
  const evalSize = num(evalInfo?.size)
  const evalDesc = (() => {
    const d = str(evalInfo?.description)
    if (d) return firstSentence(d)
    if (evalSize == null) return null
    const ph = num(evalInfo?.phishing)
    const lg = num(evalInfo?.legitimate)
    return `${fmtNum(evalSize)} held-out URLs${ph != null && lg != null ? ` (${fmtNum(ph)} phishing, ${fmtNum(lg)} legitimate)` : ''} from domains never seen in training.`
  })()
  const evalRef = evalRows.find(([n]) => n === best) ?? evalRows[0]
  const perSource = evalRef
    ? Object.entries(evalRef[1])
        .map(([k, v]) => [k.match(/^recall_(.+)$/)?.[1], num(v)] as const)
        .filter((e): e is readonly [string, number] => !!e[0] && e[1] != null)
    : []
  const evalChart = evalRows.map(([name, r]) => {
    const f1 = ratio(num(r.f1))
    const fpr = ratio(num(r.fpr))
    return { name, F1: f1 == null ? null : +(f1 * 100).toFixed(2), FPR: fpr == null ? null : +(fpr * 100).toFixed(2) }
  })
  const hasEvalChart = evalChart.some((d) => d.F1 != null || d.FPR != null)
  const hasEval = evalRows.length > 0

  // Dataset composition (dataset.composition / scheme_rates / notes)
  const dsx = obj(extra.dataset)
  const composition = obj(dsx?.composition)
  const compGroups = (() => {
    if (!composition) return []
    const by = new Map<string, { source: string; count: number }[]>()
    for (const [k, v] of Object.entries(composition)) {
      const n = num(v)
      if (n == null || n <= 0) continue
      const i = k.indexOf(':')
      const cls = i > 0 ? k.slice(0, i) : 'other'
      by.set(cls, [...(by.get(cls) ?? []), { source: i > 0 ? k.slice(i + 1) : k, count: n }])
    }
    const clsRank = (c: string) => (c === 'phishing' ? 0 : c === 'legitimate' ? 1 : 2)
    return [...by.entries()]
      .sort((a, b) => clsRank(a[0]) - clsRank(b[0]))
      .map(([cls, items]) => ({ cls, items: items.sort((a, b) => b.count - a.count), total: items.reduce((s, x) => s + x.count, 0) }))
  })()
  const compTotal = compGroups.reduce((s, g) => s + g.total, 0)
  const schemeRates = obj(dsx?.scheme_rates)
  const httpsOf = (split: string, cls: string) => ratio(num(schemeRates?.[`${split}_${cls}_https`]))
  const httpsGrid = (['phishing', 'legitimate'] as const)
    .map((cls) => ({ cls, train: httpsOf('train', cls), eval: httpsOf('eval', cls) }))
    .filter((r) => r.train != null || r.eval != null)
  const httpsBySource = schemeRates
    ? Object.entries(schemeRates)
        .map(([k, v]) => [k.match(/^train_(.+)_https$/)?.[1], ratio(num(v))] as const)
        .filter((e): e is readonly [string, number] => !!e[0] && e[0] !== 'phishing' && e[0] !== 'legitimate' && e[1] != null)
    : []
  const dsNotes = str(dsx?.notes)
  const hasComp = compGroups.length > 0 || httpsGrid.length > 0

  // Model selection + scheme-variant comparison (features / feature_variant / variant_comparison)
  const nFeatures = Array.isArray(extra.features) ? extra.features.length : null
  const activeVariant = str(extra.feature_variant)
  const vc = obj(extra.variant_comparison)
  const vWith = obj(vc?.with_scheme)
  const vWithout = obj(vc?.without_scheme)
  const variantCols =
    vWith && vWithout
      ? [
          { key: 'with_scheme', label: 'With scheme', v: vWith },
          { key: 'without_scheme', label: 'Without scheme', v: vWithout },
        ]
      : []
  const vBest = (v: Obj) => str(v.best_model)
  const vEval = (v: Obj, k: EvalKey) => {
    const b = vBest(v)
    return b ? num(obj(obj(v.modern_eval)?.[b])?.[k]) : null
  }
  const vTestF1 = (v: Obj) => {
    const b = vBest(v)
    return b ? num(obj(v.test_f1)?.[b]) : null
  }
  const variantRows: [string, string[]][] = variantCols.length
    ? ([
        ['Inputs', variantCols.map((c) => fmtNum(num(c.v.features)))],
        ['Best model', variantCols.map((c) => vBest(c.v) ?? '—')],
        ['Test F1 (stratified)', variantCols.map((c) => pct(vTestF1(c.v)))],
        ['Realistic F1', variantCols.map((c) => pct(vEval(c.v, 'f1')))],
        ['HTTPS recall', variantCols.map((c) => pct(vEval(c.v, 'https_phish_recall')))],
        ['FPR', variantCols.map((c) => pct(vEval(c.v, 'fpr')))],
      ] as [string, string[]][]).filter(([, vals]) => vals.some((x) => x !== '—'))
    : []

  if (q.error) {
    return (
      <div>
        <PageHeader title="Model Lab" subtitle="Training metrics and live performance of the ML classifiers" />
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      </div>
    )
  }

  const tdCls = (k: keyof ModelMetrics, m: ModelMetrics) => {
    const v = Number(m[k])
    return cx('px-3 py-2.5 text-right tnum', Number.isFinite(v) && bestOf[k as string] === v && 'font-semibold text-emerald-600 dark:text-emerald-400')
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Model Lab"
        subtitle="Training metrics and live performance of the ML classifiers"
        actions={
          info?.version ? (
            <Chip tone="indigo">
              <BrainCircuit className="size-3" /> v{info.version}
            </Chip>
          ) : null
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader title="Dataset" subtitle={ds?.source ? truncate(ds.source, 60) : 'Training data'} />
          {q.isLoading ? (
            <Skeleton className="h-32 w-full" />
          ) : !ds ? (
            <EmptyState compact title="No dataset info" />
          ) : (
            <>
              <KV
                rows={[
                  ['Name', ds.name ?? '—'],
                  ['Total samples', fmtNum(ds.total)],
                  ['Phishing', fmtNum(ds.phishing)],
                  ['Legitimate', fmtNum(ds.legitimate)],
                  ['Train size', fmtNum(ds.train_size)],
                  ['Test size', fmtNum(ds.test_size)],
                  ['Best model', best ?? '—'],
                  ['Trained at', fmtDate(info?.trained_at)],
                ]}
              />
              {(ds.phishing ?? 0) + (ds.legitimate ?? 0) > 0 && (
                <div className="mt-4">
                  <div className="flex h-2 overflow-hidden rounded-full">
                    <div className="bg-rose-500" style={{ width: `${((ds.phishing ?? 0) / ((ds.phishing ?? 0) + (ds.legitimate ?? 0))) * 100}%` }} />
                    <div className="flex-1 bg-emerald-500" />
                  </div>
                  <div className="mt-1.5">
                    <Legend
                      items={[
                        { label: 'Phishing', color: '#f43f5e', value: fmtNum(ds.phishing) },
                        { label: 'Legitimate', color: '#10b981', value: fmtNum(ds.legitimate) },
                      ]}
                    />
                  </div>
                </div>
              )}
            </>
          )}
        </Card>
        <div className="grid grid-cols-2 gap-3 lg:col-span-2">
          <Kpi label="Live predictions" value={fmtNum(live?.predictions)} loading={q.isLoading} sub="Scans scored by the model" />
          <Kpi label="Avg phishing probability" value={pct(live?.avg_probability, 1)} loading={q.isLoading} sub="Mean across live predictions" />
          <Kpi label="Model agreement" value={pct(live?.agreement_rate, 1)} loading={q.isLoading} sub="Models agreeing with best model" color="#6366f1" />
          <Kpi label="Feedback accuracy" value={pct(live?.feedback_accuracy, 1)} loading={q.isLoading} sub="vs verified community reports" color="#10b981" />
        </div>
      </div>

      <Card padded={false}>
        <div className="p-4 pb-0">
          <CardHeader title="Model comparison" subtitle="Hold-out test metrics; best value per column highlighted" />
        </div>
        {q.isLoading ? (
          <div className="p-4">
            <Skeleton className="h-40 w-full" />
          </div>
        ) : models.length === 0 ? (
          <EmptyState compact title="No trained models found" description="Run the training script in backend/ml to generate metrics." />
        ) : (
          <div className="thin-scroll overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-zinc-50/95 dark:bg-zinc-900/95">
                <tr className="border-b border-zinc-200 dark:border-zinc-800">
                  <th className="label px-3 py-2 text-left font-medium">Model</th>
                  {['Accuracy', 'Precision', 'Recall', 'F1', 'ROC-AUC', 'CV F1 ± std', 'Train time', 'Predict time'].map((h) => (
                    <th key={h} className="label whitespace-nowrap px-3 py-2 text-right font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {models.map((m) => (
                  <tr key={m.name} className={cx('border-b border-zinc-100 last:border-0 dark:border-zinc-800/60', m.name === best && 'bg-indigo-50/40 dark:bg-indigo-500/5')}>
                    <td className="whitespace-nowrap px-3 py-2.5">
                      <span className="flex items-center gap-2">
                        <span className="size-2 rounded-sm" style={{ background: colorOf(m.name) }} />
                        <span className="font-medium">{m.name}</span>
                        {m.name === best && (
                          <Chip tone="indigo">
                            <Award className="size-3" /> Best
                          </Chip>
                        )}
                      </span>
                    </td>
                    <td className={tdCls('accuracy', m)}>{pct(m.accuracy)}</td>
                    <td className={tdCls('precision', m)}>{pct(m.precision)}</td>
                    <td className={tdCls('recall', m)}>{pct(m.recall)}</td>
                    <td className={tdCls('f1', m)}>{pct(m.f1)}</td>
                    <td className={tdCls('roc_auc', m)}>{ratio(m.roc_auc) == null ? '—' : (ratio(m.roc_auc) as number).toFixed(4)}</td>
                    <td className={tdCls('cv_f1_mean', m)}>
                      {pct(m.cv_f1_mean)}
                      {m.cv_f1_std != null && <span className="text-xs font-normal text-zinc-500"> ± {pct(m.cv_f1_std)}</span>}
                    </td>
                    <td className={tdCls('train_time_s', m)}>{m.train_time_s == null ? '—' : `${fmtNum(m.train_time_s, 2)} s`}</td>
                    <td className={tdCls('predict_time_ms', m)}>{m.predict_time_ms == null ? '—' : m.predict_time_ms > 0 && m.predict_time_ms < 0.001 ? '<0.001 ms' : `${fmtNum(m.predict_time_ms, 3)} ms`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <ChartCard
        title="Metric comparison"
        subtitle="Percent, higher is better"
        loading={q.isLoading}
        empty={models.length === 0}
        height={280}
        right={<Legend items={models.map((m) => ({ label: m.name, color: colorOf(m.name) }))} />}
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={grouped} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="metric" />
            <YAxis domain={[(min: number) => Math.max(0, Math.floor(min - 5)), 100]} />
            <Tooltip content={<ChartTooltip valueFormatter={(v) => `${v.toFixed(2)}%`} />} cursor={{ fillOpacity: 0.06 }} />
            {models.map((m) => (
              <Bar key={m.name} dataKey={m.name} name={m.name} fill={colorOf(m.name)} radius={[2, 2, 0, 0]} isAnimationActive={false} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </ChartCard>

      {best && (
        <Card>
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <p className="flex min-w-0 items-start gap-2 text-sm text-zinc-600 dark:text-zinc-300">
              <Award className="mt-0.5 size-4 shrink-0 text-indigo-500" />
              <span>
                <span className="font-semibold text-zinc-900 dark:text-zinc-100">Model selection:</span>{' '}
                <span className="font-medium text-zinc-900 dark:text-zinc-100">{best}</span> is chosen by F1 on the stratified test split
                {hasEval ? '; the realistic set below is shown for transparency.' : '.'}
                {nFeatures != null && (
                  <Chip className="ml-2 align-middle">
                    {nFeatures} inputs{activeVariant ? ` · ${humanize(activeVariant).toLowerCase()}` : ''}
                  </Chip>
                )}
              </span>
            </p>
            {variantRows.length > 0 && (
              <div className="thin-scroll shrink-0 overflow-x-auto rounded-md border border-zinc-200 dark:border-zinc-800">
                <table className="text-xs">
                  <thead className="bg-zinc-50/95 dark:bg-zinc-900/95">
                    <tr className="border-b border-zinc-200 dark:border-zinc-800">
                      <th className="label px-3 py-1.5 text-left font-medium">Scheme feature</th>
                      {variantCols.map((c) => (
                        <th key={c.key} className="label whitespace-nowrap px-3 py-1.5 text-right font-medium">
                          <span className="inline-flex items-center gap-1.5">
                            {c.label}
                            {c.key === activeVariant && <Chip tone="indigo">In use</Chip>}
                          </span>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {variantRows.map(([label, vals]) => (
                      <tr key={label} className="border-b border-zinc-100 last:border-0 dark:border-zinc-800/60">
                        <td className="whitespace-nowrap px-3 py-1.5 text-zinc-500 dark:text-zinc-400">{label}</td>
                        {vals.map((v, i) => (
                          <td
                            key={variantCols[i].key}
                            className={cx('tnum whitespace-nowrap px-3 py-1.5 text-right', variantCols[i].key === activeVariant && 'bg-indigo-50/40 font-medium dark:bg-indigo-500/5')}
                          >
                            {v}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Card>
      )}

      {(hasEval || hasComp) && (
        <div className={cx('grid gap-4', hasEval && hasComp && 'lg:grid-cols-3')}>
          {hasEval && (
            <Card padded={false} className={cx('min-w-0', hasComp && 'lg:col-span-2')}>
              <div className="p-4 pb-0">
                <CardHeader
                  title="Realistic evaluation — unseen domains"
                  subtitle={evalDesc ?? undefined}
                  right={evalSize != null ? <Chip>{fmtNum(evalSize)} URLs</Chip> : null}
                />
              </div>
              <div className="thin-scroll overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-zinc-50/95 dark:bg-zinc-900/95">
                    <tr className="border-b border-zinc-200 dark:border-zinc-800">
                      <th className="label px-3 py-2 text-left font-medium">Model</th>
                      {EVAL_COLS.map((c) => (
                        <th key={c.key} title={c.hint} className="label whitespace-nowrap px-3 py-2 text-right font-medium">
                          {c.label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {evalRows.map(([name, r]) => (
                      <tr key={name} className={cx('border-b border-zinc-100 last:border-0 dark:border-zinc-800/60', name === best && 'bg-indigo-50/40 dark:bg-indigo-500/5')}>
                        <td className="whitespace-nowrap px-3 py-2.5">
                          <span className="flex items-center gap-2">
                            <span className="size-2 rounded-sm" style={{ background: colorOf(name) }} />
                            <span className="font-medium">{name}</span>
                            {name === best && (
                              <Chip tone="indigo">
                                <Award className="size-3" /> Best
                              </Chip>
                            )}
                          </span>
                        </td>
                        {EVAL_COLS.map((c) => {
                          const v = num(r[c.key])
                          const auc = c.key === 'roc_auc' ? ratio(v) : null
                          return (
                            <td key={c.key} className={cx('px-3 py-2.5 text-right tnum', v != null && evalBestOf[c.key] === v && 'font-semibold text-emerald-600 dark:text-emerald-400')}>
                              {c.key === 'roc_auc' ? (auc == null ? '—' : auc.toFixed(4)) : pct(v)}
                            </td>
                          )
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {perSource.length > 0 && evalRef && (
                <div className="border-t border-zinc-100 px-4 py-2 text-xs text-zinc-500 dark:border-zinc-800/60 dark:text-zinc-400">
                  Recall by phishing source · {evalRef[0]}:{' '}
                  {perSource.map(([k, v], i) => (
                    <span key={k}>
                      {i > 0 && ' · '}
                      {sourceLabel(k)} <span className="tnum font-medium text-zinc-700 dark:text-zinc-200">{pct(v, 1)}</span>
                    </span>
                  ))}
                </div>
              )}
              {hasEvalChart && (
                <div className="border-t border-zinc-100 p-4 dark:border-zinc-800/60">
                  <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                    <span className="label">F1 vs false-positive rate (%)</span>
                    <Legend
                      items={[
                        { label: 'F1', color: F1_COLOR },
                        { label: 'False-positive rate', color: FPR_COLOR },
                      ]}
                    />
                  </div>
                  <div className="h-[200px] w-full min-w-0">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={evalChart} margin={{ top: 4, right: 8, bottom: 0, left: -16 }} barGap={2}>
                        <CartesianGrid vertical={false} />
                        <XAxis dataKey="name" interval={0} tickFormatter={(v: string) => abbr(String(v))} />
                        <YAxis domain={[0, 100]} />
                        <Tooltip content={<ChartTooltip valueFormatter={(v) => `${v.toFixed(2)}%`} />} cursor={{ fillOpacity: 0.06 }} />
                        <Bar dataKey="F1" name="F1" fill={F1_COLOR} radius={[2, 2, 0, 0]} isAnimationActive={false} />
                        <Bar dataKey="FPR" name="False-positive rate" fill={FPR_COLOR} radius={[2, 2, 0, 0]} isAnimationActive={false} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}
            </Card>
          )}
          {hasComp && (
            <Card className="min-w-0">
              <CardHeader
                title="Dataset composition"
                subtitle={compTotal > 0 ? `${fmtNum(compTotal)} training-pool URLs by class and source` : 'Training pool by class and source'}
              />
              {compGroups.length > 0 && (
                <div className="space-y-3">
                  {compGroups.map((g) => {
                    const meta = CLASS_META[g.cls] ?? { label: titleCase(g.cls), color: '#64748b' }
                    return (
                      <div key={g.cls}>
                        <div className="mb-1.5 flex items-center justify-between gap-2 text-xs">
                          <span className="flex items-center gap-1.5 font-medium text-zinc-800 dark:text-zinc-200">
                            <span className="size-2 rounded-sm" style={{ background: meta.color }} />
                            {meta.label}
                          </span>
                          <span className="tnum text-zinc-500">
                            {fmtNum(g.total)}
                            {compTotal > 0 && ` · ${fmtPct(g.total / compTotal, 1, true)}`}
                          </span>
                        </div>
                        <div className="space-y-1.5">
                          {g.items.map((it) => (
                            <div key={it.source}>
                              <div className="flex items-center justify-between gap-2 text-[11px] text-zinc-600 dark:text-zinc-400">
                                <span className="truncate" title={it.source}>
                                  {sourceLabel(it.source)}
                                </span>
                                <span className="tnum shrink-0">
                                  {fmtNum(it.count)} <span className="text-zinc-400">({fmtPct(it.count / g.total, 1, true)})</span>
                                </span>
                              </div>
                              <ProgressBar value={it.count} max={g.total} color={meta.color} className="mt-0.5" />
                            </div>
                          ))}
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
              {httpsGrid.length > 0 && (
                <div className={cx(compGroups.length > 0 && 'mt-4 border-t border-zinc-100 pt-3 dark:border-zinc-800/60')}>
                  <div className="label mb-1">HTTPS share (https:// URLs)</div>
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-zinc-500 dark:text-zinc-400">
                        <th className="py-1 text-left font-medium">Class</th>
                        <th className="py-1 text-right font-medium">Train</th>
                        <th className="py-1 text-right font-medium">Realistic eval</th>
                      </tr>
                    </thead>
                    <tbody>
                      {httpsGrid.map((r) => (
                        <tr key={r.cls} className="border-t border-zinc-100 dark:border-zinc-800/60">
                          <td className="py-1 text-zinc-600 dark:text-zinc-300">{CLASS_META[r.cls]?.label ?? r.cls}</td>
                          <td className="tnum py-1 text-right">{pct(r.train, 1)}</td>
                          <td className="tnum py-1 text-right">{pct(r.eval, 1)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {httpsBySource.length > 0 && (
                    <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                      Phishing sources (train):{' '}
                      {httpsBySource.map(([k, v], i) => (
                        <span key={k}>
                          {i > 0 && ' · '}
                          {sourceLabel(k)} <span className="tnum">{pct(v, 1)}</span>
                        </span>
                      ))}
                    </p>
                  )}
                </div>
              )}
              {dsNotes && (
                <details className="mt-3 border-t border-zinc-100 pt-2 text-xs dark:border-zinc-800/60">
                  <summary className="cursor-pointer select-none text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200">How the data was prepared</summary>
                  <p className="mt-1.5 leading-relaxed text-zinc-600 dark:text-zinc-400">{dsNotes}</p>
                </details>
              )}
            </Card>
          )}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard title="ROC curves" subtitle="True positive rate vs false positive rate" loading={q.isLoading} empty={!hasRoc} height={300}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart margin={{ top: 4, right: 12, bottom: 12, left: -8 }}>
              <CartesianGrid />
              <XAxis type="number" dataKey="x" domain={[0, 1]} tickCount={6} label={{ value: 'FPR', position: 'insideBottom', offset: -6, fontSize: 11 }} />
              <YAxis type="number" dataKey="y" domain={[0, 1]} tickCount={6} />
              <Tooltip content={<ChartTooltip valueFormatter={(v) => v.toFixed(3)} labelFormatter={(l) => `FPR ${Number(l).toFixed(3)}`} />} />
              <Line data={[{ x: 0, y: 0 }, { x: 1, y: 1 }]} dataKey="y" name="Random" stroke="#a1a1aa" strokeDasharray="4 4" dot={false} isAnimationActive={false} legendType="none" />
              {roc.map((c) => (
                <Line key={c.name} data={c.data} dataKey="y" name={c.name} stroke={colorOf(c.name)} strokeWidth={c.name === best ? 2.5 : 1.5} dot={false} isAnimationActive={false} />
              ))}
              <RLegend verticalAlign="top" iconType="plainline" wrapperStyle={{ fontSize: 11, paddingBottom: 8 }} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="Precision–recall curves" subtitle="Precision vs recall" loading={q.isLoading} empty={!hasPr} height={300}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart margin={{ top: 4, right: 12, bottom: 12, left: -8 }}>
              <CartesianGrid />
              <XAxis type="number" dataKey="x" domain={[0, 1]} tickCount={6} label={{ value: 'Recall', position: 'insideBottom', offset: -6, fontSize: 11 }} />
              <YAxis type="number" dataKey="y" domain={[0, 1]} tickCount={6} />
              <Tooltip content={<ChartTooltip valueFormatter={(v) => v.toFixed(3)} labelFormatter={(l) => `Recall ${Number(l).toFixed(3)}`} />} />
              {pr.map((c) => (
                <Line key={c.name} data={c.data} dataKey="y" name={c.name} stroke={colorOf(c.name)} strokeWidth={c.name === best ? 2.5 : 1.5} dot={false} isAnimationActive={false} />
              ))}
              <RLegend verticalAlign="top" iconType="plainline" wrapperStyle={{ fontSize: 11, paddingBottom: 8 }} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">Confusion matrices</h2>
        {q.isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-52" />
            ))}
          </div>
        ) : models.length === 0 ? (
          <Card>
            <EmptyState compact title="No models" />
          </Card>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {models.map((m) => (
              <ConfusionMatrix key={m.name} model={m} color={colorOf(m.name)} />
            ))}
          </div>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard title="Feature importance" subtitle={`Top ${importance.length || 20} features${best ? ` · ${best}` : ''}`} loading={q.isLoading} empty={importance.length === 0} height={Math.max(260, importance.length * 24)}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={importance} layout="vertical" margin={{ top: 0, right: 12, bottom: 0, left: 0 }}>
              <CartesianGrid horizontal={false} />
              <XAxis type="number" tickFormatter={(v: number) => v.toFixed(2)} />
              <YAxis type="category" dataKey="name" width={150} interval={0} tick={{ fontSize: 11, width: 400 }} tickFormatter={(v: string) => truncate(String(v), 20)} />
              <Tooltip content={<ChartTooltip valueFormatter={(v) => v.toFixed(4)} />} cursor={{ fillOpacity: 0.06 }} />
              <Bar dataKey="value" name="Importance" fill="#6366f1" radius={[0, 3, 3, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
        <Card padded={false}>
          <div className="p-4 pb-0">
            <CardHeader
              title="Feature statistics"
              subtitle="Mean value in phishing vs legitimate samples"
              right={
                <Legend
                  items={[
                    { label: 'Phishing', color: '#f43f5e' },
                    { label: 'Legitimate', color: '#10b981' },
                  ]}
                />
              }
            />
          </div>
          {q.isLoading ? (
            <div className="p-4">
              <Skeleton className="h-60 w-full" />
            </div>
          ) : fstats.length === 0 ? (
            <EmptyState compact title="No feature statistics" />
          ) : (
            <div className="thin-scroll max-h-[480px] overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-zinc-50/95 dark:bg-zinc-900/95">
                  <tr className="border-b border-zinc-200 dark:border-zinc-800">
                    <th className="label px-3 py-2 text-left font-medium">Feature</th>
                    <th className="label px-3 py-2 text-right font-medium">Phishing</th>
                    <th className="label px-3 py-2 text-right font-medium">Legit</th>
                    <th className="label w-32 px-3 py-2 text-left font-medium">Relative</th>
                  </tr>
                </thead>
                <tbody>
                  {fstatsChart.map((f) => {
                    const mx = Math.max(Math.abs(f.phishing), Math.abs(f.legitimate), 1e-9)
                    return (
                      <tr key={f.name} className="border-b border-zinc-100 last:border-0 dark:border-zinc-800/60">
                        <td className="px-3 py-1.5" title={f.name}>
                          {truncate(f.name, 32)}
                        </td>
                        <td className="tnum px-3 py-1.5 text-right">{fmtNum(f.phishing, 3)}</td>
                        <td className="tnum px-3 py-1.5 text-right">{fmtNum(f.legitimate, 3)}</td>
                        <td className="px-3 py-1.5">
                          <div className="space-y-0.5">
                            <div className="h-1.5 rounded-full bg-rose-500" style={{ width: `${(Math.abs(f.phishing) / mx) * 100}%` }} />
                            <div className="h-1.5 rounded-full bg-emerald-500" style={{ width: `${(Math.abs(f.legitimate) / mx) * 100}%` }} />
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
