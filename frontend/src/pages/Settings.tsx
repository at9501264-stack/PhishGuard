import { Fragment, useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  Cog,
  FileSearch,
  GraduationCap,
  Link2,
  Monitor,
  Moon,
  Save,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Sun,
  Wand2,
} from 'lucide-react'
import { api, type Settings } from '../api/client'
import { Card, CardHeader, KV, PageHeader } from '../components/Card'
import { Segmented } from '../components/RangeSelect'
import { SkeletonRows } from '../components/Skeleton'
import { useToast } from '../components/Toast'
import { Button, ErrorBox, Field, Input, Toggle } from '../components/ui'
import { VERDICT_COLOR } from '../lib/format'
import { useTheme, type ThemePref } from '../lib/theme'

const DEFAULTS: Settings = {
  suspicious_threshold: 35,
  phishing_threshold: 65,
  enable_network_checks: true,
  enable_screenshots: false,
  timeout_s: 10,
  virustotal_api_key: '',
  google_safe_browsing_api_key: '',
  retention_days: 90,
}

function BandPreview({ sus, phish }: { sus: number; phish: number }) {
  return (
    <div>
      <div className="flex h-7 w-full overflow-hidden rounded-md text-[11px] font-medium text-white">
        <div className="flex items-center justify-center" style={{ width: `${sus}%`, background: VERDICT_COLOR.legitimate }}>
          {sus >= 12 && 'Legitimate'}
        </div>
        <div className="flex items-center justify-center" style={{ width: `${phish - sus}%`, background: VERDICT_COLOR.suspicious }}>
          {phish - sus >= 12 && 'Suspicious'}
        </div>
        <div className="flex items-center justify-center" style={{ width: `${100 - phish}%`, background: VERDICT_COLOR.phishing }}>
          {100 - phish >= 12 && 'Phishing'}
        </div>
      </div>
      <div className="tnum mt-1 flex justify-between text-[11px] text-zinc-500">
        <span>0</span>
        <span>
          0–{sus - 1} legit · {sus}–{phish - 1} suspicious · {phish}–100 phishing
        </span>
        <span>100</span>
      </div>
    </div>
  )
}

function Slider({ label, value, onChange, min = 1, max = 99, color }: { label: string; value: number; onChange: (v: number) => void; min?: number; max?: number; color: string }) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="label">{label}</span>
        <span className="tnum rounded bg-zinc-100 px-1.5 text-sm font-semibold dark:bg-zinc-800" style={{ color }}>
          {value}
        </span>
      </div>
      <input type="range" min={min} max={max} value={value} onChange={(e) => onChange(Number(e.target.value))} className="w-full" style={{ accentColor: color }} />
    </div>
  )
}

const WORKFLOW = [
  { label: 'URL Input', icon: Link2, desc: 'Web, email/SMS text, QR, bulk or API' },
  { label: 'Validation', icon: CheckCircle2, desc: 'Normalise scheme, parse host, reject invalid' },
  { label: 'Feature Extraction', icon: FileSearch, desc: 'Lexical, domain, SSL, HTTP, content, brand' },
  { label: 'Pre-processing', icon: Wand2, desc: 'Encode, scale and order feature vector' },
  { label: 'ML Model', icon: BrainCircuit, desc: 'Ensemble of 4 classifiers; best model scores' },
  { label: 'Risk Classification', icon: SlidersHorizontal, desc: '60% ML + 40% heuristics, blacklist overrides' },
  { label: 'Result', icon: ShieldCheck, desc: 'Verdict, risk score, explanation & report' },
]

function Workflow() {
  return (
    <div className="flex flex-wrap items-stretch gap-2">
      {WORKFLOW.map((s, i) => (
        <Fragment key={s.label}>
          <div className="flex w-[calc(50%-1rem)] min-w-[130px] flex-col rounded-lg border border-zinc-200 bg-zinc-50 p-3 sm:w-36 dark:border-zinc-800 dark:bg-zinc-900">
            <div className="flex items-center gap-2">
              <span className="flex size-6 items-center justify-center rounded bg-indigo-600 text-[11px] font-semibold text-white">{i + 1}</span>
              <s.icon className="size-4 text-indigo-500" />
            </div>
            <div className="mt-2 text-sm font-semibold">{s.label}</div>
            <div className="mt-0.5 text-[11px] leading-snug text-zinc-500">{s.desc}</div>
          </div>
          {i < WORKFLOW.length - 1 && (
            <div className="flex items-center text-zinc-400">
              <ArrowRight className="size-4" />
            </div>
          )}
        </Fragment>
      ))}
    </div>
  )
}

export default function SettingsPage() {
  const qc = useQueryClient()
  const toast = useToast()
  const theme = useTheme()
  const q = useQuery({ queryKey: ['settings'], queryFn: api.settings })
  const [form, setForm] = useState<Settings>(DEFAULTS)
  const [vtKey, setVtKey] = useState('')
  const [gsbKey, setGsbKey] = useState('')
  const [keysTouched, setKeysTouched] = useState({ vt: false, gsb: false })

  useEffect(() => {
    if (q.data) setForm({ ...DEFAULTS, ...q.data })
  }, [q.data])

  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setForm((f) => ({ ...f, [k]: v }))
  const setSus = (v: number) => setForm((f) => ({ ...f, suspicious_threshold: Math.min(v, f.phishing_threshold - 1) }))
  const setPhish = (v: number) => setForm((f) => ({ ...f, phishing_threshold: Math.max(v, f.suspicious_threshold + 1) }))

  const save = useMutation({
    mutationFn: () => {
      const body: Partial<Settings> = {
        suspicious_threshold: form.suspicious_threshold,
        phishing_threshold: form.phishing_threshold,
        enable_network_checks: form.enable_network_checks,
        enable_screenshots: form.enable_screenshots,
        timeout_s: Number(form.timeout_s),
        retention_days: form.retention_days == null ? null : Number(form.retention_days),
      }
      if (keysTouched.vt) body.virustotal_api_key = vtKey
      if (keysTouched.gsb) body.google_safe_browsing_api_key = gsbKey
      return api.saveSettings(body)
    },
    onSuccess: (s) => {
      toast('Settings saved', 'success')
      setVtKey('')
      setGsbKey('')
      setKeysTouched({ vt: false, gsb: false })
      if (s) qc.setQueryData(['settings'], s)
      qc.invalidateQueries({ queryKey: ['settings'] })
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Save failed', 'error'),
  })

  const dirty =
    keysTouched.vt ||
    keysTouched.gsb ||
    (q.data &&
      (['suspicious_threshold', 'phishing_threshold', 'enable_network_checks', 'enable_screenshots', 'timeout_s', 'retention_days'] as const).some(
        (k) => String(q.data?.[k] ?? '') !== String(form[k] ?? ''),
      ))

  return (
    <div className="space-y-5">
      <PageHeader
        title="Settings"
        subtitle="Detection thresholds, network checks, integrations and data retention."
        actions={
          <Button variant="primary" icon={<Save className="size-4" />} loading={save.isPending} disabled={!dirty || q.isLoading} onClick={() => save.mutate()}>
            Save changes
          </Button>
        }
      />
      {q.error && <ErrorBox error={q.error} onRetry={() => q.refetch()} />}
      {q.isLoading ? (
        <Card>
          <SkeletonRows rows={6} />
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card className="lg:col-span-2">
            <CardHeader title="Verdict thresholds" subtitle="Risk score bands used to classify scans. Applies to new scans." icon={<SlidersHorizontal className="size-4" />} />
            <div className="grid gap-5 md:grid-cols-2">
              <Slider label="Suspicious threshold" value={form.suspicious_threshold} onChange={setSus} color="#b45309" />
              <Slider label="Phishing threshold" value={form.phishing_threshold} onChange={setPhish} color={VERDICT_COLOR.phishing} />
            </div>
            <div className="mt-4">
              <div className="label mb-1.5">Live preview</div>
              <BandPreview sus={form.suspicious_threshold} phish={form.phishing_threshold} />
            </div>
          </Card>
          <Card>
            <CardHeader title="Analysis engine" icon={<Cog className="size-4" />} />
            <div className="space-y-4">
              <div>
                <Toggle checked={!!form.enable_network_checks} onChange={(v) => set('enable_network_checks', v)} label="Network checks (DNS, WHOIS, SSL, HTTP, geo)" />
                <p className="mt-1 pl-11 text-xs text-zinc-500">When off, scoring uses lexical features + ML only (instant, offline).</p>
              </div>
              <div>
                <Toggle checked={!!form.enable_screenshots} onChange={(v) => set('enable_screenshots', v)} label="Capture page screenshots" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Check timeout (s)" hint="Per network check">
                  <Input type="number" min={1} max={60} step={0.5} value={form.timeout_s} onChange={(e) => set('timeout_s', Number(e.target.value))} />
                </Field>
                <Field label="Retention (days)" hint="0 = keep forever">
                  <Input type="number" min={0} max={3650} value={form.retention_days ?? ''} onChange={(e) => set('retention_days', e.target.value === '' ? null : Number(e.target.value))} />
                </Field>
              </div>
            </div>
          </Card>
          <Card>
            <CardHeader title="Integrations" subtitle="Optional third-party reputation APIs. Keys are stored server-side and masked." icon={<Sparkles className="size-4" />} />
            <div className="space-y-4">
              <Field label="VirusTotal API key" hint={q.data?.virustotal_api_key ? `Current: ${q.data.virustotal_api_key} — leave blank to keep` : 'Not configured'}>
                <Input
                  type="password"
                  autoComplete="off"
                  value={vtKey}
                  placeholder={q.data?.virustotal_api_key ? '••••••••' : 'Paste key'}
                  onChange={(e) => {
                    setVtKey(e.target.value)
                    setKeysTouched((k) => ({ ...k, vt: true }))
                  }}
                />
              </Field>
              <Field label="Google Safe Browsing API key" hint={q.data?.google_safe_browsing_api_key ? `Current: ${q.data.google_safe_browsing_api_key} — leave blank to keep` : 'Not configured'}>
                <Input
                  type="password"
                  autoComplete="off"
                  value={gsbKey}
                  placeholder={q.data?.google_safe_browsing_api_key ? '••••••••' : 'Paste key'}
                  onChange={(e) => {
                    setGsbKey(e.target.value)
                    setKeysTouched((k) => ({ ...k, gsb: true }))
                  }}
                />
              </Field>
              {(keysTouched.vt && !vtKey) || (keysTouched.gsb && !gsbKey) ? (
                <p className="text-xs text-amber-600 dark:text-amber-400">An empty key field will clear the stored key on save.</p>
              ) : null}
            </div>
          </Card>
          <Card>
            <CardHeader title="Appearance" subtitle="Stored in this browser only" icon={<Monitor className="size-4" />} />
            <Segmented<ThemePref>
              value={theme.pref}
              onChange={theme.set}
              options={[
                { value: 'light', label: 'Light' },
                { value: 'dark', label: 'Dark' },
                { value: 'system', label: 'System' },
              ]}
            />
            <div className="mt-2 flex items-center gap-1.5 text-xs text-zinc-500">
              {theme.isDark ? <Moon className="size-3.5" /> : <Sun className="size-3.5" />} Currently {theme.isDark ? 'dark' : 'light'}
            </div>
          </Card>
        </div>
      )}

      <Card>
        <CardHeader title="About this project" icon={<GraduationCap className="size-4" />} />
        <h2 className="text-base font-semibold leading-snug">AI-Based Phishing Website Detection and Risk Analysis System Using Machine Learning</h2>
        <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
          B.Tech mini project. PhishGuard combines a machine-learning URL classifier with live domain, DNS, WHOIS, SSL, HTTP-content, brand-impersonation and threat-feed analysis to produce an
          explainable 0–100 risk score and verdict, with analytics, monitoring and community verification.
        </p>
        <div className="mt-4">
          <KV
            cols={3}
            rows={[
              ['Student', 'Ayushi Tiwari'],
              ['Project guide', 'Mr. Vishal Gupta'],
              ['Institute', 'Lloyd Institute of Engineering & Technology'],
              ['University', 'AKTU (Dr. A.P.J. Abdul Kalam Technical University)'],
              ['Stack', 'FastAPI · scikit-learn · SQLite · React · Recharts'],
            ]}
          />
        </div>
        <div className="mt-6">
          <div className="label mb-2">System workflow</div>
          <Workflow />
        </div>
      </Card>
    </div>
  )
}
