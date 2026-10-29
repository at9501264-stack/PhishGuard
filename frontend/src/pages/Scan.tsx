import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import jsQR from 'jsqr'
import { CheckCircle2, Circle, ImageUp, Link2, Loader2, Mail, QrCode, ScanSearch, XCircle } from 'lucide-react'
import { api, type ScanSource } from '../api/client'
import { Card, CardHeader, PageHeader } from '../components/Card'
import { Tabs } from '../components/Tabs'
import { Button, ErrorBox, Textarea, Toggle } from '../components/ui'
import { EmptyState } from '../components/EmptyState'
import { useToast } from '../components/Toast'
import { cx } from '../lib/format'

const STEPS = [
  { id: 'lexical', label: 'Lexical analysis', hint: 'URL structure, length, symbols, entropy' },
  { id: 'ml', label: 'ML prediction', hint: 'Ensemble of 4 trained classifiers' },
  { id: 'dns', label: 'DNS lookup', hint: 'A / AAAA / MX / NS / TXT records' },
  { id: 'whois', label: 'WHOIS', hint: 'Registrar, domain age, expiry' },
  { id: 'ssl', label: 'SSL / TLS', hint: 'Certificate validity & issuer' },
  { id: 'http', label: 'HTTP & content', hint: 'Redirects, headers, forms, scripts' },
  { id: 'brand', label: 'Brand impersonation', hint: 'Typosquat, homoglyph, combosquat' },
  { id: 'reputation', label: 'Reputation', hint: 'Threat feeds & community reports' },
]

function ScanProgress({ active, done, error, deep }: { active: boolean; done: boolean; error: boolean; deep: boolean }) {
  const [step, setStep] = useState(0)
  useEffect(() => {
    if (!active) return
    setStep(0)
    const per = deep ? 900 : 350
    const t = setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), per)
    return () => clearInterval(t)
  }, [active, deep])
  const current = done ? STEPS.length : step
  return (
    <Card>
      <CardHeader title="Analysis pipeline" subtitle={done ? 'Complete — opening report…' : error ? 'Scan failed' : 'Running checks…'} />
      <div className="mb-4 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
        <div
          className={cx('h-full rounded-full transition-all duration-500', error ? 'bg-rose-500' : 'bg-indigo-500')}
          style={{ width: `${((done ? STEPS.length : current + 0.5) / STEPS.length) * 100}%` }}
        />
      </div>
      <ol className="grid gap-2 sm:grid-cols-2">
        {STEPS.map((s, i) => {
          const state = error && i === current ? 'error' : i < current ? 'done' : i === current ? 'active' : 'pending'
          return (
            <li
              key={s.id}
              className={cx(
                'flex items-start gap-2.5 rounded-md border px-3 py-2 transition-colors',
                state === 'active' ? 'border-indigo-200 bg-indigo-50/60 dark:border-indigo-900 dark:bg-indigo-500/5' : 'border-zinc-100 dark:border-zinc-800',
              )}
            >
              {state === 'done' ? (
                <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-500" />
              ) : state === 'active' ? (
                <Loader2 className="mt-0.5 size-4 shrink-0 animate-spin text-indigo-500" />
              ) : state === 'error' ? (
                <XCircle className="mt-0.5 size-4 shrink-0 text-rose-500" />
              ) : (
                <Circle className="mt-0.5 size-4 shrink-0 text-zinc-300 dark:text-zinc-700" />
              )}
              <div className="min-w-0">
                <div className={cx('text-sm', state === 'pending' ? 'text-zinc-400' : 'font-medium')}>
                  <span className="tnum mr-1.5 text-xs text-zinc-400">{String(i + 1).padStart(2, '0')}</span>
                  {s.label}
                </div>
                <div className="truncate text-xs text-zinc-500">{s.hint}</div>
              </div>
            </li>
          )
        })}
      </ol>
    </Card>
  )
}

type Tab = 'url' | 'text' | 'qr'

export default function ScanPage() {
  const [params] = useSearchParams()
  const [tab, setTab] = useState<Tab>('url')
  const [url, setUrl] = useState(params.get('url') ?? '')
  const [deep, setDeep] = useState(true)
  const [text, setText] = useState('')
  const [extracted, setExtracted] = useState<string[] | null>(null)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [qrUrl, setQrUrl] = useState<string | null>(null)
  const [qrPreview, setQrPreview] = useState<string | null>(null)
  const [qrError, setQrError] = useState<string | null>(null)
  const [multi, setMulti] = useState<{ total: number; done: number } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const nav = useNavigate()
  const toast = useToast()
  const qc = useQueryClient()

  const scan = useMutation({
    mutationFn: ({ u, source }: { u: string; source: ScanSource }) => api.scan(u, deep, source),
    onSuccess: (r) => {
      qc.invalidateQueries()
      setTimeout(() => nav(`/scans/${r.id}`), 450)
    },
  })

  const extract = useMutation({
    mutationFn: (t: string) => api.extract(t),
    onSuccess: (r) => {
      const urls = Array.isArray(r?.urls) ? r.urls : []
      setExtracted(urls)
      setPicked(new Set(urls))
      if (urls.length === 0) toast('No URLs found in the text', 'info')
    },
    onError: (e) => toast(e instanceof Error ? e.message : 'Extraction failed', 'error'),
  })

  const submitUrl = (e: FormEvent) => {
    e.preventDefault()
    const u = url.trim()
    if (!u) return
    scan.mutate({ u, source: 'web' })
  }

  const scanPicked = async () => {
    const list = [...picked]
    if (list.length === 0) return
    if (list.length === 1) {
      scan.mutate({ u: list[0], source: 'text' })
      return
    }
    // Several URLs: scan sequentially, then open the riskiest result.
    setMulti({ total: list.length, done: 0 })
    let worst: { id: string | number; risk: number } | null = null
    for (const u of list) {
      try {
        const r = await api.scan(u, deep, 'text')
        if (!worst || r.risk_score > worst.risk) worst = { id: r.id, risk: r.risk_score }
      } catch (err) {
        toast(`${u}: ${err instanceof Error ? err.message : 'failed'}`, 'error')
      }
      setMulti((m) => (m ? { ...m, done: m.done + 1 } : m))
    }
    qc.invalidateQueries()
    setMulti(null)
    if (worst) {
      toast(`Scanned ${list.length} URLs — opening the riskiest one`, 'success')
      nav(`/scans/${worst.id}`)
    }
  }

  const onQrFile = (file: File | undefined) => {
    setQrError(null)
    setQrUrl(null)
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      const src = String(reader.result)
      setQrPreview(src)
      const img = new Image()
      img.onload = () => {
        try {
          const max = 1200
          const scale = Math.min(1, max / Math.max(img.width, img.height))
          const w = Math.max(1, Math.round(img.width * scale))
          const h = Math.max(1, Math.round(img.height * scale))
          const canvas = document.createElement('canvas')
          canvas.width = w
          canvas.height = h
          const ctx = canvas.getContext('2d')
          if (!ctx) throw new Error('Canvas unavailable')
          ctx.drawImage(img, 0, 0, w, h)
          const data = ctx.getImageData(0, 0, w, h)
          const code = jsQR(data.data, w, h, { inversionAttempts: 'attemptBoth' })
          if (!code?.data) setQrError('No QR code detected in this image. Try a sharper, well-lit image.')
          else setQrUrl(code.data.trim())
        } catch (err) {
          setQrError(err instanceof Error ? err.message : 'Could not decode image')
        }
      }
      img.onerror = () => setQrError('Could not load image')
      img.src = src
    }
    reader.readAsDataURL(file)
  }

  const busy = scan.isPending || multi !== null

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <PageHeader title="Scan" subtitle="Analyse a URL with machine learning, live network checks, brand detection and threat intelligence." />

      <Card>
        <Tabs<Tab>
          className="mb-4"
          value={tab}
          onChange={setTab}
          tabs={[
            { id: 'url', label: 'Single URL', icon: <Link2 className="size-4" /> },
            { id: 'text', label: 'Email / SMS text', icon: <Mail className="size-4" /> },
            { id: 'qr', label: 'QR code', icon: <QrCode className="size-4" /> },
          ]}
        />

        {tab === 'url' && (
          <form onSubmit={submitUrl} className="space-y-3">
            <div className="flex flex-col gap-2 sm:flex-row">
              <div className="relative flex-1">
                <ScanSearch className="pointer-events-none absolute left-3 top-1/2 size-5 -translate-y-1/2 text-zinc-400" />
                <input
                  autoFocus
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com/login"
                  className="h-12 w-full rounded-md border border-zinc-200 bg-white pl-10 pr-3 font-mono text-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 dark:border-zinc-700 dark:bg-zinc-900"
                />
              </div>
              <Button type="submit" variant="primary" className="h-12 px-6" loading={busy} disabled={!url.trim()}>
                Analyse URL
              </Button>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Toggle checked={deep} onChange={setDeep} label="Deep scan (DNS, WHOIS, SSL, HTTP, screenshot)" />
              <div className="flex flex-wrap gap-1.5 text-xs text-zinc-500">
                Try:
                {['https://www.google.com', 'http://paypa1-secure-login.com/verify', 'http://192.168.10.5/bank/login.php'].map((s) => (
                  <button key={s} type="button" onClick={() => setUrl(s)} className="font-mono text-indigo-600 hover:underline dark:text-indigo-400">
                    {s.replace(/^https?:\/\//, '')}
                  </button>
                ))}
              </div>
            </div>
          </form>
        )}

        {tab === 'text' && (
          <div className="space-y-3">
            <Textarea
              rows={7}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={'Paste a suspicious email or SMS here…\n\ne.g. "Your account is locked. Verify now at hxxp://secure-update[.]paypa1[.]com/login"'}
              className="font-mono text-xs"
            />
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Toggle checked={deep} onChange={setDeep} label="Deep scan" />
              <Button variant="primary" loading={extract.isPending} disabled={!text.trim()} onClick={() => extract.mutate(text)}>
                Extract URLs
              </Button>
            </div>
            {extracted && (
              <div className="rounded-md border border-zinc-200 dark:border-zinc-800">
                <div className="flex items-center justify-between border-b border-zinc-200 px-3 py-2 text-xs dark:border-zinc-800">
                  <span className="label">{extracted.length} URL(s) found</span>
                  {extracted.length > 0 && (
                    <button className="text-indigo-600 hover:underline dark:text-indigo-400" onClick={() => setPicked(picked.size === extracted.length ? new Set() : new Set(extracted))}>
                      {picked.size === extracted.length ? 'Select none' : 'Select all'}
                    </button>
                  )}
                </div>
                {extracted.length === 0 ? (
                  <EmptyState compact title="No URLs detected" description="Defanged URLs like hxxp:// and [.] are supported." />
                ) : (
                  <ul className="divide-y divide-zinc-100 dark:divide-zinc-800">
                    {extracted.map((u) => (
                      <li key={u}>
                        <label className="flex cursor-pointer items-center gap-2 px-3 py-2 text-sm hover:bg-zinc-50 dark:hover:bg-zinc-800/40">
                          <input
                            type="checkbox"
                            className="accent-indigo-600"
                            checked={picked.has(u)}
                            onChange={(e) => {
                              const n = new Set(picked)
                              if (e.target.checked) n.add(u)
                              else n.delete(u)
                              setPicked(n)
                            }}
                          />
                          <span className="truncate font-mono text-xs">{u}</span>
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
                {extracted.length > 0 && (
                  <div className="flex items-center justify-end gap-2 border-t border-zinc-200 px-3 py-2 dark:border-zinc-800">
                    {multi && (
                      <span className="tnum text-xs text-zinc-500">
                        Scanning {multi.done}/{multi.total}…
                      </span>
                    )}
                    <Button variant="primary" size="sm" loading={busy} disabled={picked.size === 0} onClick={scanPicked}>
                      Scan {picked.size} selected
                    </Button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {tab === 'qr' && (
          <div className="space-y-3">
            <div
              onClick={() => fileRef.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault()
                onQrFile(e.dataTransfer.files?.[0])
              }}
              className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-zinc-200 px-4 py-10 text-center hover:border-indigo-400 dark:border-zinc-700"
            >
              {qrPreview ? (
                <img src={qrPreview} alt="QR preview" className="max-h-48 rounded" />
              ) : (
                <>
                  <ImageUp className="size-8 text-zinc-400" />
                  <div className="text-sm font-medium">Drop a QR code image or click to upload</div>
                  <div className="text-xs text-zinc-500">Decoded locally in your browser — the image is never uploaded (quishing protection).</div>
                </>
              )}
              <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={(e) => onQrFile(e.target.files?.[0])} />
            </div>
            {qrError && <ErrorBox error={qrError} />}
            {qrUrl && (
              <div className="flex flex-col gap-2 rounded-md border border-zinc-200 p-3 sm:flex-row sm:items-center dark:border-zinc-800">
                <div className="min-w-0 flex-1">
                  <div className="label">Decoded content</div>
                  <div className="truncate font-mono text-sm">{qrUrl}</div>
                </div>
                <Toggle checked={deep} onChange={setDeep} label="Deep" />
                <Button variant="primary" loading={busy} onClick={() => scan.mutate({ u: qrUrl, source: 'qr' })}>
                  Scan decoded URL
                </Button>
              </div>
            )}
          </div>
        )}
      </Card>

      {scan.error && <ErrorBox error={scan.error} />}
      {(scan.isPending || scan.isSuccess || scan.isError) && <ScanProgress active={scan.isPending} done={scan.isSuccess} error={scan.isError} deep={deep} />}

      {!scan.isPending && !scan.isSuccess && (
        <div className="grid gap-3 sm:grid-cols-3">
          {[
            ['ML models', 'Logistic Regression, Decision Tree, Random Forest and SVM trained on 44 lexical URL features; the best (Random Forest) gives the score.'],
            ['Live network checks', 'DNS, WHOIS age, SSL certificate, HTTP redirects, security headers and page content.'],
            ['Threat intelligence', 'OpenPhish / PhishTank / URLhaus feeds plus community reports and brand detection.'],
          ].map(([t, d]) => (
            <Card key={t}>
              <div className="text-sm font-medium">{t}</div>
              <div className="mt-1 text-xs text-zinc-500">{d}</div>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
