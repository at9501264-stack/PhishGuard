import { useState } from 'react'
import { BookOpen, Check, Copy, ExternalLink } from 'lucide-react'
import { Card, CardHeader, PageHeader } from '../components/Card'
import { Button, Chip } from '../components/ui'
import { copyText } from '../lib/format'

interface Example {
  title: string
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  path: string
  desc: string
  curl: (o: string) => string
}

const EXAMPLES: { group: string; items: Example[] }[] = [
  {
    group: 'Scanning',
    items: [
      { title: 'Health check', method: 'GET', path: '/api/health', desc: 'Service, model and database status.', curl: (o) => `curl ${o}/api/health` },
      {
        title: 'Scan a URL',
        method: 'POST',
        path: '/api/scan',
        desc: 'Run the full analysis pipeline. Returns a ScanResult with verdict, risk score, ML explanation and all checks.',
        curl: (o) => `curl -X POST ${o}/api/scan \\\n  -H 'Content-Type: application/json' \\\n  -d '{"url": "http://paypal-login.secure-verify.com", "deep": true, "source": "api"}'`,
      },
      {
        title: 'List scans',
        method: 'GET',
        path: '/api/scans',
        desc: 'Paginated, filterable scan history.',
        curl: (o) => `curl '${o}/api/scans?verdict=phishing&min_risk=60&sort=risk_score&order=desc&page=1&page_size=25'`,
      },
      { title: 'Scan detail', method: 'GET', path: '/api/scans/{id}', desc: 'Full ScanResult for one scan.', curl: (o) => `curl ${o}/api/scans/1` },
      { title: 'Rescan', method: 'POST', path: '/api/scans/{id}/rescan', desc: 'Re-run analysis for the same URL.', curl: (o) => `curl -X POST ${o}/api/scans/1/rescan` },
      {
        title: 'Tag / annotate',
        method: 'PATCH',
        path: '/api/scans/{id}',
        desc: 'Update tags and notes.',
        curl: (o) => `curl -X PATCH ${o}/api/scans/1 \\\n  -H 'Content-Type: application/json' \\\n  -d '{"tags": ["campaign-x"], "notes": "Seen in SMS"}'`,
      },
      { title: 'Compare two scans', method: 'GET', path: '/api/scans/{id}/compare/{other_id}', desc: 'Field-level diff between two scans.', curl: (o) => `curl ${o}/api/scans/2/compare/1` },
      {
        title: 'Export scans',
        method: 'GET',
        path: '/api/scans/export',
        desc: 'Download CSV or JSON with the same filters as the list endpoint.',
        curl: (o) => `curl -o scans.csv '${o}/api/scans/export?format=csv&verdict=phishing'`,
      },
    ],
  },
  {
    group: 'Bulk & extraction',
    items: [
      {
        title: 'Create bulk job',
        method: 'POST',
        path: '/api/bulk',
        desc: 'Queue up to 500 URLs.',
        curl: (o) => `curl -X POST ${o}/api/bulk \\\n  -H 'Content-Type: application/json' \\\n  -d '{"name": "inbox sweep", "urls": ["example.com", "http://secure-login-paypa1.com"]}'`,
      },
      { title: 'Upload CSV/TXT', method: 'POST', path: '/api/bulk/upload', desc: 'Multipart file upload, one URL per line.', curl: (o) => `curl -X POST ${o}/api/bulk/upload -F 'file=@urls.txt'` },
      { title: 'Bulk job status', method: 'GET', path: '/api/bulk/{id}', desc: 'Progress, verdict counts and results.', curl: (o) => `curl ${o}/api/bulk/1` },
      {
        title: 'Extract URLs from text',
        method: 'POST',
        path: '/api/extract',
        desc: 'Find (and re-fang) URLs in an email or SMS body.',
        curl: (o) => `curl -X POST ${o}/api/extract \\\n  -H 'Content-Type: application/json' \\\n  -d '{"text": "Your account is locked, verify at hxxps://paypal-verify[.]com/login"}'`,
      },
      { title: 'Typosquat permutations', method: 'GET', path: '/api/typosquat', desc: 'dnstwist-style permutations with DNS resolution.', curl: (o) => `curl '${o}/api/typosquat?domain=paypal.com'` },
    ],
  },
  {
    group: 'Community & monitoring',
    items: [
      {
        title: 'Submit report',
        method: 'POST',
        path: '/api/reports',
        desc: 'PhishTank-style community report (triggers a scan).',
        curl: (o) => `curl -X POST ${o}/api/reports \\\n  -H 'Content-Type: application/json' \\\n  -d '{"url": "http://secure-login-paypa1.com", "label": "phishing", "brand": "PayPal"}'`,
      },
      { title: 'List reports', method: 'GET', path: '/api/reports', desc: 'Filter by status: pending, verified, rejected.', curl: (o) => `curl '${o}/api/reports?status=pending&page=1'` },
      {
        title: 'Vote on report',
        method: 'POST',
        path: '/api/reports/{id}/vote',
        desc: 'Verified at +3 net phishing votes, rejected at −3.',
        curl: (o) => `curl -X POST ${o}/api/reports/1/vote \\\n  -H 'Content-Type: application/json' \\\n  -d '{"vote": "phishing"}'`,
      },
      {
        title: 'Add to watchlist',
        method: 'POST',
        path: '/api/watchlist',
        desc: 'Monitor a URL/domain on an interval, optionally including typosquats.',
        curl: (o) => `curl -X POST ${o}/api/watchlist \\\n  -H 'Content-Type: application/json' \\\n  -d '{"target": "mybank.com", "interval_minutes": 60, "monitor_typosquats": true}'`,
      },
      { title: 'Alerts', method: 'GET', path: '/api/alerts', desc: 'Unread alerts only.', curl: (o) => `curl '${o}/api/alerts?unread=true'` },
    ],
  },
  {
    group: 'Analytics & settings',
    items: [
      { title: 'Overview KPIs', method: 'GET', path: '/api/analytics/overview', desc: 'range = 24h | 7d | 30d | 90d | all', curl: (o) => `curl '${o}/api/analytics/overview?range=30d'` },
      { title: 'Timeseries', method: 'GET', path: '/api/analytics/timeseries', desc: 'Scan counts by verdict per bucket.', curl: (o) => `curl '${o}/api/analytics/timeseries?range=7d&bucket=hour'` },
      { title: 'Distributions', method: 'GET', path: '/api/analytics/distribution', desc: 'TLDs, countries, brands, heatmap, checks…', curl: (o) => `curl '${o}/api/analytics/distribution?range=30d'` },
      { title: 'Model metrics', method: 'GET', path: '/api/analytics/model', desc: 'Training metrics + live stats.', curl: (o) => `curl ${o}/api/analytics/model` },
      { title: 'Get settings', method: 'GET', path: '/api/settings', desc: 'API keys are masked.', curl: (o) => `curl ${o}/api/settings` },
      {
        title: 'Update settings',
        method: 'PUT',
        path: '/api/settings',
        desc: 'Change thresholds and toggles.',
        curl: (o) => `curl -X PUT ${o}/api/settings \\\n  -H 'Content-Type: application/json' \\\n  -d '{"suspicious_threshold": 35, "phishing_threshold": 65, "enable_network_checks": true}'`,
      },
    ],
  },
]

const methodTone = { GET: 'emerald', POST: 'indigo', PUT: 'amber', PATCH: 'amber', DELETE: 'rose' } as const

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="group relative">
      <pre className="thin-scroll overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-zinc-200 bg-zinc-950 p-3 pr-10 font-mono text-[12px] leading-relaxed text-zinc-100 dark:border-zinc-800">
        <code>{code}</code>
      </pre>
      <button
        onClick={async () => {
          if (await copyText(code)) {
            setCopied(true)
            setTimeout(() => setCopied(false), 1500)
          }
        }}
        className="absolute right-2 top-2 rounded border border-zinc-700 bg-zinc-900 p-1 text-zinc-400 hover:text-zinc-100"
        aria-label="Copy"
        title="Copy"
      >
        {copied ? <Check className="size-3.5 text-emerald-400" /> : <Copy className="size-3.5" />}
      </button>
    </div>
  )
}

export default function ApiGuidePage() {
  const origin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:5173'
  return (
    <div className="space-y-5">
      <PageHeader
        title="API guide"
        subtitle={`REST API at ${origin}/api — JSON in/out, ISO-8601 UTC timestamps. Interactive OpenAPI docs are served by the backend.`}
        actions={
          <a href="/docs" target="_blank" rel="noreferrer">
            <Button variant="primary" icon={<BookOpen className="size-4" />}>
              Open Swagger docs <ExternalLink className="size-3.5" />
            </Button>
          </a>
        }
      />
      {EXAMPLES.map((g) => (
        <Card key={g.group}>
          <CardHeader title={g.group} />
          <div className="grid gap-4 xl:grid-cols-2">
            {g.items.map((ex) => (
              <div key={ex.title} className="min-w-0">
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <Chip tone={methodTone[ex.method]}>{ex.method}</Chip>
                  <span className="font-mono text-xs text-zinc-700 dark:text-zinc-300">{ex.path}</span>
                  <span className="text-sm font-medium">· {ex.title}</span>
                </div>
                <p className="mb-1.5 text-xs text-zinc-500">{ex.desc}</p>
                <CodeBlock code={ex.curl(origin)} />
              </div>
            ))}
          </div>
        </Card>
      ))}
    </div>
  )
}
