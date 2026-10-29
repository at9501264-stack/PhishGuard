## 🔌 REST API

Everything the dashboard and the Chrome extension do goes through one JSON REST API built with FastAPI, so any script or tool can use the same engine. Every endpoint below can be tried from the browser in the interactive **Swagger UI** at [`/docs`](https://phishguard-mini-project.vercel.app/docs). There is no login and no rate limiting, because this is a demo.

<!-- API_TABLE -->

### Example: scan a URL

`POST /api/scan` takes a JSON body with `url` (required; `http://` is added if the scheme is missing), `deep` (optional, default `true`: run the WHOIS, DNS, SSL, HTTP and content checks; `false` = URL features + ML only) and `source` (optional, one of `web`, `api`, `bulk`, `text`, `qr`, `watch`, `extension`; default `web`).

```bash
curl -s -X POST https://phishguard-mini-project.vercel.app/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "http://paypal-login-verify.secure-account.xyz/update", "deep": true, "source": "api"}' \
  | jq '{id, verdict, risk_score, trust_score, tier, threat_type, summary}'
```

The response is the full scan result: verdict, `risk_score` (0-100), ML probability and the four model scores with feature explanations, every check with its status, the WHOIS / DNS / SSL / HTTP / content / brand / reputation evidence, and the `id` of the stored report, which the dashboard opens at `/scans/{id}`. Replace the host with `http://localhost:8000` when running locally.
