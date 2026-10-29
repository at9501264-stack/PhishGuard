## 🧮 Risk scoring

Every scan ends in one **0-100 risk score**. The score blends the ML probability with the live heuristic checks, then applies a few hard rules that a human analyst would apply too: "a blocklisted URL is dangerous no matter what the model says" and "a top-10k site with no blocklist hit is not phishing". The code is in two places: `score_checks()` in [`backend/app/analysis/engine.py`](backend/app/analysis/engine.py) (the heuristic score) and [`backend/app/scoring.py`](backend/app/scoring.py) (the blend, the floors, the cap, the tiers, the threat type and the summary). The flow chart is diagram 4 in [Architecture](#-architecture).

```text
 URL ─► 44 lexical features ─► Random Forest ──────────► p  (phishing probability, 0-1)
     └► 50+ live checks (fail / warn / pass) ─► heuristic h (0-100, with floors and caps)

 risk = round(0.6 × 100p + 0.4 × h)  ─►  blocklist floor 90  ─►  community floor 85
      ─►  popular / official cap 30  ─►  verdict · tier · trust · confidence
      ─►  engines N/M · threat type · positive / negative factors · AI summary
```

### Step 1: the heuristic score (`engine.py`)

Each check returns `pass`, `warn`, `fail`, `info` or `error` with a weight from 0 to 10 (for example: blocklist hit 10, invalid certificate 8, suspicious JavaScript 7, free hosting 4, missing HTTPS 2). Only failures and warnings count:

```text
raw = Σ weight(fail) + 0.4 × Σ weight(warn)
h   = 100 × (1 − e^(−raw / 18))
```

The exponential curve saturates, so many small warnings cannot add up to more than 100, and the first strong signals count most:

| raw | 2 | 5 | 10 | 18 | 25 | 36 | 54 |
|---|---:|---:|---:|---:|---:|---:|---:|
| **h** | 10.5 | 24.3 | 42.6 | 63.2 | 75.1 | 86.5 | 95.0 |

**Floors.** Some single signals are strong enough to set a minimum heuristic score, whatever the sum says:

| Signal | Minimum h |
|---|---:|
| Listed on a threat-intelligence feed or by Google Safe Browsing / VirusTotal | **92** |
| Impersonates a brand **and** the page has a login form | 85 |
| Password form posts to an external domain (`password_external`) | 80 |
| Brand impersonation (`brand_impersonation`) | 75 |
| Malicious JavaScript patterns (`suspicious_js`) | 60 |
| Raw IP address as host · domain younger than 30 days (`domain_age`) | 55 |
| Excessive or cross-domain redirects (`redirects`) · punycode homograph (`punycode`) | 50 |
| Invalid SSL certificate (`ssl_valid`) | 45 |
| High-risk TLD (`suspicious_tld`) | 35 |

**Caps** (applied after the floors):

- **≤ 15** for an official brand domain (for example `paypal.com`), unless it is blocklisted or is a user-content host such as `docs.google.com`.
- **≤ 20** for a Tranco top-10,000 site, unless it is blocklisted or has a hard failure: brand impersonation, off-site password form, suspicious JavaScript, DNS-blocklist listing, or a host that resolves to a private network.

The result is rounded and clamped to 0-100. Every floor and cap that was applied is listed in the report as a `score_reason`.

### Step 2: blend and floors (`compute_score`)

```text
risk = round( 0.6 × (ML probability × 100)  +  0.4 × h )
risk = max(risk, 90)   if the URL is listed by any feed or API engine   (BLACKLIST_FLOOR)
risk = max(risk, 85)   if a community report is verified                (COMMUNITY_FLOOR)
risk = clamp(risk, 0, 100)
```

- The ML probability comes from the best model (Random Forest). The other three models are shown for comparison but do not change the score.
- A community report is **verified** when phishing votes minus legitimate votes reach **3 or more**. The reporter's own label counts as the first vote.
- The report shows this as a **score breakdown** (one line each for the ML model, heuristic checks, blacklists and community, plus the cap line from step 3). Each line shows the component's score, its weight and its contribution in points.

### Step 3: popular / official domain cap (`finalize`)

If the risk is above **30**, it is lowered to **30** and the verdict is recomputed, but only when **all** of these are true:

1. No feed, API engine or DNS blocklist lists the URL, no verified community report exists, and there is no malware evidence.
2. The domain is an **official brand domain** (and the `brand_official` check did not warn), **or** it is **popular**: Tranco top-1k or top-10k tier, rank 1-10,000, or a passing `popular_site` check, with no failing brand-impersonation check.
3. The host is **not a hosting, user-content or shortener platform** (114 suffixes such as `vercel.app`, `github.io`, `pages.dev`, `docs.google.com` and `bit.ly`). Anyone can publish there, so the platform's popularity says nothing about the page.

A capped result adds a line to the breakdown (for example `Popular site (Tranco rank #102) with no blocklist hit: risk capped at 30`, contribution −4) and gets a confidence of at least 0.8.

### Step 4: verdict, tier, trust score and confidence

The two thresholds are **suspicious = 35** and **phishing = 65** by default. They are the only scoring parameters you can change at run time: use the **Settings** page or `PUT /api/settings` (`suspicious_threshold`, `phishing_threshold`, each 0-100, and suspicious must be lower than phishing). They apply to every scan scored after the change. The weights (0.6 / 0.4), floors (90 / 85), the cap (30) and the Trusted limit (15) are constants in `scoring.py`.

| Risk score | Verdict | Trust tier | Tier rule (S = suspicious, P = phishing threshold) | Trust score |
|---|---|---|---|---|
| 0-14 | ✅ Legitimate | 🟢 **Trusted** | `[0, 15)` | 86-100 |
| 15-34 | ✅ Legitimate | 🟩 **Favorable** | `[15, S)` | 66-85 |
| 35-49 | ⚠️ Suspicious | 🟡 **Neutral** | `[S, (S+P)/2)` | 51-65 |
| 50-64 | ⚠️ Suspicious | 🟠 **Questionable** | `[(S+P)/2, P)` | 36-50 |
| 65-100 | 🚨 Phishing | 🔴 **Untrusted** | `[P, 100]` | 0-35 |

- **Trust score** = `100 − risk`.
- **Confidence** (0-1) measures how far the score is from the nearest threshold, relative to the width of its band:
  - phishing band: `(risk − P) / (100 − P)`
  - suspicious band: `min(risk − S, P − risk) / ((P − S) / 2)`
  - legitimate band: `(S − risk) / S`

  It is at least **0.9** when a blocklist or a verified community report decided the result, and at least **0.8** for a legitimate popular or official domain that qualifies for the cap.
- **Untested handling.** `tested_depth` is `lexical` when only the URL-based checks, the local feeds and the ML model ran. That happens with a quick scan (`"deep": false` in the API), with network checks turned off in Settings, or when the [SSRF guard](#safety) blocked the target. The score is still computed, but the UI shows **"Untested (lexical only)"** next to the tier and the summary says the live site was not tested. A low score never looks like a full clean bill of health.

### Step 5: detection engines, the "N/M engines" badge

Each report lists every reputation source as an **engine**:

| Engine group | Engines |
|---|---|
| Local threat feeds (always, offline) | OpenPhish, URLhaus (malware), Phishing.Database, PhishTank, Phishing Army |
| Optional cloud APIs (when an API key is set) | Google Safe Browsing, VirusTotal |
| DNS blocklists (network checks on) | Spamhaus DBL, SURBL, URIBL (domain) · Spamhaus ZEN, SpamCop (IPv4 address) |
| PhishGuard itself | **PhishGuard ML**: listed when the *final* verdict is phishing |

**N/M** = engines that list the URL / engines that gave a definite answer. Engines that errored or did not apply are left out of M. The badge and the summary include PhishGuard ML. The "Not listed by any reputation engine" / "Flagged by reputation engines" factor counts **external engines only**, so PhishGuard never vouches for itself.

### Step 6: threat type

The first type with evidence wins: **`malware` > `social_engineering` > `unwanted_software` > `none`**.

| Threat type | Evidence (any one is enough) |
|---|---|
| `malware` | Listed by a malware engine (URLhaus) · the verdict is not legitimate and the URL path ends in an executable or archive (`.exe .apk .scr .bat .cmd .msi .jar .vbs .ps1 .dll .hta .zip .rar .7z .iso .dmg`) |
| `social_engineering` | Listed by a phishing feed or engine · impersonates a brand (not a defensive redirect) · login or password form on a site whose verdict is not legitimate · phishing verdict |
| `unwanted_software` | Parked domain · SEO spam · hidden iframe · listed on a spam blocklist while the verdict is not legitimate |
| `none` | No evidence. Always `none` for a popular or official domain that qualifies for the cap, unless malware evidence exists. |

The report shows the evidence list (`threat_reasons`) next to the type.

### Step 7: positive and negative factors and the AI summary

**Factors** (`factors_for`). Every failing or warning check becomes a **negative factor** with a severity:

- a failure with weight ≥ 6 is **high**, weight ≥ 3 is **medium**, otherwise **low**;
- a warning with weight ≥ 7 is **medium**, otherwise **low**.

A passing check with weight > 0 (or a strong one such as a valid certificate, an old domain or no blocklist listing) becomes a **positive factor**. Three synthetic factors are added:

- the ML probability: under 30% is positive; 50% or more is negative, with high severity at 85% or more and medium at 70% or more;
- the external-engine ratio;
- the cap reason, shown first among the positives.

Negatives are sorted by severity and then weight, positives by weight. The lists are trimmed to 20 negatives and 15 positives.

**AI summary** (`build_summary`). This is plain English produced by **deterministic, rule-based templates**. No external LLM is called, so it works offline and the same scan always gives the same text. It has up to four sentences:

1. The verdict, risk score, trust score and tier.
2. The ML phishing probability and "*N* of *M* detection engines (including PhishGuard ML) flagged it".
3. For a legitimate verdict, the top three **positive signals**. Otherwise, the top three **key findings**: the engine's plain-English facts, most severe first.
4. "Only URL-based (lexical) checks ... the live site is untested" for a lexical scan, or otherwise the threat type.

### Worked example

This is a real scan from the demo data: a phishing kit on a free-hosting platform, `hxxp://www.indesx-mauve.vercel[.]app/` (defanged), with network checks on.

| Step | Input | Calculation | Result |
|---|---|---|---:|
| 1. Failed checks | blocklists 10 · invalid SSL certificate (hostname mismatch) 8 · suspicious JavaScript (obfuscated `eval(unescape(...))`, Telegram bot exfiltration) 7 | 10 + 8 + 7 | 25 |
| 2. Warnings | third-party resources on login page 5 · free hosting 4 · login form 3 · no HTTPS 2 · security headers 2 | 0.4 × 16 | 6.4 |
| 3. Heuristic curve | raw = 31.4 | 100 × (1 − e^(−31.4/18)) | 82.5 |
| 4. Heuristic floors | listed in OpenPhish + Phishing Army → 92 · suspicious JS → 60 · invalid SSL → 45 | max(82.5, 92, 60, 45) | **h = 92** |
| 5. ML | Random Forest P(phishing) = 0.9998 | 0.6 × 99.98 | 59.99 |
| 6. Blend | | 59.99 + 0.4 × 92 = 59.99 + 36.8 = 96.79 → round | 97 |
| 7. Final floors | blocklisted (≥ 90), community report verified with 5 phishing votes to 1 (≥ 85) | max(97, 90, 85) | 97 |
| 8. Cap | listed by feeds, and `vercel.app` is a hosting platform | not applied | 97 |
| **Result** | | 97 ≥ 65 | **Risk 97 · 🚨 Phishing · 🔴 Untrusted** |

- **Trust score** = 100 − 97 = **3**. **Confidence** = (97 − 65) / (100 − 65) = **0.914**.
- **Engines: 3/11 flagged.** OpenPhish, Phishing Army and PhishGuard ML listed it. URLhaus, Phishing.Database, PhishTank and the five DNS blocklists did not. No API keys were set.
- **Threat type:** `social_engineering` ("Listed as phishing by OpenPhish", "Listed as phishing by Phishing Army", "Login/password form on a suspicious site", "Phishing verdict").
- **Summary produced:** *"PhishGuard rates www.indesx-mauve.vercel.app as phishing with a risk score of 97/100 (trust score 3/100, tier Untrusted). The machine-learning model estimates a 100% phishing probability, and 3 of 11 detection engines (including PhishGuard ML) flagged it. Key findings: Listed on threat-intelligence blocklists ...; SSL certificate is not valid ...; Suspicious JavaScript .... Threat type: social engineering (phishing)."*

> [!NOTE]
> **The cap in action:** `https://www.reddit.com/r/netsec/` gets ML probability 0.5216 (a deep link looks a little unusual to the model) and h = 6 (one favicon warning: raw 1.2 → 6.4, and the top-10k cap of 20 does not bind). The blend is round(31.30 + 2.4) = **34**, which is still legitimate but close to the threshold. Reddit is Tranco **#102** with 0/10 external engines listing it, so the cap lowers the risk to **30**. Final result: **Legitimate · Favorable · trust 70 · confidence 0.8**.

### Safety

A phishing scanner has to visit hostile URLs, so the scanner must never be turned into a weapon against its own network. All of this is in [`backend/app/analysis/net_safety.py`](backend/app/analysis/net_safety.py).

**SSRF guard: only public addresses are fetched.**

- **Allowed:** only `http` and `https`, and only ports **80, 443, 8080 and 8443**.
- **Pre-check:** before any live probe the target host is resolved, and **every** resolved address must be globally routable. Refused:
  - loopback, private (RFC 1918), link-local (including the `169.254.169.254` cloud-metadata service), multicast, unspecified, reserved and shared/CGNAT addresses, and IPv6 site-local;
  - IPv4-mapped, 6to4 and NAT64 addresses that wrap a non-public IPv4 address, and Teredo tunnels;
  - local host names (`localhost`, `*.local`, `.internal`, `.lan`, `.corp`, `.home.arpa` ...);
  - IP literals in disguise: decimal `2130706433`, hex `0x7f000001`, octal `0177.0.0.1` and short `127.1` are decoded first.
- **Pinned connections:** the HTTP probe uses a guarded `httpx` client. Its connection layer resolves the host, validates the addresses and then **connects to the validated IP itself** (TLS SNI still uses the host name). A DNS-rebinding answer between "check" and "connect" therefore cannot reach an internal host. The client ignores proxy environment variables.
- **Every redirect re-checked:** automatic redirects are off. `fetch()` follows at most **10** redirects by hand and **re-validates every hop**. A public page that redirects to `http://127.0.0.1:8000/` is stopped at that hop. The TLS-certificate check also connects only to a validated address.
- **When a target is blocked:** the live probes are skipped and the report shows `blocked: non-public address` with the reason. The scan still returns a score from the lexical checks, local feeds and the ML model, marked "Untested (lexical only)".
- **What does not use the guard:** fixed third-party lookups (ip-api / ipwho.is geolocation, rdap.org, DNSBL queries, and the thum.io screenshot service for the report's Screenshot tab). Only the host name, IP or URL is sent to them as data, and PhishGuard's server never connects to the target for them.

**Hostile page content is never executed.**

- At most **2 MiB** of the response body is read. The stored DOM snapshot is capped at **500 KB** and kept gzip-compressed in the `scan_dom` table.
- The report's **Source** tab shows the HTML **only as escaped plain text**, line by line in React text nodes. It is never rendered, injected or put in an iframe (there is no `dangerouslySetInnerHTML` or `srcdoc` in the frontend). No form is submitted, and only `GET` requests are made.

**Timeouts everywhere.**

- **Per-request timeout:** `timeout_s`, 8 s by default. It can be set from 0.5 to 60 s, and the engine clamps it to 2-20 s.
- **Per-step limits:** DNS resolution 4 s, cached for 30 s; TCP connect at most 5 s; each DNS-blocklist query at most 2 s; body reads stop at the deadline.
- **Whole scan:** the full set of checks has a hard budget of `max(timeout + 2, 10) + 3` seconds inside the engine, and the scanner adds an outer safety net of `max(25, 2 × timeout + 10)` seconds around it. Every sub-check is wrapped so that a failure or a timeout becomes an `error` check instead of an exception. `run_checks()` and `fetch()` never raise, so one slow or hostile site cannot hang the API.
