#!/usr/bin/env python3
"""Capture the README media for PhishGuard: page screenshots, a demo video (MP4 + GIF) and a manifest.

Run it with the backend virtualenv, which has Playwright + Chromium + Pillow installed:

    backend/.venv/bin/python scripts/capture_media.py --base-url http://127.0.0.1:5173
    backend/.venv/bin/python scripts/capture_media.py --base-url https://<deploy-url> --readme README.md
    backend/.venv/bin/python scripts/capture_media.py --base-url http://127.0.0.1:5173 --only analytics,report --skip-video

    # interactive shots + cropped Analytics / Model Lab regions only, then number the set for the README
    backend/.venv/bin/python scripts/capture_media.py --base-url http://127.0.0.1:5173 --extras-only --skip-video
    backend/.venv/bin/python scripts/capture_media.py --curate --out docs/media

Outputs (default ``docs/media/``):
  * ``*.png``         screenshots (1440x900 viewport at deviceScaleFactor 2, full page capped, downscaled to <= 400 KB)
                      named by shot (overview.png, report-phishing-ml.png, ...) until ``--curate`` renames them to
                      the numbered README set (01-overview.png ... 49-mobile-report.png, see CURATED)
  * ``screenshots.json`` (written by ``--curate``) ordered list of {file, title, section, explanation}
  * ``demo.mp4``      ~60-90 s walkthrough (H.264, yuv420p, faststart, CRF ~28, <= 15 MB)
  * ``demo.gif``      first ~25 s of the walkthrough (960 px wide, 10 fps, palettegen/paletteuse, <= 8 MB)
  * ``manifest.json`` every produced file with a caption, size, dimensions and what failed

Everything is read-only except the demo video, which runs ONE deep scan of ``--demo-url`` through the UI.
Pages, report tabs and sidebar links are discovered from the DOM; anything missing is logged and skipped.
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

try:
    from PIL import Image
except ImportError:  # pragma: no cover - environment problem
    sys.exit("Pillow is missing. Run with backend/.venv/bin/python (or: pip install Pillow).")
try:
    from playwright.sync_api import Browser, BrowserContext, Error as PWError, Page, sync_playwright
except ImportError:  # pragma: no cover - environment problem
    sys.exit("Playwright is missing. Run with backend/.venv/bin/python "
             "(or: pip install playwright && python -m playwright install chromium).")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "docs" / "media"
DEMO_URL = "http://paypal-login-verify.secure-account.xyz/update"
TYPOSQUAT_DOMAIN = "paypal.com"
BULK_SAMPLE = ("https://www.google.com", "https://github.com/login", "http://paypal-login-verify.secure-account.xyz/update",
               "http://www.indesx-mauve.vercel.app/", "https://www.dropbox.com/login", "https://github.com/login")
# Inputs for the interactive shots (capture_extras). Nothing here is submitted except the one deep scan.
SAMPLE_EMAIL = """From: "PayPal Service" <service@paypa1-support.com>
Subject: Action required - your account has been limited
We noticed an unusual sign-in. Verify your identity within 24 hours:
hxxp://paypal-login-verify[.]secure-account[.]xyz/update
Shared document (Webmail re-validation): http://www.indesx-mauve.vercel.app/
Help Centre: https://www.paypal.com/help"""
COMMUNITY_SAMPLE = {"url": "http://secure-paypa1-login.com/verify", "brand": "PayPal",
                    "comment": "Received by SMS: 'Your PayPal account is on hold, verify now'"}
PROGRESS_URL = "http://www.indesx-mauve.vercel.app/"   # a live phishing kit, deep-scanned for the progress shot
HISTORY_PIVOT = {"threat_type": "social_engineering", "tier": "Untrusted"}
GRAPH_DOMAIN = "metamask-docs-keec0mi8n-consensys-ddffed67.vercel.app"  # /graph?domain=...&depth=2 (about 20 nodes)
GRAPH_FOCUS = ("Domain metamask-docs", "Domain www.indesx-mauve", "Domain ")
WATCH_HISTORY_LABEL = "PayPal brand protection"
# QR code (quishing test image) that encodes a phishing-style URL; decoded in the browser by jsQR.
QR_PNG_B64 = ("iVBORw0KGgoAAAANSUhEUgAAAewAAAHsAQMAAAAq5AwjAAAABlBMVEURGCf///8AJgUnAAACIUlEQVR42u2dUW6DQAwFrV4g97+lb0AbwdrP"
              "C+pPpFa2BlURTZifanDeGkPt+GRzAwcHBwcHBwcHBwf/d9xie12f/Oy8993y9X6Yf9lHGzj43+MWhm+qb7bnR3o8zoN3dv6s3rmjp4NfR+ph"
              "OA8+x/lXCT9a9nEefKTzRXVJ+9R58Kl5/pQ8AvzjVwDOg7d3Xhoyv/3QtwGf4rxuobQG+z3nHzgPPifbXG+e69YVcvJccDlTcB68f7a5p/qU"
              "f+1kwcd58L7Zxqvtr9qWX/JHqsd58Al1XhqV2rTZGzisYcGnOP8Y5lX7reDjPHj7NaxbFvlVzCPbnHm+LGZxHrx5ns/oUi+2xq9R/3OYE+fB"
              "+zqv3XgvRV4XuXlSUOfBZ/RttlakTtps8QbnwQc4X+fKspljmWdioh7nwSesYaVvk90bffXSpcd58O7Oa54vkusy1rdvB/7y4G2dt5pe7OlW"
              "Ef0KwHnwAc4v87UJn++skRucBx+V503aMjFXdtwmcOjPg0/J83o1NqeLba/z5HnwMdlGr8bqXbHl4Tbaz8R58LbOb/dJZba/XYcqN8biPHjn"
              "Oq9lXLs3+iQE5ufBh61hy8ywRJpteRv7OA/eew0bVT3a8mb7E8yspB2cBx/jfHlSpeeStqxkcR58jPNHye1R7XPADOfBh+V5nSKrDwApwuM8"
              "+JS+jdUB4zJI7/TnwW1ef55/VwEODg4ODg4ODg7eBP8GadTMWxJWrWcAAAAASUVORK5CYII=")
EXTRA_STEMS = {"scan-text", "scan-qr", "scan-progress", "history-pivot", "graph-node",
               "watchlist-history"}  # + the region stems below
# Cropped regions of long pages: (file stem, card titles, include the page header, caption, group)
ANALYTICS_REGIONS: tuple[tuple[str, tuple[str, ...], bool, str, str], ...] = (
    ("analytics-trends", ("Scans over time", "Average risk trend", "Activity heatmap"), True,
     "Analytics: scans over time by verdict, average risk trend and the weekday x hour activity heatmap", "Analytics"),
    ("analytics-distributions", ("Top-level domains", "Scan sources", "Impersonation techniques", "SSL status",
                                 "Domain age distribution", "Top failed checks"), False,
     "Analytics: TLDs, scan sources, impersonation techniques, SSL status, domain age and top failed checks",
     "Analytics"),
    ("analytics-insights", ("Threat insights", "Threat types", "Reputation tiers", "Content categories"), False,
     "Analytics: threat insights (threat types, reputation tiers, content categories)", "Analytics"),
    ("analytics-funnel", ("Detection funnel",), False, "Analytics: detection funnel", "Analytics"),
    ("analytics-performance", ("Performance", "Throughput", "Check error rates"), False,
     "Analytics: scan latency percentiles, throughput and per-check error rates", "Analytics"),
)
MODEL_REGIONS: tuple[tuple[str, tuple[str, ...], bool, str, str], ...] = (
    ("model-lab-comparison", ("Dataset", "Model comparison", "Metric comparison"), True,
     "Model Lab: dataset, live model statistics and the comparison of the four classifiers", "Machine learning"),
    ("model-lab-realistic", ("Realistic evaluation — unseen domains", "Dataset composition"), False,
     "Model Lab: realistic evaluation on unseen domains and the dataset composition", "Machine learning"),
    ("model-lab-curves", ("ROC curves", "Precision–recall curves"), False,
     "Model Lab: ROC and precision-recall curves of all four models", "Machine learning"),
    ("model-lab-confusion", ("Confusion matrices",), False, "Model Lab: confusion matrices", "Machine learning"),
    ("model-lab-features", ("Feature importance", "Feature statistics"), False,
     "Model Lab: feature importance and per-class feature statistics", "Machine learning"),
)
EXTRA_STEMS |= {r[0] for r in ANALYTICS_REGIONS + MODEL_REGIONS}
GALLERY_START = "<!-- MEDIA-GALLERY:START -->"
GALLERY_END = "<!-- MEDIA-GALLERY:END -->"
METRICS_START = "<!-- ML-METRICS:START -->"
METRICS_END = "<!-- ML-METRICS:END -->"
METRICS_FILE = ROOT / "backend" / "ml" / "artifacts" / "metrics.json"
MOBILE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1")
_T0 = time.monotonic()


def log(msg: str, level: str = "info") -> None:
    tag = {"info": "  ", "ok": "+ ", "warn": "! ", "error": "x ", "step": "> "}.get(level, "  ")
    print(f"[{time.monotonic() - _T0:6.1f}s] {tag}{msg}", flush=True)


# ============================================================================ catalogue
@dataclass(frozen=True)
class PageSpec:
    name: str                   # output file stem
    labels: tuple[str, ...]     # sidebar labels to look for (first match wins)
    paths: tuple[str, ...]      # fallback routes when the sidebar has no such link
    caption: str
    group: str
    mode: str = "full"          # full (capped full page) | sections (several scrolled viewports)
    sections: int = 1
    v2: bool = False            # optional page: its absence is reported as "skipped", not as a failure
    crop_h: int | None = None   # cut the shot at this many CSS px (long pages whose tail adds nothing)
    auto_crop: bool = False     # cut the shot just below the page content (short pages: no empty canvas)


PAGES: tuple[PageSpec, ...] = (
    PageSpec("overview", ("Overview", "Dashboard"), ("/",),
             "Overview dashboard: KPI cards, scan trend, verdict mix and the live feed of recent scans", "Dashboard"),
    PageSpec("scan", ("Scan",), ("/scan",),
             "Scan page: single URL, email/SMS text (URL extraction) or QR code, with an optional deep scan", "Scanning"),
    PageSpec("history", ("History",), ("/history",),
             "Scan history: search, filters, sorting and CSV/JSON export of every scan", "Scanning"),
    PageSpec("bulk", ("Bulk Scan", "Bulk"), ("/bulk",),
             "Bulk scanning: paste or upload up to 500 URLs and follow the job", "Scanning"),
    PageSpec("analytics", ("Analytics",), ("/analytics",), "Analytics", "Analytics", mode="sections", sections=6),
    PageSpec("model-lab", ("Model Lab", "Model"), ("/model",), "Model Lab", "Machine learning", mode="sections",
             sections=3),
    PageSpec("watchlist", ("Watchlist",), ("/watchlist",),
             "Watchlist: scheduled re-checks of URLs/domains with typosquat monitoring and change alerts", "Monitoring",
             auto_crop=True),
    PageSpec("typosquat", ("Typosquat",), ("/typosquat",),
             f"Typosquat finder: lookalike permutations of {TYPOSQUAT_DOMAIN} and which of them resolve",
             "Threat intelligence", crop_h=1425),
    PageSpec("community", ("Community",), ("/community",),
             "Community: PhishTank-style reports with voting", "Community", auto_crop=True),
    PageSpec("feeds", ("Threat Feeds", "Feeds"), ("/feeds",),
             "Threat feeds: local blocklists (OpenPhish, PhishTank, URLhaus, Phishing.Database, Phishing Army) with "
             "search and statistics", "Threat intelligence"),
    PageSpec("alerts", ("Alerts",), ("/alerts",),
             "Alerts raised by high-risk scans, watchlist changes and community verification", "Monitoring",
             auto_crop=True),
    PageSpec("activity", ("Activity Log", "Activity"), ("/activity",),
             "Activity log: audit trail of every scan, report, vote, bulk job and settings change", "Monitoring",
             crop_h=1190),
    PageSpec("settings", ("Settings",), ("/settings",),
             "Settings: verdict thresholds, network checks, optional VirusTotal / Google Safe Browsing keys and data retention", "Administration"),
    PageSpec("graph", ("Graph", "Relationship Graph"), ("/graph",),
             "Relationship graph: scanned domains linked through shared IPs, ASNs, name servers, registrars, brands and redirects",
             "Threat intelligence", v2=True),
    PageSpec("api-guide", ("API Guide",), ("/api-guide",),
             "API guide: copy-paste examples for the REST API", "Developer API", crop_h=1320),
)

# (key, label aliases (normalised, exact or prefix match), caption, optional)
# optional tabs (v2) are captured when the report has them; their absence is "skipped", not a failure.
REPORT_TABS: tuple[tuple[str, tuple[str, ...], str, bool], ...] = (
    ("summary", ("summary", "overview"), "Summary: risk gauge, trust tier, AI summary, score factors and every check", False),
    ("ml", ("ml explanation", "ml", "machine learning", "model"),
     "ML Explanation: per-model probabilities and the URL features that raised or lowered the score", False),
    ("domain", ("domain", "whois"), "Domain: WHOIS (registrar, age, expiry) and DNS records", False),
    ("geo", ("geo & hosting", "geo and hosting", "geo", "hosting"),
     "Geo & Hosting: server IP location, ASN / network owner and hosting provider", True),
    ("ssl", ("ssl", "tls", "certificate"), "SSL: certificate issuer, validity window, SANs and protocol", False),
    ("http", ("http & content", "http and content", "http"),
     "HTTP: redirect chain, security headers, forms, links and scripts", False),
    ("brand", ("brand",), "Brand: impersonated brand, technique and similarity", False),
    ("reputation", ("reputation",), "Reputation: per-engine verdicts (local threat feeds, DNS blocklists, PhishGuard ML) plus community votes", False),
    ("content", ("content",), "Content: page category, language and parked-domain detection, plus analytics/ad trackers", True),
    ("resources", ("resources",), "Resources: contacted domains and every script, style, image, frame and form",
     True),
    ("source", ("source", "dom", "html source"), "Source: stored HTML of the page with line numbers and search",
     True),
    ("graph", ("graph",), "Graph: relationship graph around the scanned domain (IP, ASN, registrar, name servers)", True),
    ("timeline", ("timeline",), "Timeline: events recorded for this scan and its domain", True),
)
LEGIT_TABS = ("summary", "ml")
# report tabs that need deep-scan data (a lexical-only scan shows an empty state there)
DEEP_TABS = {"content", "resources", "source", "graph"}
TAB_VOCAB = ("summary", "ml", "domain", "geo", "ssl", "http", "brand", "reputation", "engines", "content",
             "resources", "source", "email", "favicon", "cloaking", "browser", "graph", "timeline", "screenshot", "raw")
# report tabs shown in the video, by priority (at most VIDEO_MAX_TABS, then played in tab-bar order)
VIDEO_TABS = ("ml", "content", "graph", "reputation", "http", "domain", "brand", "ssl")
VIDEO_MAX_TABS = 5
VIDEO_SCROLL_TABS = {"ml", "http", "engines", "content"}
GROUP_ORDER = ("Dashboard", "Scanning", "Scan report", "History & bulk", "Analytics", "Machine learning",
               "Investigation", "Monitoring", "Community & intel", "Tracking & settings", "Responsive & themes",
               # groups used by raw capture runs (before --curate)
               "Threat intelligence", "Community", "Developer API", "Administration", "Dark mode", "Mobile", "Video")

# ============================================================================ in-page helpers (init script)
HELPERS_JS = r"""
(() => {
  if (window.__pg) return;
  const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();
  const visible = (e) => {
    if (!e || !e.getBoundingClientRect) return false;
    const r = e.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    const cs = getComputedStyle(e);
    return cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity || '1') > 0.05;
  };
  const isDoc = (el) => el === document.scrollingElement || el === document.documentElement || el === document.body;
  const scrollEl = () => {
    const se = document.scrollingElement || document.documentElement;
    if (se.scrollHeight > se.clientHeight + 4) return se;
    let best = null, bestH = 0;
    for (const el of document.querySelectorAll('main, [class*="overflow-y-auto"], [class*="overflow-auto"], [class*="overflow-y-scroll"]')) {
      if (el.clientHeight < innerHeight * 0.5) continue;
      if (el.scrollHeight - el.clientHeight > 4 && el.scrollHeight > bestH) { best = el; bestH = el.scrollHeight; }
    }
    return best || se;
  };
  const norm = (s) => clean(s).replace(/\s*\(?\d[\d,]*\)?$/, '').trim().toLowerCase();
  const pg = {
    clean, visible, scrollEl,
    contentHeight() {
      const el = scrollEl();
      if (isDoc(el)) return Math.max(el.scrollHeight, document.body ? document.body.scrollHeight : 0);
      return el.scrollHeight + Math.max(0, innerHeight - el.clientHeight);
    },
    scrollTo(y) { const el = scrollEl(); el.scrollTop = y; return el.scrollTop; },
    scrollTop() { return scrollEl().scrollTop; },
    async smoothScroll(o) {
      const el = scrollEl();
      const start = el.scrollTop;
      const max = Math.max(0, el.scrollHeight - el.clientHeight);
      let target = (o.to !== undefined && o.to !== null) ? o.to : start + (o.by || 0);
      target = Math.max(0, Math.min(max, target));
      const ms = Math.max(1, o.ms || 800);
      const ease = (p) => p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2;
      const t0 = performance.now();
      await new Promise((res) => {
        const step = (t) => {
          const p = Math.min(1, (t - t0) / ms);
          el.scrollTop = start + (target - start) * ease(p);
          if (p < 1) requestAnimationFrame(step); else res();
        };
        requestAnimationFrame(step);
      });
      return el.scrollTop;
    },
    busy() {
      const skel = [...document.querySelectorAll('.animate-pulse, [aria-busy="true"], [data-skeleton], .skeleton')]
        .filter((e) => { const r = e.getBoundingClientRect(); return visible(e) && r.width >= 16 && r.height >= 8; }).length;
      const spin = [...document.querySelectorAll('.animate-spin')].filter(visible).length;
      const main = document.querySelector('main') || document.body;
      const t = main ? main.innerText || '' : '';
      const loadingText = /(^|\n)\s*(Loading|Fetching)(…|\.\.\.)?\s*($|\n)/.test(t);
      return { skeletons: skel, spinners: spin, loadingText };
    },
    problems() {
      const main = document.querySelector('main') || document.body;
      const text = clean(main ? main.innerText : '');
      const notFound = /\b(page not found|404 not found)\b/i.test(text) && text.length < 800;
      const errors = [];
      for (const b of main.querySelectorAll('button')) {
        if (!/^(retry|try again|reload)$/i.test(clean(b.innerText))) continue;
        const box = b.closest('div');
        const t = clean((box || b).innerText).replace(/\s*(Retry|Try again|Reload)\s*$/i, '');
        if (t) errors.push(t.slice(0, 160));
      }
      for (const e of main.querySelectorAll('[role="alert"]')) { const t = clean(e.innerText); if (t) errors.push(t.slice(0, 160)); }
      const generic = text.match(/(Something went wrong[^.]*|Failed to fetch|Internal Server Error|Request failed[^.]*|NetworkError[^.]*|Unexpected token[^.]*)/i);
      if (generic) errors.push(generic[0].slice(0, 160));
      const offline = /\bAPI offline\b/.test(clean(document.body ? document.body.innerText : ''));
      return { notFound, errors: [...new Set(errors)].slice(0, 6), offline, textLength: text.length, title: document.title };
    },
    nav() {
      const out = [], seen = new Set();
      let links = [...document.querySelectorAll('nav a[href]')];
      if (!links.length) links = [...document.querySelectorAll('aside a[href], header a[href]')];
      for (const a of links) {
        const href = a.getAttribute('href') || '';
        if (!href.startsWith('/') || href.startsWith('//')) continue;
        const label = clean(a.innerText) || clean(a.getAttribute('title')) || clean(a.getAttribute('aria-label'));
        if (!label) continue;
        const key = label + '|' + href;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ label: label.replace(/\s*[↗→]$/, ''), href, external: a.getAttribute('target') === '_blank' });
      }
      return out;
    },
    tabs(vocab) {
      const cands = [...document.querySelectorAll('[role="tab"], button, a')].filter(visible);
      const groups = new Map();
      for (const e of cands) {
        const p = e.parentElement;
        if (!p) continue;
        if (!groups.has(p)) groups.set(p, []);
        groups.get(p).push(e);
      }
      let best = null, bestScore = 0;
      for (const [, list] of groups) {
        if (list.length < 3) continue;
        const labels = list.map((e) => norm(e.innerText || e.textContent));
        let score = labels.filter((l) => vocab.some((v) => l === v || l.startsWith(v + ' ') || l.startsWith(v))).length;
        score += 2 * list.filter((e) => e.getAttribute('role') === 'tab').length;
        if (score > bestScore) { bestScore = score; best = list; }
      }
      if (!best || bestScore < 3) return [];
      document.querySelectorAll('[data-capture-tab]').forEach((e) => e.removeAttribute('data-capture-tab'));
      return best.map((e, i) => {
        e.setAttribute('data-capture-tab', String(i));
        const selected = e.getAttribute('aria-selected') === 'true' || /border-indigo|border-primary|active|selected/.test(e.className || '');
        return { i, label: clean(e.innerText || e.textContent), norm: norm(e.innerText || e.textContent), selected };
      });
    },
    cards() {
      const el = scrollEl();
      const doc = isDoc(el);
      const baseTop = doc ? 0 : el.getBoundingClientRect().top;
      const st = el.scrollTop;
      let inset = 0;
      if (doc) {
        for (const h of document.querySelectorAll('header, [class*="sticky"], [class*="fixed"]')) {
          const cs = getComputedStyle(h);
          if (cs.position !== 'sticky' && cs.position !== 'fixed') continue;
          const r = h.getBoundingClientRect();
          if (r.top <= 1 && r.height > 20 && r.height < 160 && r.width > innerWidth * 0.4) inset = Math.max(inset, r.bottom);
        }
      }
      const root = document.querySelector('main') || document.body;
      const isCard = (e) => {
        const r = e.getBoundingClientRect();
        if (r.width < 240 || r.height < 90) return false;
        const cs = getComputedStyle(e);
        const bw = parseFloat(cs.borderTopWidth) || 0;
        const br = parseFloat(cs.borderTopLeftRadius) || 0;
        const bg = cs.backgroundColor && cs.backgroundColor !== 'rgba(0, 0, 0, 0)' && cs.backgroundColor !== 'transparent';
        return (bw >= 1 && br >= 4) || (bg && br >= 6 && cs.boxShadow !== 'none');
      };
      const all = [...root.querySelectorAll('*')].filter((e) => visible(e) && isCard(e));
      const top = all.filter((e) => !all.some((o) => o !== e && o.contains(e)));
      const out = [];
      for (const e of top) {
        const r = e.getBoundingClientRect();
        const hd = e.querySelector('h1, h2, h3, h4, [class*="font-semibold"]');
        out.push({ y0: r.top - baseTop + st, y1: r.bottom - baseTop + st, title: hd ? clean(hd.innerText).slice(0, 60) : '' });
      }
      for (const h of root.querySelectorAll('h1, h2, h3')) {
        if (!visible(h) || top.some((c) => c.contains(h))) continue;
        const r = h.getBoundingClientRect();
        out.push({ y0: r.top - baseTop + st, y1: r.bottom - baseTop + st, title: clean(h.innerText).slice(0, 60), heading: true });
      }
      out.sort((a, b) => a.y0 - b.y0);
      return { cards: out, inset, total: pg.contentHeight(), vh: innerHeight };
    },
    mainInputs() {
      const root = document.querySelector('main') || document.body;
      const res = [];
      root.querySelectorAll('input, textarea, select').forEach((e, i) => {
        if (!visible(e) || e.disabled) return;
        const type = (e.getAttribute('type') || e.tagName.toLowerCase()).toLowerCase();
        if (['hidden', 'checkbox', 'radio', 'file', 'range', 'color'].includes(type)) return;
        e.setAttribute('data-capture-input', String(i));
        const options = e.tagName === 'SELECT' ? [...e.options].map((o) => ({ value: o.value, text: clean(o.text) })) : [];
        res.push({ i, tag: e.tagName.toLowerCase(), type, placeholder: e.getAttribute('placeholder') || '', options });
      });
      return res;
    },
  };
  Object.defineProperty(window, '__pg', { value: pg, configurable: true });
})();
"""

# A visible cursor for the demo video (Playwright videos do not show the mouse).
CURSOR_JS = r"""
(() => {
  if (window.__pgCursor) return;
  window.__pgCursor = true;
  let x = -60, y = -60, down = false;
  const install = () => {
    if (!document.body) { requestAnimationFrame(install); return; }
    if (document.getElementById('__pg_cursor')) return;
    const c = document.createElement('div');
    c.id = '__pg_cursor';
    c.setAttribute('aria-hidden', 'true');
    c.style.cssText = 'position:fixed;left:0;top:0;width:22px;height:22px;margin:-11px 0 0 -11px;border-radius:9999px;' +
      'border:2px solid rgba(79,70,229,.95);box-shadow:0 1px 8px rgba(0,0,0,.25);pointer-events:none;' +
      'z-index:2147483647;transition:transform 80ms ease-out,background 120ms;will-change:transform';
    const paint = () => {
      c.style.transform = 'translate(' + x + 'px,' + y + 'px) scale(' + (down ? 0.72 : 1) + ')';
      c.style.background = down ? 'rgba(79,70,229,.55)' : 'rgba(99,102,241,.22)';
    };
    paint();
    document.body.appendChild(c);
    addEventListener('mousemove', (e) => { x = e.clientX; y = e.clientY; paint(); }, true);
    addEventListener('mousedown', () => { down = true; paint(); }, true);
    addEventListener('mouseup', () => { down = false; paint(); }, true);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install); else install();
})();
"""


# Union of the cards with the given titles (+ the page header), for cropped "region" screenshots.
REGION_JS = r"""
([titles, header, pad]) => {
  const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();
  const main = document.querySelector('main') || document.body;
  const vis = (e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
  const nodes = [...main.querySelectorAll('h1, h2, h3, div, span, p, summary')].filter(vis);
  const rects = [], missing = [];
  for (const t of titles) {
    const want = t.toLowerCase();
    const hit = nodes.find((e) => clean(e.textContent).toLowerCase() === want
      && ![...e.children].some((c) => clean(c.textContent).toLowerCase() === want));
    if (!hit) { missing.push(t); continue; }
    const card = hit.closest('.rounded-lg.border');
    let el = card && main.contains(card) ? card : null;
    if (!el) el = hit.tagName === 'H2' || hit.tagName === 'H3' ? hit.parentElement : hit;
    rects.push(el.getBoundingClientRect());
  }
  if (header) {
    const h1 = main.querySelector('h1');
    const blk = h1 && h1.parentElement && h1.parentElement.parentElement;
    if (blk) rects.push(blk.getBoundingClientRect());
  }
  if (!rects.length) return null;
  const x0 = Math.min(...rects.map((r) => r.left)) - pad, y0 = Math.min(...rects.map((r) => r.top)) - pad;
  const x1 = Math.max(...rects.map((r) => r.right)) + pad, y1 = Math.max(...rects.map((r) => r.bottom)) + pad;
  const x = Math.max(0, x0), y = Math.max(0, y0);
  return { x, y, width: Math.min(innerWidth, x1) - x, height: y1 - y, missing };
}
"""


# ============================================================================ helpers
class Api:
    """Tiny JSON client for the backend (stdlib only)."""

    def __init__(self, base: str, api_key: str | None, timeout: float = 25.0):
        self.base = base.rstrip("/")
        self.key = api_key
        self.timeout = timeout

    def get(self, path: str, **params: Any) -> Any:
        q = {k: v for k, v in params.items() if v is not None}
        url = f"{self.base}{path}" + (f"?{urllib.parse.urlencode(q)}" if q else "")
        headers = {"Accept": "application/json", "User-Agent": "phishguard-capture-media"}
        if self.key:
            headers["X-API-Key"] = self.key
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=self.timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def try_get(self, path: str, **params: Any) -> Any:
        try:
            return self.get(path, **params)
        except (urllib.error.URLError, OSError, ValueError) as e:
            log(f"API GET {path} failed: {e}", "warn")
            return None


class NetTracker:
    """In-flight request counter for a page (SPA route changes do not re-trigger Playwright's networkidle)."""

    IGNORE = {"websocket", "eventsource", "media", "manifest", "ping"}
    STALE_S = 60.0  # a request older than this no longer blocks "idle" (hung connections)

    def __init__(self, page: Page):
        self.page = page
        self.inflight: dict[Any, float] = {}
        self.last = time.monotonic()
        self.api_errors: list[tuple[int, str]] = []
        page.on("request", self._req)
        page.on("requestfinished", self._done)
        page.on("requestfailed", self._done)
        page.on("response", self._resp)

    def _req(self, r) -> None:
        if r.resource_type in self.IGNORE:
            return
        self.inflight[r] = time.monotonic()
        self.last = time.monotonic()

    def _done(self, r) -> None:
        self.inflight.pop(r, None)
        self.last = time.monotonic()

    def _resp(self, resp) -> None:
        try:
            if "/api/" in resp.url and resp.status >= 400:
                self.api_errors.append((resp.status, urllib.parse.urlsplit(resp.url).path))
        except PWError:
            pass

    def take_errors(self) -> list[tuple[int, str]]:
        errs, self.api_errors = self.api_errors, []
        return errs

    def busy(self) -> int:
        now = time.monotonic()
        return sum(1 for t in self.inflight.values() if now - t < self.STALE_S)

    def wait_idle(self, idle_ms: int = 500, timeout: float = 15.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if not self.busy() and (time.monotonic() - self.last) * 1000 >= idle_ms:
                return True
            self.page.wait_for_timeout(100)
        return False


def optimise_png(img: Image.Image, max_bytes: int, target_width: int) -> tuple[bytes, int, int, str]:
    """Downscale + palette-quantise until the PNG fits ``max_bytes``. Returns (data, w, h, method)."""
    if img.mode != "RGB":
        img = img.convert("RGB")
    widths: list[int] = []
    for f in (1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.42):
        w = max(320, min(img.width, int(target_width * f)))
        if w not in widths:
            widths.append(w)
    plan: list[tuple[int, str]] = []
    for i, w in enumerate(widths):
        plan += [(w, m) for m in (("rgb", "p256") if i == 0 else ("p256",) if i < 3 else ("p256", "p128"))]
    plan.append((widths[-1], "p64"))
    cache: dict[int, Image.Image] = {}
    best: tuple[bytes, int, int, str] | None = None
    for w, mode in plan:
        im = cache.get(w)
        if im is None:
            im = img if w == img.width else img.resize((w, max(1, round(img.height * w / img.width))),
                                                       Image.Resampling.LANCZOS)
            cache[w] = im
        buf = io.BytesIO()
        if mode == "rgb":
            im.save(buf, "PNG", optimize=True)
        else:
            im.quantize(colors=int(mode[1:]), method=Image.Quantize.MEDIANCUT,
                        dither=Image.Dither.NONE).save(buf, "PNG", optimize=True)
        data = buf.getvalue()
        if best is None or len(data) < len(best[0]):
            best = (data, im.width, im.height, mode)
        if len(data) <= max_bytes:
            return data, im.width, im.height, mode
    assert best is not None
    return best


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def norm_label(s: str) -> str:
    s = re.sub(r"\s+", " ", s or "").strip()
    s = re.sub(r"\s*\(?\d[\d,]*\)?$", "", s)
    return s.strip().lower()


def match_label(items: Iterable[dict], aliases: Iterable[str], key: str = "norm", used: set | None = None) -> dict | None:
    items = [it for it in items if not used or it.get("i") not in used]
    aliases = [a.lower() for a in aliases]
    for a in aliases:  # exact
        for it in items:
            if it.get(key) == a:
                return it
    for a in aliases:  # prefix
        for it in items:
            v = it.get(key) or ""
            if v.startswith(a + " ") or (len(a) >= 4 and v.startswith(a)):
                return it
    return None


# ============================================================================ manifest
@dataclass
class Media:
    file: str
    caption: str
    group: str
    kind: str = "screenshot"
    route: str | None = None
    theme: str = "light"
    viewport: str = "desktop"
    width: int = 0
    height: int = 0
    bytes: int = 0
    method: str | None = None
    warnings: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    base_url: str
    api_url: str
    out: Path
    api_key: str | None
    skip_video: bool
    video_only: bool
    only: tuple[str, ...]
    demo_url: str
    max_height: int
    max_kb: int
    png_width: int
    ffmpeg: str | None
    headed: bool
    scan_timeout: float
    phishing_scan_id: int | None
    legit_scan_id: int | None
    readme: Path | None
    readme_media_path: str | None
    gallery_only: bool
    keep_raw: bool
    all_tabs: bool
    verbose: bool
    show_demo_banner: bool = False
    readme_metrics: bool = False
    display_origin: str | None = None  # origin printed in page text (e.g. the API guide) instead of --base-url's
    extras_only: bool = False   # only the interactive / region shots (capture_extras)
    curate: bool = False        # no capture: rename shots to the numbered README set + write screenshots.json


# ============================================================================ capture
class Capture:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.api = Api(cfg.api_url, cfg.api_key)
        self.out = cfg.out
        self.items: list[Media] = []
        self.failed: list[dict[str, str]] = []
        self.skipped: list[dict[str, str]] = []
        self.notes: list[str] = []
        self.nav: list[dict] = []
        self.health: dict | None = None
        self.phish: dict | None = None
        self.legit: dict | None = None
        self.video_info: dict[str, Any] = {}
        self.tmp: Path | None = None

    # ------------------------------------------------------------ bookkeeping
    def want(self, name: str) -> bool:
        return not self.cfg.only or any(name.startswith(o) or o.startswith(name) for o in self.cfg.only)

    def fail(self, name: str, reason: str) -> None:
        self.failed.append({"name": name, "reason": reason})
        log(f"{name}: {reason}", "warn")

    def skip(self, name: str, reason: str) -> None:
        """An optional (v2) page or tab that this build does not have."""
        self.skipped.append({"name": name, "reason": reason})
        log(f"{name}: skipped, {reason}")

    def url(self, path: str) -> str:
        return path if path.startswith("http") else self.cfg.base_url + (path if path.startswith("/") else "/" + path)

    def attempt(self, name: str, fn: Callable[[], Any]) -> Any:
        if not self.want(name):
            return None
        try:
            return fn()
        except Exception as e:  # keep going: one broken page must not stop the run
            self.fail(name, f"{type(e).__name__}: {str(e).splitlines()[0][:200] if str(e) else ''}")
            if self.cfg.verbose:
                traceback.print_exc()
            return None

    # ------------------------------------------------------------ browser plumbing
    def new_context(self, browser: Browser, *, theme: str = "light", width: int = 1440, height: int = 900,
                    dsf: float = 2, mobile: bool = False, video_dir: Path | None = None,
                    motion: str = "reduce", cursor: bool = False) -> BrowserContext:
        kw: dict[str, Any] = dict(viewport={"width": width, "height": height}, device_scale_factor=dsf,
                                  color_scheme=theme, reduced_motion=motion, locale="en-US",
                                  ignore_https_errors=False)
        if mobile:
            kw.update(is_mobile=True, has_touch=True, user_agent=MOBILE_UA)
        if video_dir is not None:
            kw.update(record_video_dir=str(video_dir), record_video_size={"width": width, "height": height})
        ctx = browser.new_context(**kw)
        ctx.set_default_timeout(30_000)
        ctx.add_init_script(HELPERS_JS)
        ctx.add_init_script(f"try {{ localStorage.setItem('pg-theme', '{theme}'); }} catch (e) {{}}")
        if not self.cfg.show_demo_banner:  # the hosted demo shows a dismissible "Demo mode" banner
            ctx.add_init_script("try { localStorage.setItem('pg-demo-banner', 'dismissed'); } catch (e) {}")
        if cursor:
            ctx.add_init_script(CURSOR_JS)
        if self.cfg.api_key:
            key = self.cfg.api_key

            def add_key(route, request):
                route.continue_(headers={**request.headers, "x-api-key": key})
            ctx.route(re.compile(r".*/api/.*"), add_key)
        return ctx

    def settle(self, page: Page, tr: NetTracker, timeout: float = 25.0, after_ms: int = 450,
               spinner_s: float = 8.0) -> None:
        """Wait for network idle, web fonts, and for skeletons/spinners to disappear."""
        end = time.monotonic() + timeout
        tr.wait_idle(500, max(1.0, end - time.monotonic()))
        try:
            page.evaluate("document.fonts ? document.fonts.ready.then(() => true) : true")
        except PWError:
            pass
        start, stable = time.monotonic(), 0
        b: dict = {}
        while time.monotonic() < end:
            try:
                b = page.evaluate("window.__pg ? window.__pg.busy() : {skeletons: 0, spinners: 0, loadingText: false}")
            except PWError:
                b = {"skeletons": 0, "spinners": 0, "loadingText": False}
            spin_block = b.get("spinners") and time.monotonic() - start < spinner_s
            if not b.get("skeletons") and not b.get("loadingText") and not spin_block and not tr.busy():
                stable += 1
                if stable >= 2:
                    break
            else:
                stable = 0
            page.wait_for_timeout(250)
        else:
            log(f"  page still busy after {timeout:.0f}s ({b}); capturing anyway", "warn")
        tr.wait_idle(400, max(0.5, min(6.0, end - time.monotonic())))
        page.wait_for_timeout(after_ms)

    def goto(self, page: Page, tr: NetTracker, path: str, timeout: float = 30.0, spinner_s: float = 8.0) -> dict:
        resp = page.goto(self.url(path), wait_until="domcontentloaded", timeout=45_000)
        ctype = (resp.headers.get("content-type") or "") if resp else "text/html"
        if resp is not None and (resp.status >= 400 or "text/html" not in ctype):
            # e.g. a dev-server proxy prefix ("/api") swallowing "/api-guide", or a host without SPA rewrites:
            # load the app shell and switch route inside the SPA instead.
            note = (f"{path}: direct load returned HTTP {resp.status} {ctype.split(';')[0] or '?'}; "
                    f"captured via in-app navigation")
            if note not in self.notes:
                self.notes.append(note)
                log(f"  {note}", "warn")
            page.goto(self.url("/"), wait_until="domcontentloaded", timeout=45_000)
            self.settle(page, tr, timeout=20)
            page.evaluate("(p) => { history.pushState({}, '', p); "
                          "dispatchEvent(new PopStateEvent('popstate', { state: history.state })); }", path)
            page.wait_for_timeout(300)
        self.settle(page, tr, timeout=timeout, spinner_s=spinner_s)
        return self.problems(page)

    @staticmethod
    def problems(page: Page) -> dict:
        try:
            return page.evaluate("window.__pg ? window.__pg.problems() : {}") or {}
        except PWError:
            return {}

    def warnings_for(self, page: Page, tr: NetTracker) -> list[str]:
        p = self.problems(page)
        w = [f"error state: {e}" for e in p.get("errors") or []]
        if p.get("offline"):
            w.append("UI reports 'API offline'")
        if (p.get("textLength") or 0) < 30:
            w.append("page looks blank")
        for status, path in tr.take_errors():
            w.append(f"API {status} {path}")
        return list(dict.fromkeys(w))[:8]

    @staticmethod
    def neutral_mouse(page: Page) -> None:
        try:
            page.mouse.move(1, 1)
        except PWError:
            pass

    def discover_nav(self, page: Page) -> None:
        try:
            self.nav = page.evaluate("window.__pg.nav()") or []
        except PWError:
            self.nav = []
        labels = ", ".join(n["label"] for n in self.nav)
        log(f"sidebar links: {labels or '(none found)'}")

    def route_for(self, spec: PageSpec) -> tuple[str, bool]:
        items = [{"norm": norm_label(n["label"]), **n} for n in self.nav if not n.get("external")]
        hit = match_label(items, [norm_label(x) for x in spec.labels])
        if hit:
            return hit["href"], True
        return spec.paths[0], False

    # ------------------------------------------------------------ screenshots
    def save(self, raw: bytes, name: str, caption: str, group: str, *, route: str | None, theme: str = "light",
             viewport: str = "desktop", target_width: int | None = None, warnings: list[str] | None = None,
             extra: dict | None = None, crop_px: int | None = None) -> Media:
        img = Image.open(io.BytesIO(raw))
        img.load()
        if crop_px and img.height > crop_px:  # cut empty space below the meaningful content
            img = img.crop((0, 0, img.width, crop_px))
        data, w, h, method = optimise_png(img, self.cfg.max_kb * 1024, target_width or self.cfg.png_width)
        dest = self.out / f"{name}.png"
        dest.write_bytes(data)
        m = Media(file=dest.name, caption=caption, group=group, route=route, theme=theme, viewport=viewport,
                  width=w, height=h, bytes=len(data), method=method, warnings=warnings or [], extra=extra or {})
        self.items = [x for x in self.items if x.file != m.file] + [m]
        note = f" [{'; '.join(m.warnings)}]" if m.warnings else ""
        log(f"{dest.name:34s} {w}x{h} {human(len(data)):>9s} ({method}){note}", "ok" if not m.warnings else "warn")
        return m

    def show_display_origin(self, page: Page) -> None:
        """Captures run on spare ports; print the app's normal origin (--display-origin) in visible page text."""
        u = urllib.parse.urlsplit(self.cfg.base_url)
        here, there = f"{u.scheme}://{u.netloc}", (self.cfg.display_origin or "").rstrip("/")
        if not there or there == here:
            return
        try:
            page.evaluate("""([a, b]) => { const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
                for (let n = w.nextNode(); n; n = w.nextNode()) if (n.nodeValue.includes(a)) n.nodeValue = n.nodeValue.split(a).join(b); }""",
                          [here, there])
        except PWError:
            pass

    def shoot(self, page: Page, tr: NetTracker, name: str, caption: str, group: str, *, route: str | None,
              full: bool = True, theme: str = "light", viewport: str = "desktop", target_width: int | None = None,
              extra: dict | None = None, crop_h: int | None = None, max_height: int | None = None,
              settle_after: bool = True, mouse: bool = True) -> Media:
        """Screenshot the page (full content height up to ``max_height`` CSS px, or just the viewport).
        ``crop_h`` cuts the result at that many CSS px from the top (drops empty space below short pages)."""
        vp = page.viewport_size or {"width": 1440, "height": 900}
        warnings = self.warnings_for(page, tr)
        if mouse:
            self.neutral_mouse(page)
        page.evaluate("window.__pg && window.__pg.scrollTo(0)")
        resized = False
        if full:
            try:
                h = int(page.evaluate("window.__pg.contentHeight()"))
            except PWError:
                h = vp["height"]
            h = max(vp["height"], min(h, max_height or self.cfg.max_height))
            if h > vp["height"] + 8:
                page.set_viewport_size({"width": vp["width"], "height": h})
                resized = True
                page.wait_for_timeout(350)
                if settle_after:
                    self.settle(page, tr, timeout=10, after_ms=350)
        self.show_display_origin(page)
        try:
            raw = page.screenshot(type="png", animations="disabled", caret="hide", timeout=60_000)
        finally:
            if resized:
                page.set_viewport_size(vp)
                page.wait_for_timeout(150)
        dsf = self.dsf_of(page)
        return self.save(raw, name, caption, group, route=route, theme=theme, viewport=viewport,
                         target_width=target_width, warnings=warnings, extra=extra,
                         crop_px=int(crop_h * dsf) if crop_h else None)

    @staticmethod
    def dsf_of(page: Page) -> float:
        try:
            return float(page.evaluate("window.devicePixelRatio") or 1)
        except PWError:
            return 1.0

    def shoot_region(self, page: Page, tr: NetTracker, name: str, caption: str, group: str, *, route: str | None,
                     titles: Iterable[str], header: bool = False, pad: int = 12, theme: str = "light",
                     extra: dict | None = None) -> Media | None:
        """Screenshot only the cards whose titles are given (plus the page header), cropped to their union.

        The viewport is stretched to the full content height first, so every card is laid out and painted."""
        vp = page.viewport_size or {"width": 1440, "height": 900}
        warnings = self.warnings_for(page, tr)
        self.neutral_mouse(page)
        page.evaluate("window.__pg && window.__pg.scrollTo(0)")
        try:
            h = int(page.evaluate("window.__pg.contentHeight()"))
        except PWError:
            h = vp["height"]
        h = max(vp["height"], min(h, 9000))
        page.set_viewport_size({"width": vp["width"], "height": h})
        try:
            page.wait_for_timeout(400)
            self.settle(page, tr, timeout=12, after_ms=400)
            box = page.evaluate(REGION_JS, [list(titles), header, pad])
            if not box or box.get("width", 0) < 40 or box.get("height", 0) < 40:
                self.fail(name, f"none of the cards {list(titles)} found")
                return None
            if box.get("missing"):
                warnings.append(f"cards not found: {', '.join(box['missing'])}")
            clip = {k: float(box[k]) for k in ("x", "y", "width", "height")}
            self.show_display_origin(page)
            raw = page.screenshot(type="png", animations="disabled", caret="hide", clip=clip, timeout=60_000)
        finally:
            page.set_viewport_size(vp)
            page.wait_for_timeout(150)
        return self.save(raw, name, caption, group, route=route, theme=theme, warnings=warnings,
                         extra={**(extra or {}), "cards": list(titles)})

    def shoot_sections(self, page: Page, tr: NetTracker, name: str, caption: str, group: str, *, route: str,
                       max_sections: int, theme: str = "light") -> list[Media]:
        page.evaluate("window.__pg.scrollTo(0)")
        page.wait_for_timeout(150)
        info = page.evaluate("window.__pg.cards()")
        offsets = section_offsets(info, max_sections)
        warnings = self.warnings_for(page, tr)
        self.neutral_mouse(page)
        out: list[Media] = []
        n = len(offsets)
        for k, off in enumerate(offsets, start=1):
            page.evaluate(f"window.__pg.scrollTo({int(off)})")
            page.wait_for_timeout(300)
            self.settle(page, tr, timeout=10, after_ms=300)
            titles = [c["title"] for c in info["cards"]
                      if c.get("title") and off + info["inset"] - 4 <= c["y0"] < off + info["vh"] - 60]
            # card titles only: drop KPI numbers ("71", "51.8%") and the page heading itself
            titles = [t.rstrip(": ") for t in titles
                      if not re.fullmatch(r"[\d\s.,%/+\-]+", t) and norm_label(t) != norm_label(caption)]
            titles = list(dict.fromkeys(titles))[:5]
            cap = f"{caption} ({k}/{n})" + (f": {', '.join(titles)}" if titles else "")
            raw = page.screenshot(type="png", animations="disabled", caret="hide")
            out.append(self.save(raw, f"{name}-{k}", cap, group, route=route, theme=theme,
                                 warnings=warnings if k == 1 else [], extra={"scroll_y": int(off)}))
        page.evaluate("window.__pg.scrollTo(0)")
        return out

    # ------------------------------------------------------------ targets
    def pick_targets(self) -> None:
        self.health = self.api.try_get("/api/health")
        if self.health:
            log(f"API health: {self.health.get('status')} | model {self.health.get('model_version')} | "
                f"feeds {self.health.get('feeds_entries')}")
        if self.cfg.phishing_scan_id:
            self.phish = self.api.try_get(f"/api/scans/{self.cfg.phishing_scan_id}")
        else:
            self.phish = self.pick_phishing()
        if self.phish:
            log(f"phishing report: #{self.phish['id']} {self.phish.get('domain')} risk {self.phish.get('risk_score')} "
                f"({self.phish.get('verdict')})")
        else:
            log("no scans found for the phishing report", "warn")
        if self.cfg.legit_scan_id:
            self.legit = self.api.try_get(f"/api/scans/{self.cfg.legit_scan_id}")
        else:
            self.legit = self.pick_legit()
        if self.legit:
            log(f"legitimate report: #{self.legit['id']} {self.legit.get('domain')} risk {self.legit.get('risk_score')}")

    def pick_phishing(self) -> dict | None:
        """The highest-risk scan (GET /api/scans?sort=risk_score&order=desc&page_size=1). If it is a lexical-only
        scan (no live page data for the Content / Resources / Source tabs), the highest-risk deep scan among the
        top 25 is used instead, so those tabs do not show empty states."""
        top = self.api.try_get("/api/scans", sort="risk_score", order="desc", page_size=1)
        items = (top or {}).get("items") or []
        if not items:
            return None
        first = items[0]

        def deep(s: dict) -> bool:
            full = self.api.try_get(f"/api/scans/{s['id']}") or {}
            http = full.get("http") or {}
            return bool(http.get("reachable")) and full.get("tested_depth", "full") != "lexical" and (
                full.get("has_dom") is not False)
        if deep(first):
            return first
        more = self.api.try_get("/api/scans", sort="risk_score", order="desc", page_size=25)
        for s in ((more or {}).get("items") or [])[1:]:
            if s.get("verdict") == "phishing" and deep(s):
                log(f"highest-risk scan #{first['id']} has no live page data; using #{s['id']} for the report shots")
                return s
        return first

    def pick_legit(self) -> dict | None:
        res = self.api.try_get("/api/scans", verdict="legitimate", sort="risk_score", order="asc", page_size=40)
        items = (res or {}).get("items") or []
        if not items:
            return None
        prefer = ("google.com", "github.com", "wikipedia.org", "microsoft.com", "apple.com", "amazon.com",
                  "anthropic.com", "python.org")

        def rank(it: dict) -> tuple:
            d = (it.get("domain") or "").removeprefix("www.")
            return (0 if d in prefer else 1, prefer.index(d) if d in prefer else 99, it.get("risk_score") or 0)
        for it in sorted(items, key=rank)[:8]:
            full = self.api.try_get(f"/api/scans/{it['id']}") or {}
            http = full.get("http") or {}
            if http.get("reachable") and full.get("tested_depth", "full") != "lexical":
                return it
        return sorted(items, key=rank)[0]

    # ------------------------------------------------------------ desktop pages
    def capture_desktop(self, browser: Browser) -> None:
        log("desktop / light screenshots (1440x900 @2x)", "step")
        ctx = self.new_context(browser, theme="light")
        page = ctx.new_page()
        tr = NetTracker(page)
        try:
            p = self.goto(page, tr, "/")
            if p.get("offline"):
                log("the UI says the API is offline: screenshots will show error states", "warn")
            self.discover_nav(page)
            by_name = {s.name: s for s in PAGES}

            self.attempt("overview", lambda: self.capture_page(page, tr, by_name["overview"], already_open=True))
            self.attempt("scan", lambda: self.capture_scan_page(page, tr, by_name["scan"]))
            if self.phish:
                self.attempt("report-phishing", lambda: self.capture_report(
                    page, tr, self.phish, "report-phishing", [t[0] for t in REPORT_TABS]))
            else:
                self.fail("report-phishing", "no scans in the database")
            if self.legit:
                self.attempt("report-legit", lambda: self.capture_report(page, tr, self.legit, "report-legit",
                                                                         list(LEGIT_TABS)))
            else:
                self.fail("report-legit", "no legitimate scan in the database")
            self.attempt("history", lambda: self.capture_page(page, tr, by_name["history"]))
            self.attempt("bulk", lambda: self.capture_bulk(page, tr, by_name["bulk"]))
            for name in ("analytics", "model-lab", "watchlist"):
                self.attempt(name, lambda s=by_name[name]: self.capture_page(page, tr, s))
            self.attempt("typosquat", lambda: self.capture_typosquat(page, tr, by_name["typosquat"]))
            self.attempt("community", lambda: self.capture_community(page, tr, by_name["community"]))
            for name in ("feeds", "alerts", "activity", "settings", "graph", "api-guide"):
                self.attempt(name, lambda s=by_name[name]: self.capture_page(page, tr, s))
            if self.phish:
                self.attempt("domain", lambda: self.capture_domain(page, tr))
            self.attempt("api-docs", lambda: self.capture_swagger(page, tr))
        finally:
            ctx.close()

    def capture_page(self, page: Page, tr: NetTracker, spec: PageSpec, already_open: bool = False) -> None:
        route, in_nav = self.route_for(spec)
        if not already_open:
            p = self.goto(page, tr, route, timeout=40)
            if p.get("notFound"):
                why = "not in the sidebar and the route shows 'Page not found'" if not in_nav else "Page not found"
                (self.skip if spec.v2 else self.fail)(spec.name, f"{route}: {why}")
                return
        if spec.mode == "sections":
            self.shoot_sections(page, tr, spec.name, spec.caption, spec.group, route=route,
                                max_sections=spec.sections)
        else:
            crop = self.content_crop(page) if spec.auto_crop else spec.crop_h
            self.shoot(page, tr, spec.name, spec.caption, spec.group, route=route, crop_h=crop)

    def content_crop(self, page: Page, min_h: int = 640, pad: int = 28) -> int | None:
        """CSS height just below the page content (at least ``min_h``, so the sidebar menu stays whole)."""
        try:
            bottom = page.evaluate("(() => { const m = document.querySelector('main');"
                                   " const c = m && m.firstElementChild; if (!c) return 0;"
                                   " return c.getBoundingClientRect().bottom + (window.__pg ? window.__pg.scrollTop() : 0); })()")
        except PWError:
            return None
        return max(min_h, int(bottom) + pad) if bottom else None

    def capture_scan_page(self, page: Page, tr: NetTracker, spec: PageSpec) -> None:
        route, _ = self.route_for(spec)
        p = self.goto(page, tr, route)
        if p.get("notFound"):
            self.fail(spec.name, f"{route}: Page not found")
            return
        inp = self.find_url_input(page)
        if inp is not None:
            inp.fill(self.cfg.demo_url)
            page.wait_for_timeout(200)
        self.shoot(page, tr, spec.name, spec.caption, spec.group, route=route, crop_h=self.content_crop(page))

    def capture_bulk(self, page: Page, tr: NetTracker, spec: PageSpec) -> None:
        route, _ = self.route_for(spec)
        p = self.goto(page, tr, route)
        if p.get("notFound"):
            self.fail(spec.name, f"{route}: Page not found")
            return
        try:  # paste a few sample URLs (not submitted) so the form shows its de-duplicated URL count
            ta = page.locator("main textarea").first
            if ta.count():
                ta.fill("\n".join(BULK_SAMPLE))
                page.wait_for_timeout(250)
        except PWError:
            pass
        self.shoot(page, tr, spec.name, spec.caption, spec.group, route=route, crop_h=self.content_crop(page))
        jobs = self.api.try_get("/api/bulk")
        jobs = jobs.get("items") if isinstance(jobs, dict) else jobs
        if not jobs:
            return
        job = sorted(jobs, key=lambda j: (j.get("status") != "completed", -(j.get("total") or 0)))[0]
        route = f"{self.route_for(spec)[0].rstrip('/')}/{job['id']}"
        p = self.goto(page, tr, route)
        if p.get("notFound"):
            self.fail("bulk-job", f"{route}: Page not found")
            return
        self.shoot(page, tr, "bulk-job", f"Bulk job detail: per-URL verdicts and risk for '{job.get('name')}'",
                   "Scanning", route=route)

    def capture_typosquat(self, page: Page, tr: NetTracker, spec: PageSpec) -> None:
        route, _ = self.route_for(spec)
        p = self.goto(page, tr, f"{route}?domain={TYPOSQUAT_DOMAIN}", timeout=90, spinner_s=80)
        if p.get("notFound"):
            self.fail(spec.name, f"{route}: Page not found")
            return
        if not self.has_results(page):
            inp = self.find_input(page, lambda i: "domain" in i["placeholder"].lower()
                                  or i["type"] in ("input", "text", "search"))
            if inp is not None:
                inp.fill(TYPOSQUAT_DOMAIN)
                inp.press("Enter")
                page.wait_for_timeout(500)
                self.settle(page, tr, timeout=90, spinner_s=80)
        if not self.has_results(page):
            log("  typosquat: no result rows detected", "warn")
        self.shoot(page, tr, spec.name, spec.caption, spec.group, route=f"{route}?domain={TYPOSQUAT_DOMAIN}")

    def capture_domain(self, page: Page, tr: NetTracker) -> None:
        dom = self.phish.get("domain") if self.phish else None
        if not dom:
            return
        route = f"/domains/{urllib.parse.quote(dom)}"
        p = self.goto(page, tr, route)
        if p.get("notFound"):
            self.fail("domain", f"{route}: Page not found")
            return
        self.shoot(page, tr, "domain", f"Domain intelligence for {dom}: every scan, risk trend and latest result",
                   "Threat intelligence", route=route)

    def capture_swagger(self, page: Page, tr: NetTracker) -> None:
        page.goto(self.url("/docs"), wait_until="domcontentloaded", timeout=45_000)
        try:
            page.wait_for_selector(".swagger-ui .opblock, .swagger-ui .opblock-tag", timeout=20_000)
        except PWError:
            self.fail("api-docs", "/docs did not render Swagger UI (not routed on this deployment?)")
            return
        self.settle(page, tr, timeout=15)
        self.shoot(page, tr, "api-docs", "Interactive OpenAPI (Swagger) documentation served by FastAPI at /docs",
                   "Developer API", route="/docs", crop_h=1310)

    # ------------------------------------------------------------ report
    @staticmethod
    def report_caption(scan: dict, tab_caption: str) -> str:
        return (f"{tab_caption} ({scan.get('domain')}, risk {scan.get('risk_score')}/100, "
                f"{scan.get('verdict')})")

    def find_tabs(self, page: Page) -> list[dict]:
        try:
            return page.evaluate("(v) => window.__pg.tabs(v)", list(TAB_VOCAB)) or []
        except PWError:
            return []

    def capture_report(self, page: Page, tr: NetTracker, scan: dict, prefix: str, keys: list[str]) -> None:
        route = f"/scans/{scan['id']}"
        p = self.goto(page, tr, route, timeout=40)
        if p.get("notFound"):
            self.fail(prefix, f"{route}: Page not found")
            return
        tabs = self.find_tabs(page)
        if not tabs:
            log(f"  {prefix}: no tab bar detected, capturing the page as it is", "warn")
            self.shoot(page, tr, f"{prefix}-summary", self.report_caption(scan, "Scan report"), "Scan report",
                       route=route)
            return
        log(f"  report tabs: {', '.join(t['label'] for t in tabs)}")
        specs = {k: (a, c, opt) for k, a, c, opt in REPORT_TABS}
        wanted = list(keys)
        if self.cfg.all_tabs and prefix == "report-phishing":
            wanted += [re.sub(r"[^a-z0-9]+", "-", t["norm"]).strip("-") for t in tabs
                       if not any(match_label([t], specs[k][0]) for k in specs)]
        used: set[int] = set()
        for key in wanted:
            aliases, cap, optional = specs.get(
                key, ((key.replace("-", " "),), f"{key.replace('-', ' ').title()} tab", True))
            tabs = self.find_tabs(page)
            t = match_label(tabs, aliases, used=used)
            if not t:
                (self.skip if optional else self.fail)(f"{prefix}-{key}", "tab not present on this build")
                continue
            used.add(t["i"])
            page.locator(f'[data-capture-tab="{t["i"]}"]').first.click()
            page.wait_for_timeout(250)
            self.settle(page, tr, timeout=30)
            empty = self.empty_states(page) if key in DEEP_TABS | {"timeline"} else []
            m = self.shoot(page, tr, f"{prefix}-{key}", self.report_caption(scan, cap), "Scan report",
                           route=f"{route}#{key}", extra={"scan_id": scan["id"], "tab": t["label"]})
            if empty:
                m.warnings.append(f"empty state: {'; '.join(empty)}")
                log(f"  {m.file} shows an empty state ({'; '.join(empty)})", "warn")
        if prefix == "report-phishing" and "brand" in wanted and not (scan.get("brand") or {}).get("impersonated_brand"):
            alt = self.pick_branded(exclude=scan.get("id"))
            if alt:
                route = f"/scans/{alt['id']}"
                self.goto(page, tr, route, timeout=40)
                t = match_label(self.find_tabs(page), specs["brand"][0])
                if t:
                    page.locator(f'[data-capture-tab="{t["i"]}"]').first.click()
                    page.wait_for_timeout(250)
                    self.settle(page, tr, timeout=30)
                    self.items = [x for x in self.items if x.file != f"{prefix}-brand.png"]
                    self.shoot(page, tr, f"{prefix}-brand", self.report_caption(alt, specs["brand"][1]),
                               "Scan report", route=f"{route}#brand", extra={"scan_id": alt["id"], "tab": t["label"]})

    def pick_branded(self, exclude: Any = None) -> dict | None:
        """Highest-risk phishing scan that impersonates a brand (for the Brand tab shot)."""
        res = self.api.try_get("/api/scans", verdict="phishing", sort="risk_score", order="desc", page_size=50) or {}
        for it in res.get("items", []):
            if it.get("brand") and it.get("id") != exclude:
                full = self.api.try_get(f"/api/scans/{it['id']}") or {}
                if (full.get("brand") or {}).get("impersonated_brand"):
                    return full
        return None

    @staticmethod
    def empty_states(page: Page) -> list[str]:
        """Texts of visible 'no data' placeholders below the tab bar (tabs that need a deep scan)."""
        try:
            return page.evaluate(r"""() => {
              const bar = document.querySelector('[data-capture-tab]');
              const top = bar ? bar.getBoundingClientRect().bottom : 0;
              const out = [];
              for (const e of document.querySelectorAll('main .text-center, main [class*="empty"]')) {
                const r = e.getBoundingClientRect();
                if (r.top < top || r.width < 1 || r.height < 1) continue;
                const t = (e.innerText || '').replace(/\s+/g, ' ').trim();
                if (/^No (content analysis|resources recorded|page source|relationships|events recorded|data)/i.test(t)
                    && t.length < 240) out.push(t.slice(0, 90));
              }
              return [...new Set(out)].slice(0, 3);
            }""") or []
        except PWError:
            return []

    # ------------------------------------------------------------ dark + mobile
    def capture_dark(self, browser: Browser) -> None:
        log("dark-mode screenshots", "step")
        ctx = self.new_context(browser, theme="dark")
        page = ctx.new_page()
        tr = NetTracker(page)
        try:
            self.goto(page, tr, "/")
            if not self.nav:
                self.discover_nav(page)
            self.attempt("dark-overview", lambda: self.shoot(
                page, tr, "dark-overview", "Overview dashboard in dark mode", "Dark mode", route="/", full=False,
                theme="dark"))
            if self.phish:
                def report() -> None:
                    route = f"/scans/{self.phish['id']}"
                    self.goto(page, tr, route)
                    self.shoot(page, tr, "dark-report", self.report_caption(self.phish, "Scan report in dark mode"),
                               "Dark mode", route=route, full=False, theme="dark")
                self.attempt("dark-report", report)

            def analytics() -> None:
                route, _ = self.route_for(next(s for s in PAGES if s.name == "analytics"))
                self.goto(page, tr, route)
                self.shoot(page, tr, "dark-analytics", "Analytics in dark mode", "Dark mode", route=route,
                           full=False, theme="dark")
            self.attempt("dark-analytics", analytics)
        finally:
            ctx.close()

    def capture_mobile(self, browser: Browser) -> None:
        log("mobile screenshots (390x844 @2x)", "step")
        ctx = self.new_context(browser, theme="light", width=390, height=844, dsf=2, mobile=True)
        page = ctx.new_page()
        tr = NetTracker(page)
        try:
            def overview() -> None:
                self.goto(page, tr, "/")
                self.shoot(page, tr, "mobile-overview", "Overview on a phone (390x844)", "Mobile", route="/",
                           full=False, viewport="mobile", target_width=780)
            self.attempt("mobile-overview", overview)
            if self.phish:
                def report() -> None:
                    route = f"/scans/{self.phish['id']}"
                    self.goto(page, tr, route)
                    self.shoot(page, tr, "mobile-report", self.report_caption(self.phish, "Scan report on a phone"),
                               "Mobile", route=route, full=False, viewport="mobile", target_width=780)
                self.attempt("mobile-report", report)
        finally:
            ctx.close()

    # ------------------------------------------------------------ interactive + region shots
    def capture_community(self, page: Page, tr: NetTracker, spec: PageSpec) -> None:
        """Community page with the submit form filled in (not submitted) above the report tabs."""
        route, _ = self.route_for(spec)
        p = self.goto(page, tr, route)
        if p.get("notFound"):
            self.fail(spec.name, f"{route}: Page not found")
            return
        for sel, value in (('main input[placeholder^="https://"]', COMMUNITY_SAMPLE["url"]),
                           ('main input[placeholder="PayPal"]', COMMUNITY_SAMPLE["brand"]),
                           ("main textarea", COMMUNITY_SAMPLE["comment"])):
            try:
                loc = page.locator(sel).first
                if loc.count():
                    loc.fill(value)
            except PWError:
                pass
        page.wait_for_timeout(200)
        self.shoot(page, tr, spec.name, spec.caption, spec.group, route=route, crop_h=self.content_crop(page))

    def capture_extras(self, browser: Browser) -> None:
        """Views that need interaction (scan tabs, live progress, pivots, graph selection, watch history)
        and cropped regions of the long Analytics / Model Lab pages."""
        log("interactive + region screenshots (1440x900 @2x)", "step")
        ctx = self.new_context(browser, theme="light")
        page = ctx.new_page()
        tr = NetTracker(page)
        try:
            self.goto(page, tr, "/")
            if not self.nav:
                self.discover_nav(page)
            self.attempt("scan-text", lambda: self.capture_scan_text(page, tr))
            self.attempt("scan-qr", lambda: self.capture_scan_qr(page, tr))
            self.attempt("scan-progress", lambda: self.capture_scan_progress(page, tr))
            self.attempt("history-pivot", lambda: self.capture_history_pivot(page, tr))
            self.attempt("graph-node", lambda: self.capture_graph_node(page, tr))
            self.attempt("watchlist-history", lambda: self.capture_watch_history(page, tr))
            for route, specs in (("/analytics", ANALYTICS_REGIONS), ("/model", MODEL_REGIONS)):
                if not any(self.want(s[0]) for s in specs):
                    continue
                self.goto(page, tr, route, timeout=40)
                for name, titles, header, caption, group in specs:
                    self.attempt(name, lambda n=name, t=titles, h=header, c=caption, g=group: self.shoot_region(
                        page, tr, n, c, g, route=route, titles=t, header=h))
        finally:
            ctx.close()

    def open_scan_tab(self, page: Page, tr: NetTracker, label: str) -> None:
        self.goto(page, tr, "/scan")
        page.locator("main button", has_text=label).first.click()
        page.wait_for_timeout(300)

    def capture_scan_text(self, page: Page, tr: NetTracker) -> None:
        self.open_scan_tab(page, tr, "Email / SMS text")
        page.locator("main textarea").first.fill(SAMPLE_EMAIL)
        page.get_by_role("button", name=re.compile(r"Extract URLs", re.I)).click()
        page.locator("main", has_text=re.compile(r"\d+ URL\(s\) found")).first.wait_for(timeout=20_000)
        self.settle(page, tr, timeout=10)
        self.shoot(page, tr, "scan-text", "Email / SMS text: paste a message and PhishGuard extracts (and re-fangs) "
                   "every URL in it", "Scanning", route="/scan#text", crop_h=self.content_crop(page))

    def capture_scan_qr(self, page: Page, tr: NetTracker) -> None:
        assert self.tmp is not None
        qr = self.tmp / "quishing-qr.png"
        qr.write_bytes(base64.b64decode(QR_PNG_B64))
        self.open_scan_tab(page, tr, "QR code")
        page.locator('main input[type="file"]').first.set_input_files(str(qr))
        page.locator("main", has_text="Decoded content").first.wait_for(timeout=15_000)
        page.wait_for_timeout(400)
        self.shoot(page, tr, "scan-qr", "QR code (quishing): the image is decoded locally in the browser and the "
                   "embedded URL can be scanned", "Scanning", route="/scan#qr", crop_h=self.content_crop(page))

    def capture_scan_progress(self, page: Page, tr: NetTracker) -> None:
        """Deep scan through the UI. The POST /api/scan request is held for a few seconds so the live
        analysis-pipeline card can be captured mid-way (the scan itself is real and is stored)."""
        self.goto(page, tr, "/scan")
        inp = self.find_url_input(page)
        if inp is None:
            raise RuntimeError("no URL input on the scan page")
        inp.fill(PROGRESS_URL)
        held: list = []
        pat = re.compile(r".*/api/scan(\?.*)?$")

        def hold(route, request) -> None:
            if request.method == "POST":
                held.append(route)
            else:
                route.continue_()
        page.route(pat, hold)
        try:
            page.locator('main form button[type="submit"]').first.click()
            page.wait_for_timeout(4700)  # the pipeline card advances one step every 0.9 s on a deep scan
            self.shoot(page, tr, "scan-progress", "Scan in progress: the analysis pipeline steps (lexical, ML, DNS, "
                       "WHOIS, SSL, HTTP, brand, reputation) while a deep scan runs", "Scanning", route="/scan",
                       full=False, crop_h=self.content_crop(page), settle_after=False, mouse=False)
        finally:
            for r in held:
                try:
                    r.continue_()
                except PWError:
                    pass
            page.unroute(pat)
        # let the held scan finish and open its report, so the run leaves no request in flight
        page.wait_for_url(re.compile(r".*/scans/\d+.*"), timeout=int(self.cfg.scan_timeout * 1000))
        self.settle(page, tr, timeout=30)
        # (no Screenshot-tab shot: image.thum.io answers "Image not authorized" without a paid account)

    def capture_history_pivot(self, page: Page, tr: NetTracker) -> None:
        route = "/history?" + urllib.parse.urlencode(HISTORY_PIVOT)
        self.goto(page, tr, route)
        self.shoot(page, tr, "history-pivot", "History with pivot filters (threat type, trust tier) as removable "
                   "chips, synced to the URL", "History & bulk", route=route, max_height=1150)

    def capture_graph_node(self, page: Page, tr: NetTracker) -> None:
        route = "/graph?" + urllib.parse.urlencode({"domain": GRAPH_DOMAIN, "depth": 2})
        self.goto(page, tr, route, timeout=40)
        page.wait_for_timeout(3000)  # let the force layout cool down
        node = None
        for prefix in GRAPH_FOCUS:
            loc = page.locator(f'main svg g[role="button"][aria-label^="{prefix}"]').first
            if loc.count():
                node = loc
                break
        if node is None:
            raise RuntimeError("no graph node to select")
        node.focus()
        node.press("Enter")
        page.evaluate("document.activeElement && document.activeElement.blur()")
        page.wait_for_timeout(600)
        self.settle(page, tr, timeout=15)
        self.shoot(page, tr, "graph-node", "Relationship graph with a domain selected: its neighbours are highlighted "
                   "and the side panel lists details and pivots", "Investigation", route=route, max_height=1300,
                   crop_h=self.content_crop(page, min_h=900))

    def capture_watch_history(self, page: Page, tr: NetTracker) -> None:
        self.goto(page, tr, "/watchlist")
        row = page.locator("main tr", has_text=WATCH_HISTORY_LABEL).first
        if not row.count():
            row = page.locator("main tbody tr").first
        row.get_by_role("button", name=re.compile(r"History")).click()
        page.get_by_text(re.compile(r"^History · ")).first.wait_for(timeout=10_000)
        page.get_by_text("Risk over time").first.wait_for(timeout=15_000)
        self.settle(page, tr, timeout=15)
        page.wait_for_timeout(500)
        self.shoot(page, tr, "watchlist-history", "Watchlist history drawer: risk over time, every check and the "
                   "resolving typosquats of the monitored domain", "Monitoring", route="/watchlist", full=False)

    # ------------------------------------------------------------ element helpers
    def find_input(self, page: Page, pred: Callable[[dict], bool]):
        try:
            infos = page.evaluate("window.__pg.mainInputs()") or []
        except PWError:
            return None
        for i in infos:
            if pred(i):
                return page.locator(f'[data-capture-input="{i["i"]}"]').first
        return None

    def find_url_input(self, page: Page):
        return self.find_input(page, lambda i: i["tag"] in ("input", "textarea") and i["type"] in (
            "input", "text", "url", "search", "textarea") and (
            re.search(r"https?://|example|url|link", i["placeholder"], re.I) is not None))

    @staticmethod
    def has_results(page: Page) -> bool:
        try:
            return bool(page.evaluate(
                "(() => { const m = document.querySelector('main') || document.body;"
                " return m.querySelectorAll('tbody tr, [role=row], li').length >= 3; })()"))
        except PWError:
            return False

    # ------------------------------------------------------------ video
    def record_video(self, browser: Browser) -> None:
        log("demo video (1280x800)", "step")
        ffmpeg = self.cfg.ffmpeg
        if not ffmpeg:
            self.fail("demo.mp4", "ffmpeg not found (pass --ffmpeg)")
            return
        assert self.tmp is not None
        vdir = self.tmp / "video"
        vdir.mkdir(parents=True, exist_ok=True)
        ctx = self.new_context(browser, theme="light", width=1280, height=800, dsf=1, video_dir=vdir,
                               motion="no-preference", cursor=True)
        page = ctx.new_page()
        t0 = time.monotonic()
        tr = NetTracker(page)
        demo = DemoDriver(self, page, tr, t0)
        raw_path: Path | None = None
        try:
            demo.run()
        except Exception as e:
            self.fail("demo.mp4", f"demo script stopped early: {type(e).__name__}: {str(e).splitlines()[0][:160]}")
            if self.cfg.verbose:
                traceback.print_exc()
        finally:
            demo.marks.setdefault("end", time.monotonic() - t0)
            video = page.video
            ctx.close()
            if video is not None:
                try:
                    raw_path = Path(video.path())
                except PWError:
                    raw_path = None
        if not raw_path or not raw_path.exists():
            self.fail("demo.mp4", "Playwright produced no video file")
            return
        if self.cfg.keep_raw:
            shutil.copy2(raw_path, self.out / "demo-raw.webm")
        self.encode_video(raw_path, demo)

    def encode_video(self, raw: Path, demo: "DemoDriver") -> None:
        ffmpeg = self.cfg.ffmpeg
        assert ffmpeg
        m = demo.marks
        start = max(0.0, m.get("start", 0.0))
        end = m["end"]
        segs: list[tuple[float, float | None, float]] = []
        s0, s1 = m.get("scan_start"), m.get("scan_end")
        if s0 is not None and s1 is not None and s1 - s0 > 6.0:
            a, b = s0 + 0.8, s1 - 0.3          # keep the click and the first progress steps at real speed
            factor = (b - a) / 2.5             # the wait plays back in ~2.5 s
            segs = [(start, a, 1.0), (a, b, factor), (b, None, 1.0)]
        else:
            segs = [(start, None, 1.0)]
        parts, labels = [], []
        for k, (a, b, f) in enumerate(segs):
            trim = f"trim=start={a:.3f}" + (f":end={b:.3f}" if b is not None else "")
            pts = "setpts=PTS-STARTPTS" if f == 1.0 else f"setpts=(PTS-STARTPTS)/{f:.4f}"
            parts.append(f"[s{k}]{trim},{pts}[v{k}]")
            labels.append(f"[v{k}]")
        n = len(segs)
        graph = (f"[0:v]split={n}" + "".join(f"[s{k}]" for k in range(n)) + ";" + ";".join(parts) + ";"
                 + "".join(labels) + f"concat=n={n}:v=1:a=0,fps=25,format=yuv420p[v]")

        def out_time(t: float) -> float:
            acc = 0.0
            for a, b, f in segs:
                bb = b if b is not None else end
                if t <= a:
                    return round(acc, 1)
                if t <= bb:
                    return round(acc + (t - a) / f, 1)
                acc += (bb - a) / f
            return round(acc, 1)

        mp4 = self.out / "demo.mp4"
        size = 0
        for crf in (28, 31, 34, 37, 40):
            cmd = [ffmpeg, "-y", "-hide_banner", "-loglevel", "error", "-i", str(raw), "-filter_complex", graph,
                   "-map", "[v]", "-c:v", "libx264", "-preset", "slow", "-crf", str(crf), "-pix_fmt", "yuv420p",
                   "-movflags", "+faststart", "-an", str(mp4)]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                self.fail("demo.mp4", f"ffmpeg failed: {r.stderr.strip()[:300]}")
                return
            size = mp4.stat().st_size
            if size <= 15 * 1024 * 1024:
                break
            log(f"demo.mp4 is {human(size)} at CRF {crf}; re-encoding smaller", "warn")
        duration = out_time(end)
        chapters = [{"t": out_time(t), "label": label} for label, t in demo.chapters]
        mp4_item = Media(file="demo.mp4", kind="video", group="Video", bytes=size, width=1280, height=800,
                         caption=f"Demo walkthrough ({duration:.0f} s): " + " -> ".join(c["label"] for c in chapters),
                         extra={"duration_s": duration, "codec": "h264", "crf": crf, "chapters": chapters,
                                "demo_url": self.cfg.demo_url, "demo_scan_id": demo.scan_id,
                                "scan_wait_s": round(s1 - s0, 1) if s0 is not None and s1 is not None else None})
        self.items = [x for x in self.items if x.file != "demo.mp4"] + [mp4_item]
        log(f"{'demo.mp4':34s} 1280x800 {human(size):>9s} ({duration:.0f} s, CRF {crf})", "ok")
        self.encode_gif(mp4, min(25.0, duration))

    def encode_gif(self, mp4: Path, seconds: float) -> None:
        ffmpeg = self.cfg.ffmpeg
        assert ffmpeg
        gif = self.out / "demo.gif"
        size, used = 0, {}
        for colors, secs, width in ((128, seconds, 960), (96, seconds, 960), (64, seconds, 960),
                                    (64, min(seconds, 20.0), 960), (64, min(seconds, 20.0), 800)):
            vf = (f"fps=10,scale={width}:-1:flags=lanczos,split[a][b];"
                  f"[a]palettegen=max_colors={colors}:stats_mode=diff[p];"
                  f"[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle")
            cmd = [ffmpeg, "-y", "-hide_banner", "-loglevel", "error", "-t", f"{secs:.2f}", "-i", str(mp4),
                   "-filter_complex", vf, "-loop", "0", str(gif)]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                self.fail("demo.gif", f"ffmpeg failed: {r.stderr.strip()[:300]}")
                return
            size = gif.stat().st_size
            used = {"colors": colors, "seconds": round(secs, 1), "width": width, "fps": 10}
            if size <= 8 * 1024 * 1024:
                break
            log(f"demo.gif is {human(size)} ({used}); trying smaller settings", "warn")
        with Image.open(gif) as im:
            w, h = im.size
        item = Media(file="demo.gif", kind="gif", group="Video", width=w, height=h, bytes=size,
                     caption=f"Animated preview (first {used.get('seconds', seconds):.0f} s of the demo)", extra=used)
        self.items = [x for x in self.items if x.file != "demo.gif"] + [item]
        log(f"{'demo.gif':34s} {w}x{h} {human(size):>9s} ({used})", "ok")

    # ------------------------------------------------------------ manifest / readme
    def manifest_path(self) -> Path:
        return self.out / "manifest.json"

    def load_previous(self) -> dict:
        p = self.manifest_path()
        try:
            data = json.loads(p.read_text()) if p.exists() else {}
        except ValueError:
            return {}
        files = []
        for f in data.get("files", []):
            try:
                files.append(Media(**{k: v for k, v in f.items() if k in Media.__dataclass_fields__}))
            except TypeError:
                continue
        def named(key: str) -> list[dict]:
            return [f for f in data.get(key, []) if isinstance(f, dict) and "name" in f]
        return {"files": files, "failed": named("failed"), "skipped": named("skipped")}

    def attempted(self, name: str, kind: str = "screenshot") -> bool:
        """Was this shot (file stem or failure name) part of this run?"""
        if kind in ("video", "gif") or name.startswith("demo"):
            return not self.cfg.skip_video and (self.cfg.video_only or self.want("demo"))
        if self.cfg.extras_only and name not in EXTRA_STEMS:
            return False
        return not self.cfg.video_only and self.want(name)

    def write_manifest(self) -> dict:
        items = list(self.items)
        mine = {m.file for m in items}
        prev = self.load_previous()
        for m in prev.get("files", []):  # entries from an earlier run that were not regenerated now
            if m.file in mine or not (self.out / m.file).exists():
                continue
            if not self.attempted(Path(m.file).stem, m.kind):
                items.append(m)                  # outside this (partial) run: keep
            elif m.kind == "screenshot":         # attempted but not produced any more: stale, remove it
                (self.out / m.file).unlink(missing_ok=True)
                log(f"removed stale {m.file}", "warn")
        failed, skipped = list(self.failed), list(self.skipped)
        now = {f["name"] for f in failed + skipped}
        failed += [f for f in prev.get("failed", []) if f["name"] not in now and not self.attempted(f["name"])]
        skipped += [f for f in prev.get("skipped", []) if f["name"] not in now and not self.attempted(f["name"])]
        order = {g: i for i, g in enumerate(GROUP_ORDER)}
        seq = {m.file: i for i, m in enumerate(items)}
        items.sort(key=lambda m: (order.get(m.group, 99), seq[m.file]))
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "generator": "scripts/capture_media.py",
            "base_url": self.cfg.base_url,
            "model_version": (self.health or {}).get("model_version"),
            "reports": {"phishing_scan_id": (self.phish or {}).get("id"),
                        "legitimate_scan_id": (self.legit or {}).get("id")},
            "limits": {"png_max_kb": self.cfg.max_kb, "mp4_max_mb": 15, "gif_max_mb": 8},
            "files": [asdict(m) for m in items],
            "failed": failed,
            "skipped": skipped,
            "notes": self.notes,
            "sidebar": [n["label"] for n in self.nav],
        }
        self.manifest_path().write_text(json.dumps(data, indent=2) + "\n")
        log(f"manifest.json: {len(items)} files, {len(failed)} failures, {len(skipped)} skipped", "ok")
        return data


def section_offsets(info: dict, max_sections: int) -> list[int]:
    """Scroll offsets that start each viewport-sized section at the top of a card or heading."""
    cards, inset = info.get("cards") or [], float(info.get("inset") or 0)
    total, vh = float(info.get("total") or 0), float(info.get("vh") or 900)
    max_off = max(0.0, total - vh)
    offs, cur = [0], 0.0
    while len(offs) < max_sections and cur < max_off - 4:
        nxt = None
        for c in cards:
            if c["y1"] > cur + vh + 2 and c["y0"] - inset - 16 > cur + 80:
                nxt = c["y0"] - inset - 16
                break
        if nxt is None:
            nxt = cur + (vh - inset) * 0.85
        nxt = min(nxt, max_off)
        if nxt <= cur + 40:
            break
        offs.append(int(nxt))
        cur = nxt
    return offs


class DemoDriver:
    """Drives the demo walkthrough with a visible cursor, smooth scrolling and short pauses."""

    def __init__(self, cap: Capture, page: Page, tr: NetTracker, t0: float):
        self.cap, self.page, self.tr, self.t0 = cap, page, tr, t0
        self.marks: dict[str, float] = {}
        self.chapters: list[tuple[str, float]] = []
        self.scan_id: int | None = None
        self.mouse = (640.0, 400.0)

    # -- primitives
    def now(self) -> float:
        return time.monotonic() - self.t0

    def chapter(self, label: str) -> None:
        self.chapters.append((label, self.now()))
        log(f"  video {self.now():5.1f}s  {label}")

    def pause(self, s: float) -> None:
        self.page.wait_for_timeout(int(s * 1000))

    def glide(self, x: float, y: float, ms: int = 550) -> None:
        x0, y0 = self.mouse
        steps = max(8, ms // 16)
        for k in range(1, steps + 1):
            p = k / steps
            e = p * p * (3 - 2 * p)
            self.page.mouse.move(x0 + (x - x0) * e, y0 + (y - y0) * e)
            self.page.wait_for_timeout(14)
        self.mouse = (x, y)

    def glide_to(self, loc, ms: int = 550) -> bool:
        try:
            loc.scroll_into_view_if_needed(timeout=5000)
            box = loc.bounding_box(timeout=5000)
        except PWError:
            return False
        if not box:
            return False
        self.glide(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2, ms)
        return True

    def click(self, loc, ms: int = 550) -> bool:
        if not self.glide_to(loc, ms):
            return False
        self.pause(0.15)
        try:
            loc.click(timeout=8000)
        except PWError:
            return False
        return True

    def scroll(self, by: float | None = None, to: float | None = None, ms: int = 1500) -> None:
        self.page.evaluate("(o) => window.__pg.smoothScroll(o)", {"by": by, "to": to, "ms": ms})

    def height(self) -> int:
        try:
            return int(self.page.evaluate("window.__pg.contentHeight()"))
        except PWError:
            return 800

    def settle(self, timeout: float = 15.0, after_ms: int = 250) -> None:
        self.cap.settle(self.page, self.tr, timeout=timeout, after_ms=after_ms)

    def nav_click(self, labels: tuple[str, ...], fallback: str) -> bool:
        items = [{"norm": norm_label(n["label"]), **n} for n in self.cap.nav if not n.get("external")]
        hit = match_label(items, [norm_label(x) for x in labels])
        href = hit["href"] if hit else None
        if href:
            loc = self.page.locator(f'aside a[href="{href}"], nav a[href="{href}"]').first
            if self.click(loc, 650):
                self.settle()
                return True
        if not hit and fallback is None:
            return False
        self.page.goto(self.cap.url(href or fallback), wait_until="domcontentloaded")
        self.settle()
        return not self.cap.problems(self.page).get("notFound")

    def browse(self, steps: int, step_px: int = 650, ms: int = 2000, dwell: float = 0.9) -> None:
        for _ in range(steps):
            if self.page.evaluate("window.__pg.scrollTop()") + 800 >= self.height() - 4:
                break
            self.scroll(by=step_px, ms=ms)
            self.pause(dwell)
        self.scroll(to=0, ms=900)

    # -- the walkthrough
    def run(self) -> None:
        cap, page = self.cap, self.page
        page.goto(cap.url("/"), wait_until="domcontentloaded", timeout=45_000)
        self.settle(timeout=30, after_ms=500)
        if not cap.nav:
            cap.discover_nav(page)
        self.marks["start"] = max(0.0, self.now() - 0.2)
        self.chapter("Overview")
        page.mouse.move(*self.mouse)
        self.pause(1.4)
        self.scroll(by=520, ms=2200)
        self.pause(1.2)
        self.scroll(to=0, ms=1100)
        self.pause(0.4)

        # 1) scan a phishing URL with a deep scan
        self.chapter("Deep scan of a phishing URL")
        self.nav_click(("Scan",), "/scan")
        inp = cap.find_url_input(page)
        if inp is None:
            raise RuntimeError("no URL input on the scan page")
        self.click(inp, 600)
        inp.fill("")
        inp.press_sequentially(cap.cfg.demo_url, delay=42)
        self.pause(0.5)
        sw = page.locator('main [role="switch"]').first
        try:
            if sw.count() and sw.get_attribute("aria-checked") == "false":
                self.click(sw, 450)
                self.pause(0.3)
        except PWError:
            pass
        submit = page.locator('main form button[type="submit"]').first
        if not submit.count():
            submit = page.get_by_role("button", name=re.compile(r"analy[sz]e|scan", re.I)).first
        self.click(submit, 500)
        self.marks["scan_start"] = self.now()
        try:
            page.wait_for_url(re.compile(r".*/scans/\d+.*"), timeout=int(cap.cfg.scan_timeout * 1000))
            m = re.search(r"/scans/(\d+)", page.url)
            self.scan_id = int(m.group(1)) if m else None
        except PWError:
            log("  the deep scan did not open a report in time; showing the highest-risk report instead", "warn")
            if cap.phish:
                page.goto(cap.url(f"/scans/{cap.phish['id']}"), wait_until="domcontentloaded")
        self.settle(timeout=30, after_ms=300)
        self.marks["scan_end"] = self.now()

        # 2) report tabs
        self.chapter("Scan report")
        self.pause(2.0)
        self.scroll(by=560, ms=2200)
        self.pause(1.4)
        self.scroll(to=0, ms=1000)
        tabs = cap.find_tabs(page)
        specs = {k: a for k, a, _, _ in REPORT_TABS}
        present = []
        used: set[int] = set()
        for key in VIDEO_TABS:
            t = match_label(tabs, specs[key], used=used)
            if t and len(present) < VIDEO_MAX_TABS:
                used.add(t["i"])
                present.append((key, t))
        present.sort(key=lambda kt: kt[1]["i"])  # play them left to right
        if self.chapters and self.chapters[-1][0] == "Scan report":  # name what the viewer sees in the caption
            shown = ["AI summary"] + [t["label"] for _, t in present]
            self.chapters[-1] = (f"Scan report ({', '.join(shown)})", self.chapters[-1][1])
        dwell = max(1.5, min(2.6, 22.0 / max(1, len(present))))
        for key, t in present:
            tabs = cap.find_tabs(page)
            cur = next((x for x in tabs if x["norm"] == t["norm"]), None)
            if not cur:
                continue
            if not self.click(page.locator(f'[data-capture-tab="{cur["i"]}"]').first, 450):
                continue
            self.settle(timeout=8, after_ms=150)
            if key in VIDEO_SCROLL_TABS and self.height() > 800 + 240:
                self.pause(dwell * 0.5)
                self.scroll(by=min(420, self.height() - 800), ms=1100)
                self.pause(dwell * 0.5)
                self.scroll(to=0, ms=450)
            else:
                self.pause(dwell)

        # 3) analytics, model lab, graph
        self.chapter("Analytics")
        if self.nav_click(("Analytics",), "/analytics"):
            self.pause(1.4)
            self.browse(2, step_px=650, ms=2000, dwell=1.0)
        self.chapter("Model Lab")
        if self.nav_click(("Model Lab", "Model"), "/model"):
            self.pause(1.3)
            self.browse(2, step_px=650, ms=2000, dwell=1.0)
        if any(norm_label(n["label"]) in ("graph", "relationship graph") for n in cap.nav):
            self.chapter("Relationship graph")
            if self.nav_click(("Graph", "Relationship Graph"), None):  # type: ignore[arg-type]
                self.pause(3.5)

        # 4) history filters
        self.chapter("History pivot")
        if self.nav_click(("History",), "/history"):
            self.pause(1.0)
            # pivot: every scan sharing the demo scan's threat type / tier (v2 pivot filters, synced to the URL)
            scan = (cap.api.try_get(f"/api/scans/{self.scan_id}") if self.scan_id else None) or cap.phish or {}
            pivot = next(((k, scan.get(k)) for k in ("threat_type", "tier", "registrar") if scan.get(k)), None)
            if pivot:
                page.goto(cap.url("/history?" + urllib.parse.urlencode({pivot[0]: pivot[1]})),
                          wait_until="domcontentloaded")
                self.settle(timeout=10, after_ms=300)
                self.pause(1.2)
                self.scroll(by=360, ms=1200)
                self.pause(1.6)
            else:
                verdict = cap.find_input(page, lambda i: i["tag"] == "select" and any(
                    o["value"].lower() == "phishing" or o["text"].lower() == "phishing" for o in i["options"]))
                if verdict is not None and self.glide_to(verdict, 500):
                    self.pause(0.2)
                    try:
                        verdict.select_option(value="phishing")
                    except PWError:
                        verdict.select_option(label="Phishing")
                    self.settle(timeout=8, after_ms=200)
                    self.pause(2.2)
        self.pause(1.0)
        self.marks["end"] = self.now()


# ============================================================================ curated README set (--curate)
SECTIONS = ("Dashboard", "Scanning", "Scan report", "History & bulk", "Analytics", "Machine learning", "Investigation",
            "Monitoring", "Community & intel", "Tracking & settings", "Responsive & themes")
# (final file, source stem from a capture run, title, section, explanation) in README order.
CURATED: tuple[tuple[str, str, str, str, str], ...] = (
    ("01-overview.png", "overview", "Overview dashboard", "Dashboard",
     "The landing page summarises detection activity for the selected time range: total, phishing and legitimate "
     "scans, detection rate, average trust and risk scores, blacklist hits and impersonated brands. Charts of scans "
     "over time, the verdict split, the risk-score distribution, top impersonated brands and hosting countries sit "
     "next to a live scan feed, model health and recent alerts, so the current phishing picture is visible at a glance."),
    ("02-scan-url.png", "scan", "Scan a single URL", "Scanning",
     "The Scan page takes one URL and runs the full analysis pipeline. The Deep scan toggle adds live DNS, WHOIS, SSL, "
     "HTTP and page-content checks on top of the instant lexical and ML analysis, and the example links let a reviewer "
     "try a legitimate site, a typosquatted PayPal URL and a raw-IP banking page in one click."),
    ("03-scan-email-sms.png", "scan-text", "Extract URLs from an email or SMS", "Scanning",
     "A suspicious email or SMS is pasted as text and PhishGuard extracts every link in it, including defanged forms "
     "such as hxxp:// and [.]. The extracted URLs can be ticked and scanned in one go, which matches how phishing "
     "really arrives: inside messages rather than as bare links."),
    ("04-scan-qr.png", "scan-qr", "Scan a QR code (quishing)", "Scanning",
     "A QR-code image is decoded locally in the browser with jsQR, so the image is never uploaded, and the embedded "
     "URL is shown before anything is opened. One click then scans the decoded link, which protects against QR-code "
     "phishing on posters, invoices and parcel notices."),
    ("05-scan-progress.png", "scan-progress", "Scan in progress", "Scanning",
     "While a deep scan runs, the analysis-pipeline card ticks off each stage: lexical analysis, ML prediction, DNS, "
     "WHOIS, SSL/TLS, HTTP and content, brand impersonation and reputation. It makes the multi-signal design visible "
     "and tells the user what is being checked before the report opens."),
    ("06-report-summary.png", "report-phishing-summary", "Report: summary, AI summary and factors", "Scan report",
     "The report header shows the 0-100 risk gauge, verdict, trust score and tier, threat type, engines flagged, ML "
     "probability and scan duration for a live phishing kit hosted on vercel.app. The Summary tab adds a plain-English "
     "AI summary, the negative and positive factors behind the score, the score breakdown (60% ML + 40% heuristics) "
     "and every security check, so the verdict can be explained instead of being a black box."),
    ("07-report-ml-explanation.png", "report-phishing-ml", "Report: ML explanation", "Scan report",
     "The ML Explanation tab shows the primary model (Random Forest), its phishing probability and how many of the "
     "four classifiers agree. Signed feature contributions show which URL properties pushed the prediction towards "
     "phishing or safe, and the table lists every lexical feature extracted from the URL."),
    ("08-report-domain-whois.png", "report-phishing-domain", "Report: domain and WHOIS", "Scan report",
     "The Domain tab splits the hostname into subdomain, registered domain and TLD and shows WHOIS data (registrar, "
     "created, updated and expiry dates) and DNS records. Domain age is a strong phishing signal; here the registered "
     "domain is old because the kit sits on a free hosting platform, which the subdomain and hosting checks expose."),
    ("09-report-geo-hosting.png", "report-phishing-geo", "Report: geo and hosting", "Scan report",
     "Geo & Hosting resolves the server IP to its country, city, ASN, organisation and ISP, flags hosting/datacenter "
     "networks and pins the location on an OpenStreetMap map. This helps to spot phishing pages on cheap hosting and "
     "to group sites that share infrastructure."),
    ("10-report-ssl.png", "report-phishing-ssl", "Report: SSL certificate", "Scan report",
     "The SSL tab shows the certificate issuer, subject, protocol, validity window, days left and SANs, and explains "
     "why validation failed (here a hostname mismatch). Free, short-lived or mismatched certificates are common on "
     "phishing sites, so the certificate feeds into the heuristic score."),
    ("11-report-http.png", "report-phishing-http", "Report: HTTP analysis", "Scan report",
     "The HTTP tab follows the redirect chain hop by hop, shows the response details and which of six security "
     "headers are present, and detects technologies and suspicious JavaScript (obfuscated eval, exfiltration to a "
     "Telegram bot, visitor geo-lookup). The page-content counters (forms, password fields, external scripts) reveal "
     "a credential-harvesting login form."),
    ("12-report-brand.png", "report-phishing-brand", "Report: brand impersonation", "Scan report",
     "For a scan that impersonates MetaMask, the Brand tab names the targeted brand, the technique (the brand used as "
     "a subdomain of an unrelated vercel.app domain) and the similarity to the genuine brand domain. The table "
     "explains the tricks attackers use to look legitimate: typosquats, homoglyphs, combosquats, punycode, brand in "
     "the path or in the page content."),
    ("13-report-reputation.png", "report-phishing-reputation", "Report: reputation and detection engines",
     "Scan report",
     "The Reputation tab lists every detection engine with its type and result: five local threat feeds (OpenPhish, "
     "URLhaus, Phishing.Database, PhishTank, Phishing Army), five DNS blocklists and the PhishGuard ML engine. It also "
     "shows which blacklists contain the URL and the community verdict with its votes, so the ML score is "
     "cross-checked against independent sources."),
    ("14-report-content.png", "report-phishing-content", "Report: page content", "Scan report",
     "The Content tab classifies the live page (here a login page with 95% confidence), detects its language and "
     "checks whether the domain is parked. Category scores and the tracker list explain what the page is trying to "
     "do, for example harvesting webmail credentials."),
    ("15-report-resources.png", "report-phishing-resources", "Report: resources", "Scan report",
     "The Resources tab counts every script, style, image, frame and form the page loads and the domains it "
     "contacts. A login page that pulls all of its resources from third-party domains is typical of a copied "
     "phishing kit."),
    ("16-report-source.png", "report-phishing-source", "Report: page source", "Scan report",
     "The Source tab shows the stored HTML as plain text with line numbers, search, wrapping and copy; the page is "
     "never rendered. The phishing kit's markup and scripts can be inspected safely without visiting the live site."),
    ("17-report-graph.png", "report-phishing-graph", "Report: relationship graph", "Scan report",
     "The Graph tab draws the infrastructure around the scanned domain up to two hops: its URL, IP address, ASN, "
     "name servers, registrar, country and the other scanned domains that share them. Shared infrastructure links a "
     "single phishing site to related campaigns."),
    ("18-report-timeline.png", "report-phishing-timeline", "Report: timeline", "Scan report",
     "The Timeline tab lists the events recorded for this scan and its domain (scans, community reports, watchlist "
     "runs and alerts), each with expandable details. It shows how a phishing site was detected, reported and "
     "monitored over time."),
    ("19-report-legitimate.png", "report-legit-summary", "Report: legitimate (Trusted) site", "Scan report",
     "For https://github.com the gauge shows risk 3/100, tier Trusted, 0 of 11 engines flagged and a 4.3% ML "
     "phishing probability. The AI summary and the positive factors (official domain, valid certificate, not on any "
     "feed) show that safe verdicts are explained as clearly as phishing ones, which keeps false positives "
     "understandable."),
    ("20-history-pivot-filters.png", "history-pivot", "History with pivot filters", "History & bulk",
     "Scan history combines search, verdict, source, TLD, risk-range and date filters with advanced pivots (IP, ASN, "
     "registrar, content category, threat type, trust tier). Active filters appear as removable chips and are kept "
     "in the URL, so a view such as 'all untrusted social-engineering scans' can be shared or exported to CSV/JSON."),
    ("21-bulk-scan.png", "bulk", "Bulk scan", "History & bulk",
     "Up to 500 URLs are pasted or uploaded as a CSV/TXT file; duplicates are removed and the job runs in the "
     "background. The jobs table tracks the progress and verdict split of every job."),
    ("22-bulk-job-detail.png", "bulk-job", "Bulk job results", "History & bulk",
     "A finished bulk job shows its progress, the verdict distribution and every URL with its verdict, risk score, "
     "impersonated brand, blacklist status and scan time, with CSV/JSON export. A list of reported links can be "
     "triaged in one pass, and phishing URLs that are on no blacklist yet are still caught by the model."),
    ("23-analytics-trends.png", "analytics-trends", "Analytics: trends and activity heatmap", "Analytics",
     "Scans over time are stacked by verdict next to the average risk trend, and the heatmap shows scan activity by "
     "weekday and hour (UTC). Together they show when phishing activity peaks and whether risk is rising."),
    ("24-analytics-distributions.png", "analytics-distributions", "Analytics: distributions", "Analytics",
     "Charts break the scans down by top-level domain, scan source (web, bulk, extension, API, watch, text, QR), "
     "impersonation technique, SSL status, domain age and the checks that fail most often. They show which signals "
     "separate phishing from legitimate sites in the collected data."),
    ("25-analytics-threat-insights.png", "analytics-insights", "Analytics: threat insights", "Analytics",
     "Threat types (Safe Browsing-style), reputation tiers and content categories summarise what kind of threats "
     "were found. Clicking a slice or bar opens the matching scans in History."),
    ("26-analytics-funnel.png", "analytics-funnel", "Analytics: detection funnel", "Analytics",
     "The funnel shows how many scans pass each detection stage: scanned, reachable, login/password form, brand "
     "impersonation, listed in a feed and phishing verdict. It shows how the individual signals narrow down to the "
     "final phishing verdicts."),
    ("27-analytics-performance.png", "analytics-performance", "Analytics: performance", "Analytics",
     "P50, P95, P99 and maximum scan latency, the error count, hourly throughput and per-check error rates measure "
     "how fast and reliable the analysis engine is. The median deep scan, with all network checks, finishes in "
     "under two seconds."),
    ("28-model-lab-comparison.png", "model-lab-comparison", "Model Lab: dataset and model comparison",
     "Machine learning",
     "The Model Lab shows the training dataset (146,364 URLs from PhiUSIIL, PhishTank, Phishing.Database, OpenPhish "
     "and Tranco, balanced 50/50), live prediction statistics and a comparison of Logistic Regression, Decision "
     "Tree, Random Forest and SVM on accuracy, precision, recall, F1, ROC-AUC, 5-fold cross-validation and timing. "
     "Random Forest has the best F1 (85.6%) and ROC-AUC (0.945) and is used for scoring."),
    ("29-model-lab-realistic-evaluation.png", "model-lab-realistic", "Model Lab: realistic evaluation",
     "Machine learning",
     "Besides the stratified test split, every model is evaluated on 4,000 held-out URLs from campaigns and domains "
     "never seen in training (PhishTank and Phishing.Database phishing, Tranco deep links). F1, precision, recall, "
     "HTTPS recall and false-positive rate on this set give an honest estimate of real-world accuracy, and the "
     "composition card shows where the training URLs came from."),
    ("30-model-lab-roc-pr.png", "model-lab-curves", "Model Lab: ROC and precision-recall curves", "Machine learning",
     "ROC and precision-recall curves of the four classifiers on the test split, with the best model drawn thicker. "
     "They show the trade-off between catching phishing and raising false alarms at every threshold."),
    ("31-model-lab-confusion-matrices.png", "model-lab-confusion", "Model Lab: confusion matrices",
     "Machine learning",
     "One confusion matrix per model counts true/false positives and negatives on the 29,272-URL test split. Missed "
     "phishing (false negatives) and blocked legitimate sites (false positives) are the two errors that matter in "
     "practice."),
    ("32-model-lab-feature-importance.png", "model-lab-features", "Model Lab: feature importance", "Machine learning",
     "The top 20 Random Forest features and the mean of each feature in phishing vs legitimate samples explain what "
     "the model learned. Subdomain length, free-hosting platforms and hostname length matter most, and phishing "
     "hostnames are much longer on average (25.3 vs 16.5 characters)."),
    ("33-domain-intelligence.png", "domain", "Domain intelligence", "Investigation",
     "The Domain page aggregates every scan of one domain: scan count, average risk, latest verdict, first and last "
     "seen, a risk trend and the latest IP, hosting, registrar, domain age and SSL issuer. From here the domain can "
     "be watched, re-scanned or checked for typosquats."),
    ("34-graph-node-selected.png", "graph-node", "Relationship graph with a node selected", "Investigation",
     "The Graph page links scanned domains through shared IPs, ASNs, name servers, registrars, brands and redirects, "
     "here centred on a MetaMask phishing domain at depth 2. Selecting the domain highlights its neighbours and opens "
     "a side panel with its verdict, risk, connections and pivots, which helps to uncover campaigns that reuse the "
     "same infrastructure."),
    ("35-typosquat-paypal.png", "typosquat", "Typosquat finder (paypal.com)", "Investigation",
     "dnstwist-style permutations of paypal.com (omission, transposition, homoglyph, TLD swap, dictionary words and "
     "more, 13 techniques) are generated and checked in DNS. Here 50 of the 60 checked lookalikes resolve, each with "
     "its IP and a one-click scan, which shows how many domains could be used to impersonate a single brand."),
    ("36-watchlist.png", "watchlist", "Watchlist", "Monitoring",
     "URLs and domains are re-checked automatically on an interval; each target shows its last verdict, risk, change "
     "and alert count, and brand domains can also be monitored for newly resolving typosquats. A verdict change or a "
     "new lookalike raises an alert."),
    ("37-watchlist-history.png", "watchlist-history", "Watchlist history", "Monitoring",
     "The history drawer of a monitored target charts its risk over time against the suspicious (35) and phishing "
     "(65) thresholds and lists every check with a link to its report. For a brand domain such as paypal.com it also "
     "lists the resolving typosquats, the lookalikes most likely to be used against that brand."),
    ("38-alerts.png", "alerts", "Alerts", "Monitoring",
     "Alerts are raised by high-risk scans, watchlist changes, typosquat baselines and community verification, with "
     "severity filters and read/unread state. Each alert links to the scan or watchlist entry that caused it."),
    ("39-community.png", "community", "Community reports", "Community & intel",
     "Anyone can report a suspicious URL with a label, targeted brand and comment; reports are verified "
     "PhishTank-style at +3 net phishing votes and rejected at -3. The Pending, Verified and Rejected tabs show the "
     "reporter, status and votes, and a verified report raises the risk score of that URL."),
    ("40-threat-feeds.png", "feeds", "Threat feeds", "Community & intel",
     "PhishGuard keeps local copies of five public blocklists (OpenPhish, URLhaus, Phishing.Database, PhishTank and "
     "Phishing Army, about 657,000 entries) that can be refreshed on demand. Charts show the entries per feed, top "
     "TLDs and most targeted brands, and any URL, domain or brand can be searched across all feeds."),
    ("41-activity-log.png", "activity", "Activity log", "Tracking & settings",
     "The activity log is an audit trail of scans, alerts, watchlist runs, community reports, votes, bulk jobs, "
     "typosquat searches and settings changes, filterable by event type and with expandable details. It makes every "
     "action of the system traceable."),
    ("42-settings.png", "settings", "Settings", "Tracking & settings",
     "Verdict thresholds (35 suspicious, 65 phishing) are set with sliders and a live preview; other options switch "
     "network checks and page screenshots, set the check timeout and data retention and store optional VirusTotal / "
     "Google Safe Browsing keys. The About section names the project, student, guide and institute and shows the "
     "seven-step system workflow."),
    ("43-api-guide.png", "api-guide", "API guide", "Tracking & settings",
     "The API guide lists the REST endpoints with copy-paste curl examples for scanning, history, export, bulk jobs, "
     "URL extraction, typosquats, community reports and the watchlist. Any tool or script can use the same engine as "
     "the dashboard, for example to check links from a mail gateway."),
    ("44-swagger-docs.png", "api-docs", "Swagger / OpenAPI docs", "Tracking & settings",
     "FastAPI serves interactive OpenAPI documentation at /docs, where every endpoint can be tried from the browser. "
     "The description documents the scoring formula: risk = 0.6 x ML probability x 100 + 0.4 x heuristic score, "
     "raised on a blacklist hit or a verified community report."),
    ("45-dark-overview.png", "dark-overview", "Dark mode: overview", "Responsive & themes",
     "Every page has a dark theme (light, dark or follow the system). Cards, charts and tables keep their contrast, "
     "which suits long analysis sessions."),
    ("46-dark-report.png", "dark-report", "Dark mode: scan report", "Responsive & themes",
     "The phishing report in dark mode keeps the risk gauge, verdict chips, tabs and AI summary readable. The colour "
     "coding is the same as in the light theme, so red still means danger."),
    ("47-dark-analytics.png", "dark-analytics", "Dark mode: analytics", "Responsive & themes",
     "Analytics in dark mode re-colours the stacked scans-over-time chart, the average risk trend and the activity "
     "heatmap for a dark background. Verdict colours stay consistent across both themes."),
    ("48-mobile-overview.png", "mobile-overview", "Mobile: overview", "Responsive & themes",
     "On a 390 px phone screen the sidebar collapses into a menu and the KPI cards stack in two columns. The "
     "dashboard stays usable on small screens without horizontal scrolling."),
    ("49-mobile-report.png", "mobile-report", "Mobile: scan report", "Responsive & themes",
     "On a phone the report's action buttons wrap and the risk gauge, verdict and key numbers stack vertically. A "
     "suspicious link received by SMS can be checked on the same device."),
)
FEATURED = ("01-overview", "02-scan-url", "06-report-summary", "07-report-ml-explanation", "13-report-reputation",
            "17-report-graph", "23-analytics-trends", "28-model-lab-comparison", "34-graph-node-selected",
            "20-history-pivot-filters", "35-typosquat-paypal", "37-watchlist-history")


def media_entry(p: Path) -> dict:
    """Basic manifest entry for a demo video / GIF / poster that this script did not produce."""
    e: dict[str, Any] = {"file": p.name, "caption": "Demo walkthrough", "group": "Video", "route": None,
                         "theme": "light", "viewport": "desktop", "bytes": p.stat().st_size, "warnings": [], "extra": {}}
    ext = p.suffix.lower()
    e["kind"] = ("video" if ext in (".mp4", ".webm") else "gif" if ext == ".gif"
                 else "poster" if ext in (".png", ".jpg", ".jpeg") else "subtitles")
    if ext in (".png", ".jpg", ".jpeg", ".gif"):
        try:
            with Image.open(p) as im:
                e["width"], e["height"] = im.size
        except OSError:
            pass
    ffprobe = shutil.which("ffprobe") or ("/opt/homebrew/bin/ffprobe" if Path("/opt/homebrew/bin/ffprobe").exists() else None)
    if ffprobe and ext in (".mp4", ".webm", ".gif"):
        r = subprocess.run([ffprobe, "-v", "error", "-select_streams", "v:0", "-show_entries",
                            "stream=width,height,codec_name:format=duration", "-of", "json", str(p)],
                           capture_output=True, text=True)
        try:
            info = json.loads(r.stdout or "{}")
            st = (info.get("streams") or [{}])[0]
            e.update(width=st.get("width"), height=st.get("height"))
            dur = float((info.get("format") or {}).get("duration") or 0)
            if dur:
                e["extra"] = {"duration_s": round(dur, 1), "codec": st.get("codec_name")}
                e["caption"] = (f"Demo walkthrough ({dur:.0f} s)" if e["kind"] == "video"
                                else f"Animated preview ({dur:.0f} s)")
        except (ValueError, TypeError):
            pass
    if e["kind"] == "poster":
        e["caption"] = "Poster frame of the demo video"
    return e


def curate(out: Path) -> dict:
    """Rename capture-run stems to the numbered README set, delete superseded PNGs, write screenshots.json and
    update manifest.json. Files the video step owns (demo.*, demo-*) are never touched."""
    mf = out / "manifest.json"
    manifest = json.loads(mf.read_text()) if mf.exists() else {"files": []}
    entries = {Path(f["file"]).stem: f for f in manifest.get("files", []) if isinstance(f, dict) and "file" in f}
    files, gallery, missing = [], [], []
    for order, (final, stem, title, section, explanation) in enumerate(CURATED, start=1):
        src, dst = out / f"{stem}.png", out / final
        if src.exists():
            src.replace(dst)
        if not dst.exists():
            missing.append(final)
            continue
        e = dict(entries.get(stem) or entries.get(Path(final).stem) or {})
        with Image.open(dst) as im:
            w, h = im.size
        e.update({"file": final, "title": title, "section": section, "group": section, "order": order,
                  "kind": "screenshot", "width": w, "height": h, "bytes": dst.stat().st_size,
                  "caption": e.get("caption") or title})
        e.setdefault("theme", "dark" if "dark-" in final else "light")
        e.setdefault("viewport", "mobile" if "mobile-" in final else "desktop")
        files.append(e)
        gallery.append({"file": final, "title": title, "section": section, "explanation": explanation})
    keep = {g["file"] for g in gallery}
    removed = []
    for p in sorted(out.glob("*.png")):
        if p.name not in keep and not p.name.startswith("demo"):
            p.unlink()
            removed.append(p.name)
    video = [f for f in manifest.get("files", []) if isinstance(f, dict) and str(f.get("file", "")).startswith("demo")
             and (out / f["file"]).exists()]
    have = {f["file"] for f in video}
    for p in sorted(out.glob("demo*")):  # media owned by the video step: keep (or add) a basic entry
        if p.name not in have and p.suffix.lower() in (".mp4", ".gif", ".webm", ".png", ".jpg", ".jpeg", ".vtt", ".srt"):
            video.append(media_entry(p))
    for f in video:
        if (out / f["file"]).exists():
            f["bytes"] = (out / f["file"]).stat().st_size
    manifest.update({
        "curated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sections": list(SECTIONS),
        "screenshots_index": "screenshots.json",
        "files": files + video,
        "failed": [f for f in manifest.get("failed", []) if isinstance(f, dict)
                   and str(f.get("name", "")).startswith("demo")],
        "skipped": [],
    })
    (out / "screenshots.json").write_text(json.dumps(gallery, indent=2, ensure_ascii=False) + "\n")
    mf.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    total = sum(f["bytes"] for f in files)
    log(f"curated {len(files)} screenshots ({human(total)}); removed {len(removed)} superseded PNGs", "ok")
    if missing:
        log(f"missing (not captured yet): {', '.join(missing)}", "warn")
    return manifest


# ============================================================================ README sync


def _cell(f: dict, media_path: str, cols: int) -> str:
    src = f"{media_path}/{f['file']}"
    cap = (f.get("title") or f.get("caption") or f["file"]).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (f'    <td width="{100 // cols}%" valign="top"><a href="{src}"><img src="{src}" alt="{cap}"></a>'
            f"<br><sub>{cap}</sub></td>")


def _table(items: list[dict], media_path: str, cols: int) -> list[str]:
    lines = ["<table>"]
    for i in range(0, len(items), cols):
        lines.append("  <tr>")
        lines += [_cell(f, media_path, cols) for f in items[i:i + cols]]
        lines.append("  </tr>")
    return lines + ["</table>"]


def gallery_markdown(manifest: dict, media_path: str) -> str:
    """Featured grid + a collapsible section with every other screenshot, grouped like the manifest."""
    files = [f for f in manifest.get("files", []) if f.get("kind") == "screenshot"]
    by_stem = {Path(f["file"]).stem: f for f in files}
    featured = [by_stem[s] for s in FEATURED if s in by_stem]
    rest = [f for f in files if f not in featured]
    lines = [GALLERY_START,
             f"<!-- generated by scripts/capture_media.py from {media_path}/manifest.json; edits here are overwritten -->",
             ""]
    lines += _table(featured or files, media_path, 2)
    if featured and rest:
        groups: dict[str, list[dict]] = {}
        for f in rest:
            groups.setdefault(f.get("group") or "Other", []).append(f)
        order = {g: i for i, g in enumerate(GROUP_ORDER)}
        lines += ["", "<details>", f"<summary><b>All other screenshots ({len(rest)})</b></summary>", ""]
        for g in sorted(groups, key=lambda x: order.get(x, 99)):
            lines += ["", f"#### {g}", ""]
            lines += _table(groups[g], media_path, 3 if g == "Mobile" else 2)
        lines += ["", "</details>"]
    lines += ["", GALLERY_END]
    return "\n".join(lines)


def _pct(v: Any) -> str:
    return f"{float(v) * 100:.1f}%" if isinstance(v, (int, float)) else "-"


def metrics_markdown(metrics: dict, source: str) -> str:
    """README block with the model comparison table (and the held-out evaluation when present)."""
    ds = metrics.get("dataset") or {}
    feats = metrics.get("features") or metrics.get("feature_names") or []
    best = metrics.get("best_model")
    trained = str(metrics.get("trained_at") or "")[:16].replace("T", " ")
    lines = [METRICS_START,
             f"<!-- generated by scripts/capture_media.py --readme-metrics from {source}; edits here are overwritten -->",
             "",
             f"Model version `{metrics.get('version')}` (trained {trained} UTC) on **{ds.get('total', 0):,} URLs** "
             f"({ds.get('phishing', 0):,} phishing / {ds.get('legitimate', 0):,} legitimate; "
             f"{ds.get('train_size', 0):,} train / {ds.get('test_size', 0):,} test) with **{len(feats)} lexical "
             f"features**. Best model: **{best}** (highest test F1).",
             "",
             "| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | 5-fold CV F1 | Train time |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for m in metrics.get("models") or []:
        name = f"**{m['name']}**" if m.get("name") == best else m.get("name")
        cv = (f"{float(m['cv_f1_mean']) * 100:.1f}% ± {float(m.get('cv_f1_std') or 0) * 100:.1f}"
              if isinstance(m.get("cv_f1_mean"), (int, float)) else "-")
        lines.append(f"| {name} | {_pct(m.get('accuracy'))} | {_pct(m.get('precision'))} | {_pct(m.get('recall'))} "
                     f"| {_pct(m.get('f1'))} | {float(m.get('roc_auc') or 0):.3f} | {cv} | {m.get('train_time_s', '-')} s |")
    modern, info = metrics.get("modern_eval"), metrics.get("modern_eval_info") or {}
    if isinstance(modern, dict) and modern:
        lines += ["",
                  f"Held-out \"modern\" evaluation ({info.get('size', 0):,} URLs never used for training or model "
                  f"selection: {info.get('description', '').rstrip('.')}).",
                  "",
                  "| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | False-positive rate |",
                  "|---|---:|---:|---:|---:|---:|---:|"]
        for name, m in modern.items():
            nm = f"**{name}**" if name == best else name
            lines.append(f"| {nm} | {_pct(m.get('accuracy'))} | {_pct(m.get('precision'))} | {_pct(m.get('recall'))} "
                         f"| {_pct(m.get('f1'))} | {float(m.get('roc_auc') or 0):.3f} | {_pct(m.get('fpr'))} |")
    lines += ["", METRICS_END]
    return "\n".join(lines)


def replace_block(text: str, start: str, end: str, block: str) -> str | None:
    if start not in text or end not in text:
        return None
    a = text.index(start)
    b = text.index(end, a) + len(end)
    return text[:a] + block + text[b:]


def update_readme(readme: Path, manifest: dict | None, media_path: str, metrics_file: Path | None = None) -> bool:
    if not readme.exists():
        log(f"{readme} does not exist; not updated", "warn")
        return False
    text, ok = readme.read_text(), True
    if manifest is not None:
        new = replace_block(text, GALLERY_START, GALLERY_END, gallery_markdown(manifest, media_path))
        if new is None:
            log(f"{readme.name} has no {GALLERY_START} ... {GALLERY_END} markers; gallery not written", "warn")
            ok = False
        else:
            text = new
            log(f"README gallery updated in {readme}", "ok")
    if metrics_file is not None:
        try:
            metrics = json.loads(metrics_file.read_text())
        except (OSError, ValueError) as e:
            log(f"cannot read {metrics_file}: {e}", "warn")
            return False
        src = os.path.relpath(metrics_file, readme.parent)
        new = replace_block(text, METRICS_START, METRICS_END, metrics_markdown(metrics, Path(src).as_posix()))
        if new is None:
            log(f"{readme.name} has no {METRICS_START} ... {METRICS_END} markers; metrics not written", "warn")
            ok = False
        else:
            text = new
            log(f"README metrics updated from {metrics_file} (model {metrics.get('version')})", "ok")
    readme.write_text(text)
    return ok


# ============================================================================ main
def parse_args(argv: list[str] | None = None) -> Config:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default="http://127.0.0.1:5173", help="frontend URL (default %(default)s)")
    ap.add_argument("--api-url", default=None, help="API origin if it differs from --base-url")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="output folder (default docs/media)")
    ap.add_argument("--api-key", default=os.environ.get("PHISHGUARD_API_KEY"),
                    help="sent as X-API-Key on API requests (env PHISHGUARD_API_KEY)")
    ap.add_argument("--skip-video", action="store_true", help="screenshots only")
    ap.add_argument("--video-only", action="store_true", help="demo video only")
    ap.add_argument("--only", default="", help="comma-separated shot-name prefixes, e.g. overview,report-phishing")
    ap.add_argument("--demo-url", default=DEMO_URL, help="URL deep-scanned in the demo video")
    ap.add_argument("--max-height", type=int, default=1800, help="cap for full-page shots in CSS px (default 1800)")
    ap.add_argument("--max-kb", type=int, default=400, help="max PNG size in KB (default 400)")
    ap.add_argument("--png-width", type=int, default=1600, help="target PNG width for desktop shots (default 1600)")
    ap.add_argument("--ffmpeg", default=shutil.which("ffmpeg") or ("/opt/homebrew/bin/ffmpeg"
                    if Path("/opt/homebrew/bin/ffmpeg").exists() else None), help="ffmpeg binary")
    ap.add_argument("--scan-timeout", type=float, default=120.0, help="seconds to wait for the demo deep scan")
    ap.add_argument("--phishing-scan-id", type=int, default=None, help="override the phishing report scan id")
    ap.add_argument("--legit-scan-id", type=int, default=None, help="override the legitimate report scan id")
    ap.add_argument("--all-tabs", action="store_true", help="capture every report tab, not just the main ones")
    ap.add_argument("--show-demo-banner", action="store_true",
                    help="keep the hosted demo's 'Demo mode' banner in the shots (hidden by default)")
    ap.add_argument("--readme", default=None,
                    help="README to update: screenshot gallery between the MEDIA-GALLERY markers")
    ap.add_argument("--readme-media-path", default=None,
                    help="media path used in README links (default: --out relative to the README)")
    ap.add_argument("--readme-metrics", action="store_true",
                    help="with --readme: also rewrite the ML-METRICS block from backend/ml/artifacts/metrics.json")
    ap.add_argument("--gallery-only", action="store_true",
                    help="no capture: only rebuild the README blocks from an existing manifest.json")
    ap.add_argument("--keep-raw", action="store_true", help="also keep the raw Playwright .webm (demo-raw.webm)")
    ap.add_argument("--display-origin", default=None,
                    help="origin to show in page text when capturing on another port, e.g. http://localhost:5173")
    ap.add_argument("--extras-only", action="store_true",
                    help="only the interactive shots (scan tabs, scan progress, pivots, graph selection, watch "
                         "history) and the cropped Analytics / Model Lab regions")
    ap.add_argument("--curate", action="store_true",
                    help="no capture: rename the shots in --out to the numbered README set (CURATED), delete "
                         "superseded PNGs, write screenshots.json and update manifest.json")
    ap.add_argument("--headed", action="store_true", help="show the browser")
    ap.add_argument("-v", "--verbose", action="store_true", help="print tracebacks")
    a = ap.parse_args(argv)
    base = a.base_url.rstrip("/")
    return Config(
        base_url=base, api_url=(a.api_url or base).rstrip("/"), out=Path(a.out).expanduser().resolve(),
        api_key=a.api_key or None, skip_video=a.skip_video, video_only=a.video_only,
        only=tuple(x.strip() for x in a.only.split(",") if x.strip()), demo_url=a.demo_url,
        max_height=a.max_height, max_kb=a.max_kb, png_width=a.png_width, ffmpeg=a.ffmpeg, headed=a.headed,
        scan_timeout=a.scan_timeout, phishing_scan_id=a.phishing_scan_id, legit_scan_id=a.legit_scan_id,
        readme=Path(a.readme).expanduser().resolve() if a.readme else None, readme_media_path=a.readme_media_path,
        gallery_only=a.gallery_only, keep_raw=a.keep_raw, all_tabs=a.all_tabs, verbose=a.verbose,
        show_demo_banner=a.show_demo_banner, readme_metrics=a.readme_metrics,
        display_origin=a.display_origin, extras_only=a.extras_only, curate=a.curate)


def media_path_for(cfg: Config) -> str:
    if cfg.readme_media_path:
        return cfg.readme_media_path.rstrip("/")
    assert cfg.readme is not None
    return Path(os.path.relpath(cfg.out, cfg.readme.parent)).as_posix()


def main(argv: list[str] | None = None) -> int:
    cfg = parse_args(argv)
    metrics_file = METRICS_FILE if cfg.readme_metrics else None
    if cfg.curate:
        manifest = curate(cfg.out)
        if cfg.readme:
            update_readme(cfg.readme, manifest, media_path_for(cfg), metrics_file)
        return 0
    if cfg.gallery_only:
        if not cfg.readme:
            sys.exit("--gallery-only needs --readme")
        mf = cfg.out / "manifest.json"
        manifest = json.loads(mf.read_text()) if mf.exists() else None
        if manifest is None:
            log(f"{mf} not found: gallery left as it is", "warn")
        return 0 if update_readme(cfg.readme, manifest, media_path_for(cfg), metrics_file) else 1
    cfg.out.mkdir(parents=True, exist_ok=True)
    log(f"capturing {cfg.base_url} -> {cfg.out}", "step")
    cap = Capture(cfg)
    cap.tmp = Path(tempfile.mkdtemp(prefix=".capture-", dir=cfg.out))
    try:
        cap.pick_targets()
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not cfg.headed)
            try:
                if not cfg.video_only and not cfg.extras_only:
                    cap.capture_desktop(browser)
                    if any(cap.want(n) for n in ("dark-overview", "dark-report", "dark-analytics")):
                        cap.capture_dark(browser)
                    if any(cap.want(n) for n in ("mobile-overview", "mobile-report")):
                        cap.capture_mobile(browser)
                if not cfg.video_only:
                    cap.capture_extras(browser)
                if not cfg.skip_video and (cap.want("demo") or cfg.video_only):
                    cap.record_video(browser)
            finally:
                browser.close()
    finally:
        manifest = cap.write_manifest()
        shutil.rmtree(cap.tmp, ignore_errors=True)
    if cfg.readme:
        update_readme(cfg.readme, manifest, media_path_for(cfg), metrics_file)
    total = sum(f["bytes"] for f in manifest["files"])
    log(f"done: {len(manifest['files'])} files, {human(total)} in {cfg.out}", "step")
    for title, key, level in (("skipped (optional, not in this build):", "skipped", "info"),
                              ("not captured:", "failed", "warn")):
        if manifest.get(key):
            log(title, level)
            for f in manifest[key]:
                log(f"   {f['name']}: {f['reason']}", level)
    return 0 if manifest["files"] else 1


if __name__ == "__main__":
    sys.exit(main())
