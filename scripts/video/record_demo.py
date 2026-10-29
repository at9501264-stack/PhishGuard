#!/usr/bin/env python3
"""Record the narrated PhishGuard demo video from ``scripts/video/scenes.json``.

Pipeline
  1. Narration: one macOS ``say`` clip per scene (default voice Rishi, en_IN), converted to WAV, duration via ffprobe.
  2. Recording: headless Playwright Chromium (1440x900, record_video_dir) walks the real app scene by scene and
     runs the actions DSL (goto, scroll, click_text, type, press, wait_for_text, wait, highlight, title_card).
     A caption bar (scene title + caption), a fake cursor, pulsing highlights and full-screen title cards are
     injected into the page, so the video explains itself even without sound. Every scene stays on screen for
     max(narration + 0.5 s, min_seconds); waits inside a scene stretch or shrink to fit that window.
  3. Post: the WAV clips are placed at the real scene start times (adelay + amix + loudnorm) and muxed with the
     recording into ``docs/media/demo.mp4`` (H.264 + AAC, faststart). Also writes ``demo.srt`` (captions with real
     timings), ``demo-poster.png`` and ``demo-preview.gif`` (scan -> report -> analytics highlights).

Run it against your own servers (never the ports 8000/5173 you use day to day), on a copy of the database:

    backend/.venv/bin/python scripts/video/record_demo.py \
        --base-url http://localhost:5295 --api-url http://localhost:8095 --work /tmp/pg-video

    # rebuild mp4 / srt / gif / poster from an earlier recording in --work, without recording again
    backend/.venv/bin/python scripts/video/record_demo.py --work /tmp/pg-video --post-only

Route tokens in scenes.json: ``:latest`` = the scan created by the "scan" scene (read from the URL the Scan page
navigates to), ``:phishing`` = highest-risk phishing scan, ``:legit`` = newest Trusted legitimate scan of github.com.
A failing action is logged and skipped; it never aborts the video.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCENES = ROOT / "scripts" / "video" / "scenes.json"
OUT_DIR = ROOT / "docs" / "media"
FFMPEG = shutil.which("ffmpeg") or "/opt/homebrew/bin/ffmpeg"
FFPROBE = shutil.which("ffprobe") or "/opt/homebrew/bin/ffprobe"

W, H = 1440, 900
AUDIO_LEAD = 0.10          # narration starts this long after the scene starts
SCENE_PAD = 0.50           # silence kept after each narration clip
PAYPAL_URL = "http://paypal-login-verify.secure-account.xyz/update"

FAILURES: list[str] = []


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def fail(scene: str, what: str, err: Exception | str) -> None:
    line = f"{scene}: {what}: {str(err).splitlines()[0][:200]}"
    FAILURES.append(line)
    log("FAILED " + line)


def run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def probe_duration(path: Path) -> float:
    out = run([FFPROBE, "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)]).stdout
    return float(out.strip())


# --------------------------------------------------------------------------------------------- narration (TTS)

def pick_voice(preferred: str | None) -> str:
    voices = run(["say", "-v", "?"]).stdout
    names = {line.split("  ")[0].strip() for line in voices.splitlines() if line.strip()}
    for v in ([preferred] if preferred else []) + ["Rishi", "Samantha", "Daniel"]:
        if v in names:
            return v
    return "Samantha"


def make_narration(scenes: list[dict], work: Path, voice: str, rate: int) -> None:
    adir = work / "audio"
    adir.mkdir(parents=True, exist_ok=True)
    for i, s in enumerate(scenes, 1):
        base = adir / f"{i:02d}-{s['id']}"
        aiff, wav = base.with_suffix(".aiff"), base.with_suffix(".wav")
        run(["say", "-v", voice, "-r", str(rate), "-o", str(aiff), s["narration"]])
        run([FFMPEG, "-y", "-v", "error", "-i", str(aiff), "-ar", "48000", "-ac", "1", str(wav)])
        s["audio"] = str(wav)
        s["audio_s"] = round(probe_duration(wav), 3)
        s["hold_s"] = round(max(s["audio_s"] + SCENE_PAD, float(s.get("min_seconds", 0))), 3)
    total = sum(s["hold_s"] for s in scenes)
    log(f"narration: voice={voice} rate={rate} speech={sum(s['audio_s'] for s in scenes):.1f}s planned={total:.1f}s")


# --------------------------------------------------------------------------------------------- API helpers

def api_get(api: str, path: str, **params: Any) -> Any:
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    with urllib.request.urlopen(f"{api}{path}{'?' + q if q else ''}", timeout=20) as r:
        return json.loads(r.read().decode())


def resolve_tokens(api: str) -> dict[str, int | None]:
    tok: dict[str, int | None] = {"phishing": None, "legit": None}
    try:
        items = api_get(api, "/api/scans", verdict="phishing", sort="risk_score", order="desc", page_size=1)["items"]
        tok["phishing"] = items[0]["id"] if items else None
    except Exception as e:  # noqa: BLE001
        fail("tokens", ":phishing", e)
    try:
        items = api_get(api, "/api/scans", q="github.com", verdict="legitimate", tier="Trusted", page_size=25)["items"]
        exact = [i for i in items if i["url"].rstrip("/") in ("https://github.com", "http://github.com")]
        pick = exact or items
        if not pick:
            pick = api_get(api, "/api/scans", verdict="legitimate", tier="Trusted", page_size=1)["items"]
        tok["legit"] = pick[0]["id"] if pick else None
    except Exception as e:  # noqa: BLE001
        fail("tokens", ":legit", e)
    log(f"tokens: {tok}")
    return tok


def latest_paypal_scan(api: str) -> int | None:
    try:
        items = api_get(api, "/api/scans", q="paypal-login-verify.secure-account.xyz", sort="created_at",
                        order="desc", page_size=1)["items"]
        return items[0]["id"] if items else None
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------------------------- injected overlay

OVERLAY_JS = r"""
(() => {
  if (window.__pg) return;
  const css = `
  #pg-cap{position:fixed;left:248px;right:24px;bottom:18px;z-index:2147483600;pointer-events:none;
    display:flex;align-items:center;gap:18px;padding:13px 22px;border-radius:14px;
    background:rgba(15,14,38,.88);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);
    box-shadow:0 10px 30px rgba(0,0,0,.28),inset 0 0 0 1px rgba(255,255,255,.08);
    font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#fff;
    transition:opacity .45s ease,transform .45s ease}
  #pg-cap.pg-hide{opacity:0;transform:translateY(16px)}
  #pg-cap .pg-num{flex:none;display:grid;place-items:center;width:38px;height:38px;border-radius:10px;
    background:linear-gradient(135deg,#6366f1,#8b5cf6);font-weight:700;font-size:15px;letter-spacing:.02em}
  #pg-cap .pg-body{min-width:0;flex:1;transition:opacity .3s ease}
  #pg-cap .pg-title{font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#a5b4fc;margin-bottom:3px}
  #pg-cap .pg-text{font-size:19px;line-height:1.3;font-weight:500;color:#f8fafc}
  #pg-cap .pg-brand{flex:none;font-size:12px;font-weight:600;color:#c7d2fe;opacity:.8;text-align:right;line-height:1.35}
  #pg-card{position:fixed;inset:0;z-index:2147483640;pointer-events:none;opacity:0;transition:opacity .7s ease;
    display:flex;align-items:center;justify-content:center;
    background:radial-gradient(1200px 700px at 20% 15%,rgba(129,140,248,.35),transparent 60%),
      radial-gradient(900px 600px at 85% 90%,rgba(168,85,247,.30),transparent 60%),
      linear-gradient(135deg,#0b0a24 0%,#1e1b4b 45%,#312e81 100%);
    font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#fff}
  #pg-card.pg-show{opacity:1}
  #pg-card::before{content:"";position:absolute;inset:0;opacity:.18;
    background-image:linear-gradient(rgba(255,255,255,.12) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.12) 1px,transparent 1px);
    background-size:48px 48px;mask-image:radial-gradient(ellipse at center,#000 30%,transparent 75%);
    -webkit-mask-image:radial-gradient(ellipse at center,#000 30%,transparent 75%)}
  #pg-card .pg-inner{position:relative;max-width:1260px;padding:0 70px;text-align:center;transition:opacity .35s ease,transform .35s ease}
  #pg-card .pg-inner.pg-swap{opacity:0;transform:translateY(10px)}
  #pg-card .pg-eyebrow{display:inline-flex;align-items:center;gap:10px;padding:7px 16px;border-radius:999px;
    background:rgba(255,255,255,.08);box-shadow:inset 0 0 0 1px rgba(255,255,255,.14);
    font-size:15px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:#c7d2fe}
  #pg-card h1{margin:26px 0 22px;font-size:76px;line-height:1.05;font-weight:800;letter-spacing:-.02em;
    background:linear-gradient(180deg,#fff 30%,#c7d2fe);-webkit-background-clip:text;background-clip:text;color:transparent}
  #pg-card .pg-rule{width:88px;height:4px;margin:0 auto 26px;border-radius:4px;background:linear-gradient(90deg,#818cf8,#c084fc)}
  #pg-card p{margin:10px 0;font-size:24px;line-height:1.45;color:#e0e7ff;font-weight:450;text-wrap:balance}
  #pg-card p:first-of-type{color:#fff;font-weight:600}
  .pg-hl{position:fixed;z-index:2147483500;pointer-events:none;border-radius:12px;
    box-shadow:0 0 0 3px rgba(245,158,11,.95),0 0 0 9px rgba(245,158,11,.22),0 0 28px 6px rgba(245,158,11,.35);
    animation:pgPulse 1.1s ease-in-out infinite;transition:opacity .35s ease}
  @keyframes pgPulse{0%,100%{box-shadow:0 0 0 3px rgba(245,158,11,.95),0 0 0 9px rgba(245,158,11,.22),0 0 24px 4px rgba(245,158,11,.30)}
    50%{box-shadow:0 0 0 3px rgba(245,158,11,1),0 0 0 14px rgba(245,158,11,.10),0 0 36px 10px rgba(245,158,11,.40)}}
  #pg-cursor{position:fixed;left:0;top:0;z-index:2147483620;pointer-events:none;width:20px;height:20px;margin:-10px 0 0 -10px;
    border-radius:50%;background:rgba(99,102,241,.22);border:2.5px solid #4f46e5;box-shadow:0 2px 10px rgba(0,0,0,.30);
    transition:transform .55s cubic-bezier(.22,.8,.3,1),opacity .3s ease;opacity:0}
  .pg-ripple{position:fixed;z-index:2147483610;pointer-events:none;width:16px;height:16px;margin:-8px 0 0 -8px;border-radius:50%;
    border:3px solid rgba(79,70,229,.85);animation:pgRipple .6s ease-out forwards}
  @keyframes pgRipple{from{transform:scale(.6);opacity:1}to{transform:scale(3.4);opacity:0}}
  `;
  const st = document.createElement('style'); st.id = 'pg-style'; st.textContent = css;
  document.documentElement.appendChild(st);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const cap = document.createElement('div'); cap.id = 'pg-cap'; cap.className = 'pg-hide';
  cap.innerHTML = '<div class="pg-num"></div><div class="pg-body"><div class="pg-title"></div><div class="pg-text"></div></div>' +
                  '<div class="pg-brand">PhishGuard<br>demo</div>';
  const card = document.createElement('div'); card.id = 'pg-card';
  card.innerHTML = '<div class="pg-inner"></div>';
  const cur = document.createElement('div'); cur.id = 'pg-cursor';
  document.body.append(cap, card, cur);
  let hl = null, hlTimer = null, hlRaf = null;
  window.__pg = {
    caption(num, title, text) {
      const body = cap.querySelector('.pg-body');
      body.style.opacity = '0';
      setTimeout(() => {
        cap.querySelector('.pg-num').textContent = num;
        cap.querySelector('.pg-title').textContent = title;
        cap.querySelector('.pg-text').textContent = text;
        body.style.opacity = '1';
      }, cap.classList.contains('pg-hide') ? 0 : 220);
    },
    showCaption(on) { cap.classList.toggle('pg-hide', !on); },
    card(heading, sub, eyebrow, instant) {
      const inner = card.querySelector('.pg-inner');
      const html = `<div class="pg-eyebrow">${esc(eyebrow || 'PhishGuard')}</div><h1>${esc(heading)}</h1><div class="pg-rule"></div>` +
        String(sub || '').split('\n').filter(Boolean).map((l) => `<p>${esc(l)}</p>`).join('');
      const shown = card.classList.contains('pg-show');
      if (instant) { card.style.transition = 'none'; inner.innerHTML = html; card.classList.add('pg-show');
        void card.offsetHeight; card.style.transition = ''; return; }
      if (shown) { inner.classList.add('pg-swap'); setTimeout(() => { inner.innerHTML = html; inner.classList.remove('pg-swap'); }, 380); }
      else { inner.innerHTML = html; card.classList.add('pg-show'); }
    },
    hideCard() { card.classList.remove('pg-show'); },
    cardShown() { return card.classList.contains('pg-show'); },
    highlight(el, ms, self) {
      this.clearHighlight();
      let target = el;
      const vw = innerWidth, vh = innerHeight;
      if (!self) for (let i = 0, n = el; i < 6 && n && n !== document.body && n.tagName !== 'MAIN'; i++, n = n.parentElement) {
        const cs = getComputedStyle(n), r = n.getBoundingClientRect();
        if (r.width * r.height > vw * vh * 0.62) break;
        const bordered = parseFloat(cs.borderTopWidth) > 0 || (cs.boxShadow && cs.boxShadow !== 'none') ||
                         (cs.backgroundColor && cs.backgroundColor !== 'rgba(0, 0, 0, 0)' && parseFloat(cs.borderRadius) > 0);
        if (bordered && r.width > 40) { target = n; break; }
      }
      hl = document.createElement('div'); hl.className = 'pg-hl'; document.body.appendChild(hl);
      const place = () => {
        if (!hl) return;
        const r = target.getBoundingClientRect(), pad = 6;
        const top = Math.max(r.top - pad, 62), bottom = Math.min(r.bottom + pad, vh - 6);
        hl.style.visibility = (r.bottom < 90 || r.top > vh - 40) ? 'hidden' : 'visible';
        hl.style.left = (r.left - pad) + 'px'; hl.style.top = top + 'px';
        hl.style.width = (r.width + 2 * pad) + 'px'; hl.style.height = Math.max(bottom - top, 10) + 'px';
        hlRaf = requestAnimationFrame(place);
      };
      place();
      hlTimer = setTimeout(() => this.clearHighlight(), ms || 2600);
    },
    clearHighlight() {
      if (hlTimer) clearTimeout(hlTimer); if (hlRaf) cancelAnimationFrame(hlRaf);
      if (hl) { const h = hl; h.style.opacity = '0'; setTimeout(() => h.remove(), 400); }
      hl = null; hlTimer = null; hlRaf = null;
    },
    cursor(x, y) { cur.style.opacity = '1'; cur.style.transform = `translate(${x}px, ${y}px)`;
      clearTimeout(this._ct); this._ct = setTimeout(() => { cur.style.opacity = '0'; }, 1900); },
    hideCursor() { cur.style.opacity = '0'; },
    ripple(x, y) { const r = document.createElement('div'); r.className = 'pg-ripple'; r.style.left = x + 'px'; r.style.top = y + 'px';
      document.body.appendChild(r); setTimeout(() => r.remove(), 700); },
    async smoothScroll(to, ms) {
      const start = scrollY, max = document.documentElement.scrollHeight - innerHeight;
      const end = to === 'top' ? 0 : to === 'bottom' ? max : Math.max(0, Math.min(Number(to), max));
      const t0 = performance.now(), d = ms || 900;
      await new Promise((res) => { const step = (t) => { const k = Math.min(1, (t - t0) / d);
        const e = k < .5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;
        scrollTo(0, start + (end - start) * e); k < 1 ? requestAnimationFrame(step) : res(); }; requestAnimationFrame(step); });
    },
  };
})();
"""


# --------------------------------------------------------------------------------------------- recorder

class Recorder:
    def __init__(self, page, base: str, api: str):
        self.page = page
        self.base = base.rstrip("/")
        self.api = api
        self.inflight: set = set()
        self.cursor_xy = (W * 0.6, H * 0.55)
        page.on("request", self._req)
        page.on("requestfinished", self._done)
        page.on("requestfailed", self._done)

    # network tracking (only /api/ calls count as "page still loading")
    def _req(self, r) -> None:
        if "/api/" in r.url:
            self.inflight.add(r)

    def _done(self, r) -> None:
        self.inflight.discard(r)

    def sleep(self, s: float) -> None:
        if s > 0:
            self.page.wait_for_timeout(int(s * 1000))

    def wait_loaded(self, timeout: float = 10.0) -> None:
        p = self.page
        end, quiet = time.time() + timeout, None
        while time.time() < end:
            if not self.inflight:
                quiet = quiet or time.time()
                if time.time() - quiet > 0.35:
                    break
            else:
                quiet = None
            p.wait_for_timeout(50)
        try:
            p.wait_for_function("() => !document.querySelector('main .animate-pulse')", timeout=8000)
        except Exception:  # noqa: BLE001
            log("  (skeleton still visible after 8 s)")
        self.ensure_overlay()

    def ensure_overlay(self) -> None:
        self.page.evaluate(OVERLAY_JS)

    def path(self) -> str:
        return self.page.evaluate("location.pathname + location.search")

    def goto(self, path: str, force: bool = False, timeout: float = 10.0) -> None:
        p = self.page
        if not force and p.url.startswith(self.base) and self.path() == path:
            return
        if not p.url.startswith(self.base) or force:
            p.goto(self.base + path, wait_until="domcontentloaded")
        else:  # client-side navigation: no reload, overlays and caches survive
            p.evaluate("""(u) => { history.pushState({}, '', u); dispatchEvent(new PopStateEvent('popstate', {state: {}}));
                                   scrollTo(0, 0); }""", path)
        self.wait_loaded(timeout)
        if re.match(r"^/scans/\d+", path):
            # the report component is reused between scan ids and keeps its active tab: start on Summary
            p.evaluate("""() => { const b = [...document.querySelectorAll('[data-report-tabs] button')]
                                     .find((e) => /^\\s*Summary/.test(e.textContent || ''));
                                   if (b && !/indigo-50/.test(b.className)) b.click(); scrollTo(0, 0); }""")
            p.wait_for_timeout(150)

    def prefetch(self, routes: list[str], until: float, back_to: str) -> None:
        """Visit routes under an opaque title card so React Query caches their data (no skeletons on camera)."""
        while routes and time.time() < until - 1.5:
            r = routes.pop(0)
            try:
                self.goto(r, timeout=min(6.0, max(1.0, until - time.time() - 1.2)))
            except Exception as e:  # noqa: BLE001
                log(f"  prefetch {r}: {e}")
        try:
            self.goto(back_to)
        except Exception as e:  # noqa: BLE001
            log(f"  prefetch back to {back_to}: {e}")

    # element lookup -------------------------------------------------------------------------------------------
    def find_text(self, text: str, exact: bool = False, scope: str | None = None):
        p = self.page
        roots = [p.locator(scope)] if scope else [p.locator("main"), p]
        for root in roots:
            loc = root.get_by_text(text, exact=exact)
            try:
                n = min(loc.count(), 12)
            except Exception:  # noqa: BLE001
                continue
            for i in range(n):
                el = loc.nth(i)
                try:
                    if el.is_visible():
                        return el
                except Exception:  # noqa: BLE001
                    pass
        return None

    def find_clickable(self, text: str, match: str = "contains", scope: str | None = None):
        p = self.page
        root = p.locator(scope) if scope else p
        cands = []
        if match == "exact":
            for role in ("button", "tab", "link"):
                cands.append(root.get_by_role(role, name=text, exact=True))
        rx = re.compile(r"^\s*" + re.escape(text), re.I) if match == "prefix" else re.compile(re.escape(text), re.I)
        if match == "exact":
            rx = re.compile(r"^\s*" + re.escape(text) + r"\s*$", re.I)
        cands.append(root.locator("button, [role=tab], a, [role=button]").filter(has_text=rx))
        cands.append(root.get_by_text(text, exact=(match == "exact")))
        for loc in cands:
            try:
                n = min(loc.count(), 10)
            except Exception:  # noqa: BLE001
                continue
            for i in range(n):
                el = loc.nth(i)
                try:
                    if el.is_visible():
                        return el
                except Exception:  # noqa: BLE001
                    pass
        return None

    def bring_into_view(self, el) -> None:
        box = el.bounding_box()
        if not box:
            return
        top_ok, bottom_ok = box["y"] >= 70, box["y"] + min(box["height"], 420) <= H - 110
        if top_ok and bottom_ok:
            return
        y = self.page.evaluate("scrollY") + box["y"] - (H * 0.28)
        self.page.evaluate("(y) => window.__pg.smoothScroll(y, 750)", max(0, y))
        self.sleep(0.15)

    def park_mouse(self) -> None:
        """Move the real (invisible) mouse to an empty corner so no hover tooltips or hover styles linger."""
        try:
            self.page.mouse.move(W - 6, 70)
        except Exception:  # noqa: BLE001
            pass

    def move_cursor(self, el, field: bool = False) -> tuple[float, float] | None:
        box = el.bounding_box()
        if not box:
            return None
        if field:   # text fields: park the cursor near the right end so the typed text stays readable
            x, y = box["x"] + box["width"] - 28, box["y"] + min(box["height"] / 2, 22)
        else:       # buttons / tabs: lower-right of the label
            x, y = box["x"] + box["width"] * 0.78, box["y"] + box["height"] * 0.72
        self.page.evaluate("([x, y]) => window.__pg.cursor(x, y)", [x, y])
        self.sleep(0.6)
        self.cursor_xy = (x, y)
        return x, y

    # actions --------------------------------------------------------------------------------------------------
    def act(self, sid: str, a: dict, deadline: float, rest_wait_ms: float, rest_other: float) -> None:
        p, do = self.page, a.get("do")
        if do == "wait":
            budget = deadline - time.time() - rest_other
            k = max(0.15, min(2.5, budget / max(rest_wait_ms / 1000.0, 0.001)))
            self.sleep(a.get("ms", 1000) / 1000.0 * k)
        elif do == "title_card":
            p.evaluate("([h, s]) => { window.__pg.showCaption(false); window.__pg.hideCursor(); window.__pg.card(h, s, 'PhishGuard'); }",
                       [a.get("heading", ""), a.get("sub", "")])
        elif do == "goto":
            self.goto(a["path"])
        elif do == "scroll":
            to = a.get("to", 0)
            p.evaluate("() => window.__pg.clearHighlight()")
            p.evaluate("(t) => window.__pg.smoothScroll(t, 900)", to)
        elif do == "wait_for_text":
            loc = p.get_by_text(a["text"], exact=a.get("match") == "exact").first
            loc.wait_for(state="visible", timeout=a.get("timeout_ms", 8000))
            if a.get("timeout_ms", 0) > 10000:   # long waits (scan) end with a page change
                self.wait_loaded()
        elif do == "highlight":
            el = self.find_text(a["text"], exact=a.get("match") == "exact", scope=a.get("scope"))
            if el is None:
                raise RuntimeError(f"text not found: {a['text']!r}")
            self.bring_into_view(el)
            el.evaluate("(e, [ms, self]) => window.__pg.highlight(e, ms, self)", [a.get("ms", 2600), bool(a.get("self"))])
        elif do == "click_text":
            el = self.find_clickable(a["text"], a.get("match", "contains"), a.get("scope"))
            if el is None:
                raise RuntimeError(f"clickable not found: {a['text']!r}")
            self.bring_into_view(el)
            xy = self.move_cursor(el)
            if xy:
                p.evaluate("([x, y]) => window.__pg.ripple(x, y)", list(xy))
            el.click(timeout=5000)
            self.park_mouse()
            self.sleep(0.25)
            self.wait_loaded(6)
        elif do == "type":
            sel = a["selector"]
            loc = p.locator(sel).first if re.match(r"^(textarea|input|select|[#.\[])", sel) else p.get_by_placeholder(sel).first
            loc.wait_for(state="visible", timeout=6000)
            self.bring_into_view(loc)
            xy = self.move_cursor(loc, field=True)
            if xy:
                p.evaluate("([x, y]) => window.__pg.ripple(x, y)", list(xy))
            loc.click()
            self.park_mouse()
            loc.fill("")
            loc.press_sequentially(a["text"], delay=a.get("delay_ms", 32))
        elif do == "press":
            p.keyboard.press(a["key"])
        else:
            raise RuntimeError(f"unknown action {do!r}")

    @staticmethod
    def est_cost(a: dict) -> float:
        do = a.get("do")
        return {"highlight": 0.25, "click_text": 1.2, "wait_for_text": 0.3, "scroll": 1.0, "goto": 1.0,
                "press": 0.1, "title_card": 0.05}.get(do, 0.0) + (len(a.get("text", "")) * 0.04 + 0.9 if do == "type" else 0)


def resolve_route(route: str, tok: dict, rec: Recorder) -> str:
    if ":latest" in route:
        m = re.match(r"^/scans/(\d+)", rec.path())
        sid = m.group(1) if m else (latest_paypal_scan(rec.api) or tok.get("latest"))
        tok["latest"] = int(sid) if sid else None
        route = route.replace(":latest", str(sid))
    if ":phishing" in route:
        route = route.replace(":phishing", str(tok["phishing"]))
    if ":legit" in route:
        route = route.replace(":legit", str(tok["legit"]))
    return route


def record(scenes: list[dict], args, work: Path) -> dict:
    from playwright.sync_api import sync_playwright

    vdir = work / "raw"
    shutil.rmtree(vdir, ignore_errors=True)
    vdir.mkdir(parents=True)
    tok = resolve_tokens(args.api_url)
    base = args.base_url.rstrip("/")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        # warm-up pass: compiles every Vite module and fills server caches, so nothing loads slowly on camera
        log("warm-up pass")
        wctx = browser.new_context(viewport={"width": W, "height": H}, color_scheme="light")
        wp = wctx.new_page()
        # (typosquat is left to the prefetch under the title cards: each visit runs a live DNS sweep and logs an activity)
        warm = {"/", "/scan", "/bulk", "/graph", "/watchlist", "/feeds", "/activity", "/settings", "/api-guide"}
        for s in scenes:
            r = s["route"]
            if ":latest" in r:
                continue
            warm.add(r.replace(":phishing", str(tok["phishing"])).replace(":legit", str(tok["legit"])))
        for r in sorted(warm):
            try:
                wp.goto(base + r, wait_until="networkidle", timeout=30000)
                wp.wait_for_timeout(600)
            except Exception as e:  # noqa: BLE001
                log(f"  warm-up {r}: {e}")
        wctx.close()

        ctx = browser.new_context(viewport={"width": W, "height": H}, device_scale_factor=1, color_scheme="light",
                                  record_video_dir=str(vdir), record_video_size={"width": W, "height": H})
        page = ctx.new_page()
        t0 = time.time()
        rec = Recorder(page, base, args.api_url)
        rec.goto("/", force=True)
        first = scenes[0]
        tc = next((a for a in first["actions"] if a.get("do") == "title_card"), None)
        if tc:
            page.evaluate("([h, s]) => window.__pg.card(h, s, 'PhishGuard', true)", [tc["heading"], tc.get("sub", "")])
        rec.sleep(0.6)

        timeline = []
        # routes visited under the opening title cards, slowest first (typosquat resolves DNS live)
        queue = ["/typosquat?domain=paypal.com", "/graph", f"/scans/{tok['phishing']}", f"/scans/{tok['legit']}",
                 "/analytics", "/model", "/feeds", "/history?tier=Untrusted", "/watchlist", "/community", "/alerts",
                 "/activity", "/settings", "/api-guide", "/bulk", "/scan"]
        for i, s in enumerate(scenes, 1):
            sid = s["id"]
            start = time.time()
            deadline = start + s["hold_s"]
            log(f"scene {i:02d} {sid} (hold {s['hold_s']:.1f}s)")
            is_card = any(a.get("do") == "title_card" for a in s["actions"])
            try:
                route = resolve_route(s["route"], tok, rec)
                if not is_card:
                    rec.goto(route)
                    page.evaluate("() => window.__pg.clearHighlight()")
                    if page.evaluate("() => window.__pg.cardShown()"):
                        page.evaluate("() => window.__pg.hideCard()")
                    page.evaluate("([n, t, c]) => { window.__pg.caption(n, t, c); window.__pg.showCaption(true); }",
                                  [f"{i:02d}", s["title"], s.get("caption", "")])
            except Exception as e:  # noqa: BLE001
                fail(sid, f"route {s['route']}", e)
            acts = s["actions"]
            for j, a in enumerate(acts):
                if a.get("do") == "title_card" and queue:
                    if i > 1:
                        rec.act(sid, a, deadline, 0, 0)
                    nxt = next((x for x in scenes[i:] if not any(y.get("do") == "title_card" for y in x["actions"])), None)
                    back = nxt["route"] if nxt and ":" not in nxt["route"] else rec.path()
                    rec.prefetch(queue, deadline - 0.4, back)
                    continue
                if i == 1 and a.get("do") == "title_card":
                    continue   # already on screen
                rest = acts[j + 1:]
                rest_wait = sum(x.get("ms", 1000) for x in acts[j:] if x.get("do") == "wait")
                rest_other = sum(Recorder.est_cost(x) for x in rest)
                try:
                    rec.act(sid, a, deadline, rest_wait, rest_other)
                except Exception as e:  # noqa: BLE001
                    if a.get("optional"):
                        log(f"  skipped optional {a.get('do')} {a.get('text', '')!r}: {str(e).splitlines()[0][:80]}")
                        continue
                    fail(sid, f"{a.get('do')} {a.get('text') or a.get('path') or a.get('selector') or ''}".strip(), e)
                    try:
                        rec.ensure_overlay()
                    except Exception:  # noqa: BLE001
                        pass
            left = deadline - time.time()
            if left > 0:
                rec.sleep(left)
            end = time.time()
            if end - deadline > 0.3:
                log(f"  overran by {end - deadline:.1f}s")
            timeline.append({"id": sid, "title": s["title"], "start": round(start - t0, 3), "end": round(end - t0, 3),
                             "audio": s["audio"], "audio_s": s["audio_s"], "route": rec.path()})
        rec.sleep(0.8)
        t_end = time.time() - t0
        page.evaluate("() => window.__pg && window.__pg.clearHighlight()")
        video = page.video
        ctx.close()
        raw = Path(video.path())
        browser.close()

    data = {"raw_video": str(raw), "t_end": round(t_end, 3), "scenes": timeline, "tokens": tok,
            "failures": FAILURES, "voice": args.voice, "rate": args.rate}
    (work / "timeline.json").write_text(json.dumps(data, indent=2))
    return data


# --------------------------------------------------------------------------------------------- post-production

def build_mp4(data: dict, out: Path, work: Path) -> dict:
    scenes = data["scenes"]
    trim = scenes[0]["start"]
    total = round(data["t_end"] - trim, 3)
    inputs, filters, labels = [], [], []
    for k, s in enumerate(scenes):
        inputs += ["-i", s["audio"]]
        delay = int(round((s["start"] - trim + AUDIO_LEAD) * 1000))
        filters.append(f"[{k}:a]adelay={delay}:all=1[a{k}]")
        labels.append(f"[a{k}]")
    filters.append("".join(labels) + f"amix=inputs={len(labels)}:normalize=0:dropout_transition=0,"
                   "loudnorm=I=-16:TP=-1.5:LRA=11,aresample=48000,"
                   f"apad,atrim=0:{total},afade=t=out:st={max(total - 0.8, 0):.2f}:d=0.8[aout]")
    narr = work / "narration.wav"
    run([FFMPEG, "-y", "-v", "error", *inputs, "-filter_complex", ";".join(filters), "-map", "[aout]",
         "-ac", "2", "-ar", "48000", str(narr)])

    def encode(width: int, height: int) -> None:
        vf = (f"fps=25,scale={width}:{height}:flags=lanczos,format=yuv420p,"
              f"fade=t=in:st=0:d=0.6,fade=t=out:st={max(total - 0.8, 0):.2f}:d=0.8")
        run([FFMPEG, "-y", "-v", "error", "-ss", f"{trim:.3f}", "-i", data["raw_video"], "-i", str(narr),
             "-map", "0:v:0", "-map", "1:a:0", "-t", f"{total:.3f}", "-vf", vf,
             "-c:v", "libx264", "-preset", "medium", "-crf", "26", "-pix_fmt", "yuv420p",
             "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart", str(out)])

    encode(W, H)
    size = out.stat().st_size
    if size > 40 * 1024 * 1024:
        log(f"{size / 1e6:.1f} MB > 40 MB, re-encoding at 1280x800")
        encode(1280, 800)
    return {"trim": trim, "total": total}


SPOKEN_TO_TEXT = [
    ("Mister Vishal Gupta", "Mr. Vishal Gupta"), ("who-is", "WHOIS"), ("forty-four", "44"),
    ("ninety-two out of a hundred", "92 out of 100"), ("trust score eight", "trust score 8"),
    ("sixty-forty", "60/40"), ("vercel dot app", "vercel.app"), ("github dot com", "github.com"),
    ("three of eleven", "3 of 11"), ("Three of eleven", "3 of 11"), ("risk three", "risk 3"),
    ("ninety-seven", "97"), ("five hundred", "500"), ("one hundred forty-six thousand", "146,000"),
    ("eighty-six percent", "86%"), ("A U C of zero point nine four", "AUC of 0.94"),
    ("six hundred fifty-seven thousand", "657,000"), ("Fast API", "FastAPI"), ("S Q Lite", "SQLite"),
]


def to_display(s: str) -> str:
    for a, b in SPOKEN_TO_TEXT:
        s = s.replace(a, b)
    return s


def split_chunks(text: str, limit: int = 84) -> list[str]:
    """Sentence-level cues; a sentence longer than two subtitle lines is split at the most balanced comma,
    or else before a joining word (and, by, with, ...) near its middle."""
    out: list[str] = []
    for sent in re.split(r"(?<=[.!?])\s+", text.strip()):
        out += _split_sentence(sent.strip(), limit)
    return [c for c in out if c]


def _split_sentence(sent: str, limit: int) -> list[str]:
    if len(sent) <= limit:
        return [sent]
    cuts = [m.end() for m in re.finditer(r"[,:]\s", sent)]
    best = min(cuts, key=lambda c: max(c, len(sent) - c)) if cuts else None
    if best is None or max(best, len(sent) - best) > limit:
        joins = [m.start() + 1 for m in re.finditer(r"\s(?:and|by|with|while|from|to|like|on|for)\s", sent)]
        spaces = joins or [m.start() + 1 for m in re.finditer(r"\s", sent)]
        alt = min(spaces, key=lambda c: max(c, len(sent) - c)) if spaces else None
        if alt is not None and (best is None or max(alt, len(sent) - alt) < max(best, len(sent) - best)):
            best = alt
    if best is None:
        return [sent]
    return _split_sentence(sent[:best].strip(), limit) + _split_sentence(sent[best:].strip(), limit)


def wrap2(s: str, width: int = 44) -> str:
    if len(s) <= width:
        return s
    words, best = s.split(), None
    for k in range(1, len(words)):
        a, b = " ".join(words[:k]), " ".join(words[k:])
        score = max(len(a), len(b))
        if best is None or score < best[0]:
            best = (score, a, b)
    return f"{best[1]}\n{best[2]}" if best else s


def srt_ts(t: float) -> str:
    ms = int(round(t * 1000))
    h, ms = divmod(ms, 3600000)
    m, ms = divmod(ms, 60000)
    s, ms = divmod(ms, 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def build_srt(data: dict, scenes_src: list[dict], out: Path, trim: float) -> int:
    by_id = {s["id"]: s for s in scenes_src}
    cues, n = [], 0
    for s in data["scenes"]:
        spoken = by_id[s["id"]]["narration"]
        chunks = split_chunks(spoken)
        weights = [len(c) for c in chunks]
        t = s["start"] - trim + AUDIO_LEAD
        dur = s["audio_s"]
        for c, wgt in zip(chunks, weights):
            d = dur * wgt / sum(weights)
            n += 1
            cues.append(f"{n}\n{srt_ts(t)} --> {srt_ts(t + d - 0.05)}\n{wrap2(to_display(c))}\n")
            t += d
    out.write_text("\n".join(cues), encoding="utf-8")
    return n


def build_gif(data: dict, mp4: Path, out: Path, work: Path, trim: float) -> None:
    st = {s["id"]: (s["start"] - trim, s["end"] - trim) for s in data["scenes"]}
    # (scene, offset into scene, length): scan -> verdict -> explainability -> analytics -> model lab
    plan = [("scan", 0.8, 6.0), ("verdict", 0.3, 4.6), ("ml-brand", 1.6, 4.4), ("analytics", 0.4, 4.4),
            ("model-lab", 2.2, 3.2)]
    segs = [(st[i][0] + off, min(ln, st[i][1] - st[i][0] - off)) for i, off, ln in plan if i in st]
    inputs, parts = [], []
    for k, (ss, ln) in enumerate(segs):
        inputs += ["-ss", f"{ss:.2f}", "-t", f"{ln:.2f}", "-i", str(mp4)]
        parts.append(f"[{k}:v]fps=10,scale=960:-2:flags=lanczos,setsar=1[v{k}]")
    concat = "".join(f"[v{k}]" for k in range(len(segs))) + f"concat=n={len(segs)}:v=1:a=0[cat]"
    pal = work / "palette.png"
    fc = ";".join(parts + [concat])
    run([FFMPEG, "-y", "-v", "error", *inputs, "-filter_complex",
         fc + ";[cat]palettegen=max_colors=160:stats_mode=diff[p]", "-map", "[p]", str(pal)])
    run([FFMPEG, "-y", "-v", "error", *inputs, "-i", str(pal), "-filter_complex",
         fc + f";[cat][{len(segs)}:v]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle[g]",
         "-map", "[g]", "-loop", "0", str(out)])


POSTER_HTML = """<!doctype html><html><head><meta charset="utf-8"><style>
*{box-sizing:border-box;margin:0}
body{width:1440px;height:900px;overflow:hidden;color:#fff;
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  background:radial-gradient(900px 600px at 12% 10%,rgba(129,140,248,.38),transparent 60%),
    radial-gradient(800px 600px at 95% 100%,rgba(168,85,247,.34),transparent 60%),
    linear-gradient(135deg,#0b0a24 0%,#1e1b4b 48%,#312e81 100%)}
.left{position:absolute;left:84px;top:0;bottom:0;width:560px;display:flex;flex-direction:column;justify-content:center}
.eyebrow{align-self:flex-start;padding:8px 16px;border-radius:999px;background:rgba(255,255,255,.09);
  box-shadow:inset 0 0 0 1px rgba(255,255,255,.16);font-size:15px;font-weight:700;letter-spacing:.12em;
  text-transform:uppercase;color:#c7d2fe}
h1{margin:26px 0 18px;font-size:96px;line-height:1;font-weight:800;letter-spacing:-.025em;
  background:linear-gradient(180deg,#fff 35%,#c7d2fe);-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{font-size:28px;line-height:1.32;font-weight:600;color:#e0e7ff;text-wrap:balance}
.play{margin-top:40px;display:flex;align-items:center;gap:18px}
.btn{flex:none;width:78px;height:78px;border-radius:50%;display:grid;place-items:center;
  background:linear-gradient(135deg,#6366f1,#a855f7);box-shadow:0 12px 34px rgba(99,102,241,.55),0 0 0 8px rgba(255,255,255,.07)}
.play div.t{font-size:20px;line-height:1.45;color:#c7d2fe}.play b{color:#fff;font-weight:650}
.foot{margin-top:44px;font-size:16px;line-height:1.5;color:#a5b4fc}
.shot{position:absolute;left:676px;top:236px;width:720px;border-radius:16px;overflow:hidden;background:#fff;
  box-shadow:0 40px 90px rgba(0,0,0,.55),0 0 0 1px rgba(255,255,255,.14);transform:perspective(2000px) rotateY(-6deg) rotateX(1.5deg);
  transform-origin:left center}
.bar{height:38px;display:flex;align-items:center;gap:8px;padding:0 14px;background:#f4f4f5;border-bottom:1px solid #e4e4e7}
.dot{width:11px;height:11px;border-radius:50%}.url{margin-left:14px;flex:1;height:22px;border-radius:6px;background:#fff;
  box-shadow:inset 0 0 0 1px #e4e4e7;font:600 12px/22px ui-monospace,Menlo,monospace;color:#52525b;padding:0 10px}
.shot img{display:block;width:100%}
.chip{position:absolute;padding:12px 18px;border-radius:14px;font-weight:700;font-size:19px;
  box-shadow:0 18px 40px rgba(0,0,0,.40)}
.c1{left:1060px;top:178px;background:#fff1f2;color:#be123c;box-shadow:0 18px 40px rgba(0,0,0,.40),inset 0 0 0 2px #fecdd3}
.c2{left:636px;top:680px;background:#1e1b4b;color:#e0e7ff;box-shadow:0 18px 40px rgba(0,0,0,.45),inset 0 0 0 1px rgba(255,255,255,.18);
  font-weight:600;font-size:17px}
.c2 b{color:#fff}
</style></head><body>
<div class="left">
  <div class="eyebrow">Narrated demo &middot; __DUR__</div>
  <h1>PhishGuard</h1>
  <div class="sub">AI-Based Phishing Website Detection and Risk Analysis System Using Machine Learning</div>
  <div class="play"><div class="btn"><svg width="32" height="32" viewBox="0 0 24 24"><path d="M8 5.5v13l10.5-6.5z" fill="#fff"/></svg></div>
    <div class="t">Live deep scan &rarr; explainable verdict<br><b>ML + DNS &middot; WHOIS &middot; SSL &middot; content &middot; threat feeds</b></div></div>
  <div class="foot">B.Tech Mini Project &middot; Ayushi Tiwari &middot; Guide: Mr. Vishal Gupta<br>Lloyd Institute of Engineering &amp; Technology (AKTU)</div>
</div>
<div class="shot"><div class="bar"><span class="dot" style="background:#f87171"></span><span class="dot" style="background:#fbbf24"></span>
  <span class="dot" style="background:#34d399"></span><div class="url">PhishGuard &middot; Scan report #__SID__</div></div><img src="data:image/png;base64,__IMG__"></div>
<div class="chip c1">&#9888; Phishing &middot; Risk __RISK__ / 100</div>
<div class="chip c2"><b>Trust score __TRUST__</b> &middot; Tier: __TIER__ &middot; __THREAT__</div>
</body></html>"""


def build_poster(args, data: dict, out: Path, work: Path, duration: float) -> None:
    """Poster: the real report header of the scan made in the video, framed on the title-card gradient."""
    import base64
    from PIL import Image
    from playwright.sync_api import sync_playwright

    sid = data["tokens"].get("latest") or latest_paypal_scan(args.api_url) or data["tokens"].get("phishing")
    scan = api_get(args.api_url, f"/api/scans/{sid}")
    with sync_playwright() as pw:
        b = pw.chromium.launch(headless=True)
        ctx = b.new_context(viewport={"width": W, "height": H}, device_scale_factor=2, color_scheme="light")
        pg = ctx.new_page()
        rec = Recorder(pg, args.base_url, args.api_url)
        rec.goto(f"/scans/{sid}", force=True)
        pg.evaluate("() => document.querySelectorAll('#pg-cap,#pg-card,#pg-cursor,.pg-hl').forEach((e) => e.remove())")
        pg.wait_for_timeout(1500)   # gauge animation
        shot = pg.screenshot(clip={"x": 236, "y": 64, "width": 860, "height": 430})
        mins, secs = divmod(int(round(duration)), 60)
        html = (POSTER_HTML.replace("__IMG__", base64.b64encode(shot).decode()).replace("__SID__", str(sid))
                .replace("__DUR__", f"{mins} min {secs:02d} s").replace("__RISK__", str(scan.get("risk_score")))
                .replace("__TRUST__", f"{scan.get('trust_score')}/100").replace("__TIER__", str(scan.get("tier")))
                .replace("__THREAT__", str(scan.get("threat_type") or "").replace("_", " ").capitalize()))
        pctx = b.new_context(viewport={"width": W, "height": H}, device_scale_factor=1)
        pp = pctx.new_page()
        pp.set_content(html)
        pp.wait_for_timeout(400)
        raw = work / "poster-raw.png"
        pp.screenshot(path=str(raw))
        ctx.close()
        pctx.close()
        b.close()
    img = Image.open(raw).convert("RGB")
    img.save(out, optimize=True)          # full colour if it fits the 400 KB budget ...
    if out.stat().st_size <= 400 * 1024:
        return
    for wd in (1440, 1280, 1120):         # ... else a 256-colour palette biased towards the screenshot,
        im = img if wd == W else img.resize((wd, round(H * wd / W)), Image.LANCZOS)
        k = wd / W                        # so the red gauge / badges keep their colour
        crop = im.crop((round(630 * k), round(170 * k), round(1430 * k), round(730 * k)))
        comp = Image.new("RGB", (im.width, im.height + 3 * crop.height))
        comp.paste(im, (0, 0))
        for j in range(3):
            comp.paste(crop, (0, im.height + j * crop.height))
        pal = comp.quantize(colors=256, method=Image.Quantize.MEDIANCUT)
        im.quantize(palette=pal, dither=Image.Dither.FLOYDSTEINBERG).save(out, optimize=True)
        if out.stat().st_size <= 400 * 1024:
            return


# --------------------------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default="http://localhost:5295", help="frontend (your own dev server)")
    ap.add_argument("--api-url", default="http://localhost:8095", help="backend used for route tokens")
    ap.add_argument("--work", default=str(Path(tempfile.gettempdir()) / "phishguard-video"), help="scratch directory")
    ap.add_argument("--out-dir", default=str(OUT_DIR))
    ap.add_argument("--voice", default="Rishi", help="macOS say voice (falls back to Samantha)")
    ap.add_argument("--rate", type=int, default=220, help="say -r value (Rishi at 220 speaks about 170 wpm)")
    ap.add_argument("--post-only", action="store_true", help="reuse <work>/timeline.json and the raw recording")
    ap.add_argument("--no-poster", action="store_true")
    args = ap.parse_args()

    work, out_dir = Path(args.work), Path(args.out_dir)
    work.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    scenes = json.loads(SCENES.read_text())

    if args.post_only:
        data = json.loads((work / "timeline.json").read_text())
        FAILURES.extend(data.get("failures", []))
    else:
        args.voice = pick_voice(args.voice)
        make_narration(scenes, work, args.voice, args.rate)
        data = record(scenes, args, work)

    mp4 = out_dir / "demo.mp4"
    info = build_mp4(data, mp4, work)
    n = build_srt(data, scenes, out_dir / "demo.srt", info["trim"])
    build_gif(data, mp4, out_dir / "demo-preview.gif", work, info["trim"])
    dur = probe_duration(mp4)
    if not args.no_poster:
        try:
            build_poster(args, data, out_dir / "demo-poster.png", work, dur)
        except Exception as e:  # noqa: BLE001
            fail("poster", "build", e)
    summary = {
        "duration_s": round(dur, 2), "size_mb": round(mp4.stat().st_size / 1e6, 2), "voice": data.get("voice"),
        "rate": data.get("rate"), "scenes": len(data["scenes"]), "srt_cues": n,
        "gif_mb": round((out_dir / "demo-preview.gif").stat().st_size / 1e6, 2),
        "poster_kb": round((out_dir / "demo-poster.png").stat().st_size / 1024) if (out_dir / "demo-poster.png").exists() else None,
        "failures": FAILURES,
    }
    (work / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
