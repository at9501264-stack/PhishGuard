"""Local threat-intel blocklists (OpenPhish, URLhaus, Phishing.Database, PhishTank, Phishing Army).

Files are cached in backend/data/feeds/ with an index.json; in-memory sets are loaded lazily for O(1) lookup.
"""
from __future__ import annotations

import csv
import io
import json
import os
import random
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import tldextract

from .brands import detect_brand

FEED_DIR = Path(__file__).resolve().parents[2] / "data" / "feeds"
INDEX_FILE = FEED_DIR / "index.json"
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
UA = "Mozilla/5.0 (PhishGuard threat-intel updater; academic project)"

# name -> config. "sources" are tried in order (first success wins). kind: urls | domains | mixed | phishtank
FEEDS: dict[str, dict] = {
    "OpenPhish": {"file": "openphish.txt", "kind": "urls", "homepage": "https://openphish.com",
                  "sources": ["https://openphish.com/feed.txt",
                              "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"]},
    "URLhaus": {"file": "urlhaus.txt", "kind": "mixed", "homepage": "https://urlhaus.abuse.ch",
                "sources": ["https://urlhaus.abuse.ch/downloads/text_online/",
                            # official text dumps now return 410 without auth; the malware-filter project mirrors them
                            "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt"]},
    "Phishing.Database": {"file": "phishing_database.txt", "kind": "mixed",
                          "homepage": "https://github.com/mitchellkrogza/Phishing.Database",
                          "sources": ["https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-today.txt",
                                      "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"]},
    "PhishTank": {"file": "phishtank.csv", "kind": "phishtank", "homepage": "https://phishtank.org",
                  "sources": ["http://data.phishtank.com/data/online-valid.csv"]},
    "Phishing Army": {"file": "phishing_army.txt", "kind": "domains", "homepage": "https://phishing.army",
                      "sources": ["https://phishing.army/download/phishing_army_blocklist.txt"]},
}

# Domains that host user content: only an exact URL match counts (never a domain-level match).
SHARED_HOSTS = {
    "google.com", "docs.google.com", "drive.google.com", "sites.google.com", "forms.google.com", "storage.googleapis.com",
    "googleapis.com", "googleusercontent.com", "github.com", "raw.githubusercontent.com", "gist.github.com",
    "firebaseapp.com", "web.app", "firebasestorage.googleapis.com", "appspot.com", "blogspot.com", "weebly.com",
    "wix.com", "wixsite.com", "wordpress.com", "medium.com", "dropbox.com", "dl.dropboxusercontent.com",
    "onedrive.live.com", "1drv.ms", "sharepoint.com", "microsoft.com", "live.com", "office.com", "forms.office.com",
    "forms.gle", "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "linktr.ee",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "youtube.com", "amazonaws.com",
    "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net", "windows.net", "core.windows.net", "vercel.app",
    "netlify.app", "pages.dev", "workers.dev", "herokuapp.com", "glitch.me", "repl.co", "replit.app", "000webhostapp.com",
    "github.io", "gitlab.io", "notion.site", "notion.so", "canva.com", "my.canva.site", "typeform.com",
    "jotform.com", "surveymonkey.com", "webflow.io", "square.site", "godaddysites.com", "yolasite.com",
    "telegram.org", "t.me", "discord.com", "discord.gg", "apple.com", "icloud.com", "adobe.com", "ipfs.io",
    "cloudflare-ipfs.com", "dweb.link", "translate.goog", "ngrok.io", "ngrok-free.app", "duckdns.org", "wa.me",
    "mediafire.com", "mega.nz", "box.com", "wetransfer.com", "yandex.ru", "mail.ru", "baidu.com", "qq.com",
    "amazon.com", "paypal.com", "ebay.com", "zoom.us", "cloudflare.com", "pastebin.com", "imgur.com",
}
# Registered domains where even a subdomain match is meaningless (big multi-tenant brands)
BIG_PLATFORMS = {"google.com", "github.com", "microsoft.com", "live.com", "office.com", "facebook.com",
                 "amazonaws.com", "amazon.com", "apple.com", "icloud.com", "googleapis.com", "googleusercontent.com",
                 "windows.net", "sharepoint.com", "dropbox.com", "yandex.ru", "adobe.com", "linkedin.com",
                 "cloudflare.com", "paypal.com", "youtube.com", "twitter.com", "x.com", "instagram.com",
                 "wikipedia.org", "mozilla.org", "apple.co", "azure.com", "cloudfront.net", "akamaihd.net"}

_lock = threading.RLock()
_loaded = False
_url_sets: dict[str, set[str]] = {}
_host_sets: dict[str, set[str]] = {}
_entries: dict[str, list[str]] = {}       # raw entries for search (urls or domains)
_pt_targets: dict[str, str] = {}          # normalised url -> phishtank target
_index_cache: dict | None = None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_url(u: str) -> str:
    """Normalise URL for matching: no scheme, lower host, no www., no fragment, no trailing slash."""
    u = (u or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    try:
        sp = urlsplit(u)
        host = (sp.hostname or "").lower().strip(".")
    except Exception:
        return u.lower()
    if host.startswith("www."):
        host = host[4:]
    port = ""
    try:
        if sp.port and sp.port not in (80, 443):
            port = f":{sp.port}"
    except Exception:
        pass
    path = sp.path or ""
    path = path.rstrip("/")
    q = f"?{sp.query}" if sp.query else ""
    return f"{host}{port}{path}{q}"


def norm_host(h: str) -> str:
    h = (h or "").strip().lower().strip(".")
    if h.startswith("www."):
        h = h[4:]
    return h


def _host_of(u: str) -> str:
    if "://" not in u:
        u = "http://" + u
    try:
        return norm_host(urlsplit(u).hostname or "")
    except Exception:
        return ""


def _registered(host: str) -> str:
    try:
        e = _EXTRACT(host)
        r = getattr(e, "top_domain_under_public_suffix", None) or e.registered_domain
        return r or host
    except Exception:
        return host


def _is_shared(host: str) -> bool:
    if not host:
        return True
    if host in SHARED_HOSTS:
        return True
    reg = _registered(host)
    return reg in BIG_PLATFORMS or (reg in SHARED_HOSTS and host == reg)


# ---------------------------------------------------------------------------------------- parsing
def _parse(kind: str, text: str) -> tuple[list[str], list[str], dict[str, str]]:
    """Return (urls, domains, phishtank_targets)."""
    urls: list[str] = []
    domains: list[str] = []
    targets: dict[str, str] = {}
    if kind == "phishtank":
        rd = csv.DictReader(io.StringIO(text))
        for row in rd:
            u = (row.get("url") or "").strip()
            if u:
                urls.append(u)
                t = (row.get("target") or "").strip()
                if t and t.lower() != "other":
                    targets[norm_url(u)] = t
        return urls, domains, targets
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!;[" or line.startswith("<"):
            continue
        if line.startswith("||"):
            line = line[2:]
        for suf in ("^$all", "$all", "^"):
            if line.endswith(suf):
                line = line[: -len(suf)]
        line = line.split()[0] if " " in line else line
        if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
            continue
        if "://" in line or "/" in line:
            urls.append(line if "://" in line else "http://" + line)
        else:
            domains.append(line.lower())
    if kind == "urls":
        return urls + ["http://" + d for d in domains], [], targets
    return urls, domains, targets


def _load_feed(name: str, cfg: dict) -> None:
    path = FEED_DIR / cfg["file"]
    us: set[str] = set()
    hs: set[str] = set()
    entries: list[str] = []
    if path.exists():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            urls, domains, targets = _parse(cfg["kind"], text)
            for u in urls:
                nu = norm_url(u)
                if nu:
                    us.add(nu)
                    entries.append(u)
                    h = _host_of(u)
                    if h and not _is_shared(h):
                        hs.add(h)
            for d in domains:
                h = norm_host(d)
                if h and not _is_shared(h):
                    hs.add(h)
                    entries.append(h)
            if targets:
                _pt_targets.update(targets)
        except Exception:
            pass
    _url_sets[name] = us
    _host_sets[name] = hs
    _entries[name] = entries


def _ensure_loaded(force: bool = False) -> None:
    global _loaded
    if _loaded and not force:
        return
    with _lock:
        if _loaded and not force:
            return
        if force:
            _pt_targets.clear()
        for name, cfg in FEEDS.items():
            _load_feed(name, cfg)
        _loaded = True


def _read_index() -> dict:
    global _index_cache
    if _index_cache is not None:
        return _index_cache
    try:
        _index_cache = json.loads(INDEX_FILE.read_text())
    except Exception:
        _index_cache = {"feeds": {}, "stats": None}
    return _index_cache


def _write_index(idx: dict) -> None:
    global _index_cache
    FEED_DIR.mkdir(parents=True, exist_ok=True)
    tmp = INDEX_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(idx, indent=1))
    os.replace(tmp, INDEX_FILE)
    _index_cache = idx


# ---------------------------------------------------------------------------------------- download
def _download(name: str, cfg: dict) -> dict:
    errors = []
    for src in cfg["sources"]:
        try:
            with httpx.Client(timeout=httpx.Timeout(60.0, connect=15.0), follow_redirects=True,
                              headers={"User-Agent": UA}) as c:
                r = c.get(src)
            if r.status_code != 200:
                errors.append(f"{src}: HTTP {r.status_code}")
                continue
            text = r.text
            urls, domains, _ = _parse(cfg["kind"], text)
            n = len(urls) + len(domains)
            if n == 0:
                errors.append(f"{src}: empty feed")
                continue
            FEED_DIR.mkdir(parents=True, exist_ok=True)
            tmp = FEED_DIR / (cfg["file"] + ".tmp")
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, FEED_DIR / cfg["file"])
            return {"status": "ok", "source_used": src, "entries": n, "last_updated": _now(),
                    "error": "; ".join(errors) or None}
        except Exception as e:
            errors.append(f"{src}: {type(e).__name__}: {e}"[:300])
    return {"status": "error", "error": "; ".join(errors)[:1000]}


def refresh_feeds() -> dict:
    """Download all feeds (in parallel), store on disk, rebuild in-memory sets. Returns {"feeds": feed_status()}."""
    idx = _read_index()
    feeds_idx = dict(idx.get("feeds") or {})
    with ThreadPoolExecutor(max_workers=len(FEEDS)) as ex:
        futs = {name: ex.submit(_download, name, cfg) for name, cfg in FEEDS.items()}
        for name, f in futs.items():
            try:
                res = f.result()
            except Exception as e:
                res = {"status": "error", "error": str(e)}
            prev = feeds_idx.get(name, {})
            if res["status"] == "ok":
                feeds_idx[name] = {**prev, **res, "last_attempt": _now()}
            else:
                has_file = (FEED_DIR / FEEDS[name]["file"]).exists()
                feeds_idx[name] = {**prev, "status": "stale" if has_file else "error", "error": res.get("error"),
                                   "last_attempt": _now()}
    _ensure_loaded(force=True)
    idx = {"feeds": feeds_idx, "stats": None, "updated_at": _now()}
    try:
        idx["stats"] = _compute_stats()
    except Exception:
        idx["stats"] = None
    _write_index(idx)
    return {"feeds": feed_status(), "stats": idx["stats"]}


# ---------------------------------------------------------------------------------------- API
def feed_status() -> list[dict]:
    idx = _read_index().get("feeds") or {}
    out = []
    for name, cfg in FEEDS.items():
        meta = idx.get(name, {})
        has_file = (FEED_DIR / cfg["file"]).exists()
        entries = meta.get("entries")
        if _loaded:
            entries = len(_entries.get(name, []))
        out.append({
            "name": name,
            "url": meta.get("source_used") or cfg["sources"][0],
            "homepage": cfg["homepage"],
            "kind": cfg["kind"],
            "entries": int(entries or 0),
            "last_updated": meta.get("last_updated"),
            "last_attempt": meta.get("last_attempt"),
            "status": meta.get("status") or ("ok" if has_file else "never"),
            "error": meta.get("error"),
        })
    return out


def lookup(url: str) -> list[dict]:
    """Return [{"name","listed":True,"detail"}] for each feed containing the URL (or its host)."""
    try:
        _ensure_loaded()
        nu = norm_url(url)
        host = _host_of(url)
        if not nu:
            return []
        variants = {nu}
        if "?" in nu:
            variants.add(nu.split("?", 1)[0])
        hosts: list[str] = []
        if host and not _is_shared(host):
            parts = host.split(".")
            reg = _registered(host)
            for i in range(len(parts) - 1):
                cand = ".".join(parts[i:])
                if _is_shared(cand) or len(cand) < len(reg):
                    break
                hosts.append(cand)
        out = []
        for name in FEEDS:
            us = _url_sets.get(name, set())
            hit = next((v for v in variants if v in us), None)
            if hit:
                det = f"Exact URL listed in {name}"
                t = _pt_targets.get(hit)
                if t:
                    det += f" (target: {t})"
                out.append({"name": name, "listed": True, "detail": det, "match": "url"})
                continue
            hs = _host_sets.get(name, set())
            h = next((c for c in hosts if c in hs), None)
            if h:
                det = f"Domain {h} listed in {name}" if h == host else f"Parent domain {h} listed in {name}"
                out.append({"name": name, "listed": True, "detail": det, "match": "domain"})
        return out
    except Exception:
        return []


def search_entries(q: str, limit: int = 100) -> list[dict]:
    try:
        _ensure_loaded()
        q = (q or "").strip().lower()
        out = []
        for name, entries in _entries.items():
            for e in entries:
                if not q or q in e.lower():
                    host = _host_of(e)
                    nu = norm_url(e)
                    target = _pt_targets.get(nu) or detect_brand(e).get("impersonated_brand")
                    out.append({"url": e, "domain": host, "feed": name, "target": target})
                    if len(out) >= limit:
                        return out
        return out
    except Exception:
        return []


def _compute_stats() -> dict:
    _ensure_loaded()
    by_feed = {n: len(e) for n, e in _entries.items()}
    all_hosts: set[str] = set()
    for hs in _host_sets.values():
        all_hosts |= hs
    for us in _url_sets.values():
        for u in us:
            all_hosts.add(u.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0])
    tlds: Counter = Counter()
    regs: Counter = Counter()
    for h in all_hosts:
        try:
            e = _EXTRACT(h)
            if e.suffix:
                tlds[e.suffix] += 1
            elif h.replace(".", "").isdigit():
                tlds["(ip)"] += 1
            r = getattr(e, "top_domain_under_public_suffix", None) or e.registered_domain
            if r:
                regs[r] += 1
        except Exception:
            pass
    # targeted brands: PhishTank native target + brand detector on a sample of URL-feed entries
    targets: Counter = Counter(_pt_targets.values())
    sample: list[str] = []
    for name in ("OpenPhish", "PhishTank", "URLhaus", "Phishing.Database", "Phishing Army"):
        ents = _entries.get(name, [])
        if name == "PhishTank":
            ents = [e for e in ents if norm_url(e) not in _pt_targets]
        k = min(len(ents), 2500)
        rnd = random.Random(42)
        sample += rnd.sample(ents, k) if k else []
    sampled_hits: Counter = Counter()
    for e in sample:
        b = detect_brand(e).get("impersonated_brand")
        if b:
            sampled_hits[b] += 1
    # scale sampled counts to approximate totals
    total_entries = sum(by_feed.values())
    scale = max(1.0, (total_entries - len(_pt_targets)) / max(1, len(sample)))
    for b, n in sampled_hits.items():
        targets[b] += int(round(n * scale))
    return {
        "total_entries": total_entries,
        "unique_hosts": len(all_hosts),
        "by_feed": by_feed,
        "top_domains_tlds": [{"name": t, "value": v} for t, v in tlds.most_common(15)],
        "top_registered_domains": [{"name": t, "value": v} for t, v in regs.most_common(15)],
        "top_targets": [{"name": t, "value": v} for t, v in targets.most_common(15)],
        "computed_at": _now(),
        "targets_estimated": True,
    }


def stats() -> dict:
    try:
        s = _read_index().get("stats")
        if s:
            return s
        if any((FEED_DIR / c["file"]).exists() for c in FEEDS.values()):
            s = _compute_stats()
            idx = _read_index()
            idx["stats"] = s
            try:
                _write_index(idx)
            except Exception:
                pass
            return s
    except Exception:
        pass
    return {"total_entries": 0, "by_feed": {}, "top_domains_tlds": [], "top_targets": []}


def total_entries() -> int:
    try:
        return int(stats().get("total_entries", 0))
    except Exception:
        return 0
