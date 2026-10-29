"""Tranco top-1M popularity rank (G13).

Source: ``backend/ml/data/raw/top-1m.csv`` (the ML agent's copy, read-only) if present, else
``backend/data/tranco/top-1m.csv`` downloaded from https://tranco-list.eu/top-1m.csv.zip.

To keep memory small (a 1M-entry dict costs >150 MB) the list is indexed as two numpy arrays: sorted 64-bit
mmh3 hashes of the domains and their ranks (~12 MB), cached in ``backend/data/tranco/tranco_index.npz``.
Lookups are O(log n). The index is built lazily on first use (thread-safe) and rebuilt if the source changes.

Ranks of *platforms* are never applied to their user-content subdomains (x.github.io, foo.blogspot.com,
abc.web.app, ...): the rank describes the platform, not the tenant, so those return rank=None with a note.
"""
from __future__ import annotations

import csv
import io
import json
import os
import threading
import time
import zipfile
from pathlib import Path

import tldextract

BACKEND = Path(__file__).resolve().parents[2]
DATA_DIR = BACKEND / "data" / "tranco"
ML_COPY = BACKEND / "ml" / "data" / "raw" / "top-1m.csv"
LOCAL_COPY = DATA_DIR / "top-1m.csv"
INDEX_FILE = DATA_DIR / "tranco_index.npz"
META_FILE = DATA_DIR / "tranco_index.json"
DOWNLOAD_URL = "https://tranco-list.eu/top-1m.csv.zip"

_ICANN = tldextract.TLDExtract(suffix_list_urls=())
_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

# multi-tenant hosts whose subdomains are user content but which are not in the PSL private section
PLATFORM_HOSTS = {
    "blogspot.com", "weebly.com", "weeblysite.com", "wixsite.com", "wix.com", "000webhostapp.com", "godaddysites.com",
    "square.site", "yolasite.com", "wordpress.com", "sites.google.com", "docs.google.com", "drive.google.com",
    "forms.gle", "storage.googleapis.com", "firebasestorage.googleapis.com", "script.google.com",
    "googleusercontent.com", "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev",
    "workers.dev", "r2.dev", "web.app", "firebaseapp.com", "appspot.com", "glitch.me", "repl.co", "replit.app",
    "ngrok.io", "ngrok-free.app", "duckdns.org", "webflow.io", "notion.site", "my.canva.site", "ipfs.io", "dweb.link",
    "cloudflare-ipfs.com", "translate.goog", "framer.app", "mystrikingly.com", "jimdosite.com", "webnode.page",
    "azurewebsites.net", "onrender.com", "fly.dev", "surge.sh", "codesandbox.io", "byethost.com", "epizy.com",
    "rf.gd", "infinityfreeapp.com", "no-ip.org", "hopto.org", "zapto.org", "ddns.net", "trycloudflare.com",
    "s3.amazonaws.com", "amazonaws.com", "cloudfront.net", "blob.core.windows.net", "web.core.windows.net",
    "sharepoint.com", "my.sharepoint.com", "dropboxusercontent.com", "dl.dropboxusercontent.com", "myshopify.com",
    "carrd.co", "tilda.ws", "site123.me", "wixstudio.io", "webs.com", "tumblr.com", "medium.com", "substack.com",
    "linktr.ee", "bit.ly", "typeform.com", "jotform.com", "formstack.com", "surveymonkey.com", "zohosites.com",
    "mailchimpsites.com", "mobirisesite.com", "hubspotpagebuilder.com", "hs-sites.com", "ukit.me", "teachable.com",
}

# hosts where the *path* is user content (Google Sites/Forms/Drive, buckets, gists, IPFS gateways, ...)
UGC_PATH_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "script.google.com", "script.googleusercontent.com", "raw.githubusercontent.com",
    "gist.github.com", "gist.githubusercontent.com", "objects.githubusercontent.com", "dl.dropboxusercontent.com",
    "dropboxusercontent.com", "forms.office.com", "forms.microsoft.com", "onedrive.live.com", "1drv.ms",
    "s3.amazonaws.com", "translate.goog", "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "gateway.pinata.cloud",
    "pastebin.com", "telegra.ph", "linktr.ee", "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rebrand.ly", "ow.ly", "rb.gy", "t.ly", "shorturl.at", "lnkd.in", "qrco.de", "my.canva.site", "canva.site",
    "notion.site", "sway.office.com", "sway.cloud.microsoft", "docsend.com", "issuu.com", "flowcode.com",
    "web.archive.org", "share.hsforms.com", "forms.zohopublic.com", "form.jotform.com", "airtable.com", "glitch.me",
}

_lock = threading.Lock()
_hashes = None
_ranks = None
_meta: dict = {}
_load_error: str | None = None
_download_attempted = False


def _hash(domain: str) -> int:
    import mmh3
    return mmh3.hash64(domain.encode("utf-8", "ignore"), seed=0, signed=False)[0]


def _source() -> Path | None:
    for p in (ML_COPY, LOCAL_COPY):
        try:
            if p.exists() and p.stat().st_size > 1_000_000:
                return p
        except OSError:
            continue
    return None


def _download() -> Path | None:
    """Download the Tranco zip into backend/data/tranco/ (once per process)."""
    global _download_attempted
    if _download_attempted:
        return None
    _download_attempted = True
    try:
        import httpx
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0), follow_redirects=True,
                          headers={"User-Agent": "PhishGuard (academic project)"}) as c:
            r = c.get(DOWNLOAD_URL)
        if r.status_code != 200:
            return None
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            name = next((n for n in z.namelist() if n.endswith(".csv")), None)
            if not name:
                return None
            data = z.read(name)
        tmp = LOCAL_COPY.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, LOCAL_COPY)
        return LOCAL_COPY
    except Exception:
        return None


def _build(src: Path):
    import numpy as np
    hs, rs = [], []
    with open(src, "r", encoding="utf-8", errors="ignore", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 2:
                continue
            try:
                rk = int(row[0])
            except ValueError:
                continue
            d = row[1].strip().lower().rstrip(".")
            if d:
                hs.append(_hash(d))
                rs.append(rk)
    h = np.array(hs, dtype=np.uint64)
    r = np.array(rs, dtype=np.int32)
    order = np.lexsort((r, h))          # by hash, then rank (keeps best rank first on collisions)
    h, r = h[order], r[order]
    keep = np.ones(len(h), dtype=bool)
    keep[1:] = h[1:] != h[:-1]
    return h[keep], r[keep], len(hs)


def _ensure_loaded() -> bool:
    global _hashes, _ranks, _meta, _load_error
    if _hashes is not None:
        return True
    with _lock:
        if _hashes is not None:
            return True
        try:
            import numpy as np
            src = _source() or _download()
            if not src:
                _load_error = "Tranco list not available (no local copy and download failed)"
                return False
            st = src.stat()
            sig = {"source": str(src), "size": st.st_size, "mtime": int(st.st_mtime)}
            if INDEX_FILE.exists() and META_FILE.exists():
                try:
                    meta = json.loads(META_FILE.read_text())
                    if all(meta.get(k) == v for k, v in sig.items()):
                        z = np.load(INDEX_FILE)
                        _hashes, _ranks, _meta = z["h"], z["r"], meta
                        return True
                except Exception:
                    pass
            t = time.time()
            h, r, n = _build(src)
            meta = {**sig, "entries": int(n), "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "list_date": time.strftime("%Y-%m-%d", time.gmtime(st.st_mtime)), "build_s": round(time.time() - t, 2)}
            try:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
                tmp = INDEX_FILE.with_name("tranco_index.tmp.npz")
                np.savez(tmp, h=h, r=r)
                os.replace(tmp, INDEX_FILE)
                META_FILE.write_text(json.dumps(meta, indent=1))
            except Exception:
                pass
            _hashes, _ranks, _meta = h, r, meta
            return True
        except Exception as e:  # pragma: no cover
            _load_error = f"{type(e).__name__}: {e}"
            return False


def rank(domain: str) -> int | None:
    """Tranco rank of an exact (registered) domain, or None."""
    if not domain or not _ensure_loaded():
        return None
    import numpy as np
    d = domain.strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    hv = np.uint64(_hash(d))
    i = int(np.searchsorted(_hashes, hv))
    if i < len(_hashes) and _hashes[i] == hv:
        return int(_ranks[i])
    return None


def tier_for(r: int | None) -> str | None:
    if r is None:
        return None
    if r <= 1000:
        return "top1k"
    if r <= 10_000:
        return "top10k"
    if r <= 100_000:
        return "top100k"
    if r <= 1_000_000:
        return "top1m"
    return None


def platform_of(host: str) -> str | None:
    """If ``host`` is a tenant subdomain of a multi-tenant platform, return the platform domain."""
    h = (host or "").lower().strip(".")
    if not h:
        return None
    try:
        icann = _ICANN(h)
        reg = icann.top_domain_under_public_suffix or h
        priv = _PRIVATE(h).top_domain_under_public_suffix or reg
    except Exception:
        return None
    if priv != reg and h != reg:
        return _PRIVATE(h).suffix or reg       # e.g. github.io, blogspot.com
    bare = h[4:] if h.startswith("www.") else h
    if bare in UGC_PATH_HOSTS:
        return bare                            # sites.google.com/view/<anything> etc.
    for p in PLATFORM_HOSTS:
        if h != p and h.endswith("." + p) and h != "www." + p:
            return p
    return None


def lookup(host: str) -> dict:
    """{"rank","tier","source":"Tranco","domain","platform","note","list_date"}. Never raises."""
    out = {"rank": None, "tier": None, "source": "Tranco", "domain": None, "platform": None, "note": None,
           "list_date": None}
    try:
        h = (host or "").lower().strip(".").strip("[]")
        if not h:
            return out
        try:
            import ipaddress
            ipaddress.ip_address(h)
            out["note"] = "IP address host – not ranked"
            return out
        except ValueError:
            pass
        if not _ensure_loaded():
            out["note"] = _load_error
            return out
        out["list_date"] = _meta.get("list_date")
        reg = _ICANN(h).top_domain_under_public_suffix or h
        plat = platform_of(h)
        if plat:
            pr = rank(plat) or rank(reg)
            out["platform"] = plat
            out["note"] = (f"{h} is user content on {plat}" + (f" (platform rank #{pr} not applied)" if pr else ""))
            out["platform_rank"] = pr
            return out
        r = rank(reg)
        if r is None and h != reg:
            r = rank(h)
            if r is not None:
                out["domain"] = h
        else:
            out["domain"] = reg if r is not None else None
        out["rank"] = r
        out["tier"] = tier_for(r)
        return out
    except Exception as e:  # pragma: no cover
        out["note"] = f"lookup error: {e}"
        return out


def status() -> dict:
    ok = _ensure_loaded()
    return {"loaded": ok, "error": _load_error, **({k: v for k, v in _meta.items()} if ok else {}),
            "entries_indexed": int(len(_hashes)) if ok else 0}
