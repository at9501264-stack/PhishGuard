"""PhishGuard analysis engine.

Merges the kinds of checks done by urlscan.io, URLVoid, Sucuri SiteCheck, ScamAdviser, CheckPhish,
IPQualityScore, Google Safe Browsing and VirusTotal into one async pipeline.

Public API: ``async run_checks(url, settings) -> dict`` (never raises; see docs/SPEC.md section 2).
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import math
import os
import re
import socket
import ssl
import tempfile
import threading
import time
from collections import Counter, OrderedDict
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

import httpx
import tldextract

from . import dnsbl, feeds, net_safety, popularity, rdap
from .brands import BRANDS, detect_brand, is_legit_domain

EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/129.0.0.0 Safari/537.36")
MAX_BODY = 2 * 1024 * 1024
MAX_DOM = 500 * 1024  # dom_html cap (bytes)
TOTAL_BUDGET_S = 10.0

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site", "icu", "buzz", "cyou", "sbs", "rest",
    "live", "click", "link", "work", "fit", "loan", "win", "bid", "date", "racing", "men", "kim", "country",
    "stream", "gdn", "cam", "bar", "mom", "monster", "quest", "lol", "support", "zip", "mov", "shop", "store",
    "fun", "space", "website", "tech", "host", "press", "pw", "cc", "su", "ws", "info", "biz", "vip", "top",
    "life", "today", "xin", "bond", "cfd", "beauty", "hair", "skin", "makeup", "autos", "boats", "homes",
    "motorcycles", "yachts", "accountant", "review", "download", "trade", "party", "science", "faith", "cricket",
    "uno", "asia", "ru", "cn", "best", "pics", "help", "account", "digital", "network", "services", "email",
}
HIGH_RISK_TLDS = {"tk", "ml", "ga", "cf", "gq", "zip", "mov", "cyou", "sbs", "icu", "buzz", "rest", "cfd", "bond",
                  "monster", "quest", "gdn", "xin", "top", "xyz", "click", "lol", "pw", "su"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
              "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "bitly.com", "s.id", "v.gd", "shorte.st", "adf.ly",
              "lnkd.in", "qrco.de", "tr.ee", "short.io", "bl.ink", "soo.gd", "clck.ru", "u.to", "x.gd", "urlz.fr",
              "y2u.be", "surl.li", "lnk.bio", "linktr.ee", "amzn.to", "forms.gle", "1url.com", "2u.pw"}
FREE_HOSTING = {"000webhostapp.com", "weebly.com", "weeblysite.com", "wixsite.com", "blogspot.com", "firebaseapp.com",
                "web.app", "glitch.me", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "r2.dev",
                "github.io", "gitlab.io", "herokuapp.com", "repl.co", "replit.app", "duckdns.org", "ngrok.io",
                "ngrok-free.app", "appspot.com", "webflow.io", "godaddysites.com", "square.site", "yolasite.com",
                "wordpress.com", "sites.google.com", "notion.site", "my.canva.site", "ipfs.io", "dweb.link",
                "cloudflare-ipfs.com", "translate.goog", "framer.app", "blogspot.in", "mystrikingly.com",
                "jimdosite.com", "webnode.page", "azurewebsites.net", "onrender.com", "fly.dev", "surge.sh",
                "codesandbox.io", "freehosting.com", "byethost.com", "epizy.com", "rf.gd", "infinityfreeapp.com",
                "no-ip.org", "hopto.org", "zapto.org", "ddns.net", "serveo.net", "trycloudflare.com"}
SENSITIVE_WORDS = ["login", "log-in", "logon", "signin", "sign-in", "verify", "verification", "secure", "account",
                   "update", "banking", "confirm", "password", "passwd", "webscr", "ebayisapi", "wallet", "unlock",
                   "suspend", "restore", "recover", "billing", "invoice", "payment", "authenticate", "auth", "kyc",
                   "validate", "credential", "security", "alert", "support", "refund", "reward", "claim", "gift",
                   "free", "bonus", "lucky", "prize", "airdrop", "seed", "connect-wallet", "otp"]
URGENCY_PHRASES = ["verify your account", "account has been suspended", "account will be suspended", "unusual activity",
                   "confirm your identity", "update your payment", "your account has been locked", "limited access",
                   "unauthorized login", "security alert", "within 24 hours", "within 48 hours", "act now",
                   "immediately", "your password will expire", "re-activate", "reactivate your account",
                   "kyc update", "kyc pending", "your package could not be delivered", "delivery failed",
                   "you have won", "claim your reward", "claim your prize", "connect your wallet", "seed phrase",
                   "recovery phrase", "wallet validation", "account verification required", "pan card", "aadhaar"]
SENSITIVE_INPUT_RX = re.compile(
    r"(card.?number|cc.?num|cardnum|cvv|cvc|expir|ssn|social.?security|otp|one.?time|pin\b|atm.?pin|mpin|aadhaar|"
    r"aadhar|pan.?(card|no|number)|mother.?maiden|seed|mnemonic|private.?key|recovery.?phrase|routing|iban|sort.?code)",
    re.I)
SUSPICIOUS_EXT = (".exe", ".apk", ".scr", ".bat", ".cmd", ".msi", ".jar", ".vbs", ".ps1", ".dll", ".iso", ".img",
                  ".hta", ".lnk", ".zip", ".rar", ".7z", ".sh", ".bin", ".dmg", ".js")
PRIVACY_WORDS = ["privacy", "redacted", "proxy", "whoisguard", "domains by proxy", "contact privacy", "withheld",
                 "data protected", "not disclosed", "gdpr", "private", "perfect privacy", "whois agent",
                 "identity protection", "protected", "statutory masking", "anonymize", "domain admin"]

JS_PATTERNS = [
    ("eval_atob", r"eval\s*\(\s*(window\.)?atob\s*\(", "eval(atob(...)) – executes base64-hidden code"),
    ("eval_unescape", r"eval\s*\(\s*(unescape|decodeURIComponent)\s*\(", "eval(unescape(...)) – obfuscated code"),
    ("packer", r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e", "Dean Edwards packer obfuscation"),
    ("docwrite_unescape", r"document\.write\s*\(\s*(unescape|atob|decodeURIComponent)\s*\(",
     "document.write(unescape(...)) – injects hidden HTML"),
    ("location_obfuscated", r"(window\.|document\.|top\.)?location(\.href)?\s*(=|\.replace\s*\(|\.assign\s*\()\s*"
                            r"[^;\n]{0,80}(atob|fromCharCode|unescape|decodeURIComponent)",
     "Obfuscated window.location redirect"),
    ("fromcharcode_blob", r"String\.fromCharCode\s*\(\s*(\d{2,3}\s*,\s*){20,}", "Long String.fromCharCode sequence"),
    ("keylogger", r"(onkey(press|down|up)\s*=|addEventListener\s*\(\s*['\"]key(press|down|up)['\"])"
                  r"[\s\S]{0,600}(XMLHttpRequest|fetch\s*\(|sendBeacon|new\s+Image|\.ajax\s*\()",
     "Keystroke capture sent to network (keylogger-like)"),
    ("telegram_exfil", r"api\.telegram\.org/bot", "Exfiltration to Telegram bot API (phishing-kit signature)"),
    ("discord_webhook", r"discord(app)?\.com/api/webhooks", "Exfiltration to Discord webhook"),
    ("disable_rightclick", r"(oncontextmenu\s*=\s*['\"]?\s*return\s+false|addEventListener\s*\(\s*['\"]contextmenu)",
     "Right-click disabled (anti-inspection)"),
    ("devtools_trap", r"setInterval\s*\(\s*(function\s*\(\s*\)\s*\{\s*)?debugger", "Anti-debugging trap"),
    ("base64_html", r"data:text/html;base64,", "Base64-encoded HTML document"),
    ("big_atob", r"atob\s*\(\s*['\"][A-Za-z0-9+/=]{800,}['\"]", "Large base64 payload decoded at runtime"),
    ("ip_lookup", r"(ipapi\.co|ip-api\.com|ipinfo\.io|api\.ipify\.org|geoplugin\.net)", "Visitor IP/geo lookup (kit cloaking)"),
]
_JS_RX = [(i, re.compile(p, re.I), d) for i, p, d in JS_PATTERNS]

TECH_HTML = [
    ("WordPress", r"wp-content|wp-includes|wp-json"), ("Shopify", r"cdn\.shopify\.com|Shopify\.theme"),
    ("Wix", r"static\.wixstatic\.com|wix-bolt|_wixCIDX"), ("Squarespace", r"static1\.squarespace\.com|squarespace"),
    ("Joomla", r"/media/jui/|Joomla!"), ("Drupal", r"Drupal\.settings|/sites/default/files"),
    ("Magento", r"Mage\.Cookies|/static/frontend/Magento"), ("Webflow", r"webflow\.(js|com)|data-wf-page"),
    ("Next.js", r"__NEXT_DATA__|/_next/static"), ("Nuxt", r"__NUXT__|/_nuxt/"), ("Gatsby", r"___gatsby"),
    ("React", r"data-reactroot|react(\.production)?(\.min)?\.js|react-dom"), ("Vue.js", r"vue(\.min)?\.js|data-v-[0-9a-f]{8}"),
    ("Angular", r"ng-version=|angular(\.min)?\.js"), ("jQuery", r"jquery[\.-]?(\d[\d.]*)?(\.min)?\.js"),
    ("Bootstrap", r"bootstrap(\.min)?\.(css|js)"), ("Tailwind CSS", r"tailwind(\.min)?\.css|cdn\.tailwindcss\.com"),
    ("Font Awesome", r"font-?awesome"), ("Google Analytics", r"google-analytics\.com|gtag\(|googletagmanager\.com/gtag"),
    ("Google Tag Manager", r"googletagmanager\.com/gtm"), ("Google reCAPTCHA", r"google\.com/recaptcha|grecaptcha"),
    ("hCaptcha", r"hcaptcha\.com"), ("Cloudflare Turnstile", r"challenges\.cloudflare\.com/turnstile"),
    ("Facebook Pixel", r"connect\.facebook\.net"), ("Hotjar", r"static\.hotjar\.com"),
    ("Stripe.js", r"js\.stripe\.com"), ("PHP", r"\.php(\?|\"|')"), ("ASP.NET", r"__VIEWSTATE|\.aspx"),
    ("Laravel", r"laravel_session|csrf-token\" content"), ("Cloudflare", r"cdnjs\.cloudflare\.com|/cdn-cgi/"),
    ("Telegram bot (kit)", r"api\.telegram\.org/bot"),
]
_TECH_RX = [(n, re.compile(p, re.I)) for n, p in TECH_HTML]

# --------------------------------------------------------------------------------------------- caches


class TTLCache:
    def __init__(self, maxsize: int = 1024, ttl: float = 3600):
        self.maxsize, self.ttl = maxsize, ttl
        self._d: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            v = self._d.get(key)
            if not v:
                return None
            if time.time() - v[0] > self.ttl:
                self._d.pop(key, None)
                return None
            self._d.move_to_end(key)
            return v[1]

    def set(self, key, value):
        with self._lock:
            self._d[key] = (time.time(), value)
            self._d.move_to_end(key)
            while len(self._d) > self.maxsize:
                self._d.popitem(last=False)


WHOIS_CACHE = TTLCache(1024, 3600)
GEO_CACHE = TTLCache(2048, 6 * 3600)
DNS_CACHE = TTLCache(2048, 600)
SSL_CACHE = TTLCache(1024, 900)

# --------------------------------------------------------------------------------------------- helpers


def _iso(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, date):
        return v.isoformat()
    return str(v)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _registered(host: str) -> str:
    e = EXTRACT(host)
    r = getattr(e, "top_domain_under_public_suffix", None) or e.registered_domain
    return r or host


def _jsonable(o):
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [_jsonable(v) for v in o]
    if isinstance(o, (datetime, date)):
        return _iso(o)
    if isinstance(o, bytes):
        return o.decode("utf-8", "ignore")
    if isinstance(o, float) and (math.isnan(o) or math.isinf(o)):
        return None
    if o is None or isinstance(o, (str, int, float, bool)):
        return o
    return str(o)


def _check(cid, category, name, status, detail, weight) -> dict:
    return {"id": cid, "category": category, "name": name, "status": status, "detail": detail, "weight": weight}


def _parse_ip_host(host: str) -> str | None:
    """Detect IPv4/IPv6 incl. decimal (3232235777), hex (0xC0A80001) and octal dotted forms."""
    h = host.strip("[]")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        if re.fullmatch(r"\d{8,10}", h):
            n = int(h)
            if n < 2 ** 32:
                return str(ipaddress.IPv4Address(n))
        if re.fullmatch(r"0x[0-9a-f]{1,8}", h, re.I):
            return str(ipaddress.IPv4Address(int(h, 16)))
        parts = h.split(".")
        if len(parts) == 4 and all(re.fullmatch(r"(0x[0-9a-f]+|0[0-7]*|\d+)", p, re.I) for p in parts):
            nums = [int(p, 16) if p.lower().startswith("0x") else (int(p, 8) if len(p) > 1 and p.startswith("0") else int(p))
                    for p in parts]
            if all(0 <= n <= 255 for n in nums):
                return ".".join(map(str, nums))
    except Exception:
        pass
    return None


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def normalize_url(url: str) -> str:
    u = (url or "").strip().strip("<>\"'")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    try:
        sp = urlsplit(u)
        host = sp.hostname or ""
        if host and not host.isascii():
            enc = ".".join(p.encode("idna").decode() if not p.isascii() else p for p in host.split("."))
            netloc = sp.netloc.replace(sp.hostname, enc) if sp.hostname in sp.netloc else enc
            u = sp._replace(netloc=netloc).geturl()
    except Exception:
        pass
    return u


def parse_domain(url: str) -> dict:
    sp = urlsplit(url)
    host = (sp.hostname or "").lower().strip(".")
    ip = _parse_ip_host(host) if host else None
    puny = None
    if "xn--" in host:
        try:
            puny = ".".join(p.encode().decode("idna") if p.startswith("xn--") else p for p in host.split("."))
        except Exception:
            puny = None
    if ip:
        return {"domain": host, "registered_domain": ip, "subdomain": "", "tld": "", "is_ip": True,
                "punycode": None, "ip": ip}
    e = EXTRACT(host)
    reg = getattr(e, "top_domain_under_public_suffix", None) or e.registered_domain or host
    return {"domain": host, "registered_domain": reg, "subdomain": e.subdomain, "tld": e.suffix, "is_ip": False,
            "punycode": puny, "ip": None}


# --------------------------------------------------------------------------------------------- DNS


async def dns_lookup(host: str, timeout: float) -> dict:
    cached = DNS_CACHE.get(host)
    if cached:
        return cached
    import dns.asyncresolver
    res = dns.asyncresolver.Resolver()
    res.timeout = min(2.5, timeout)
    res.lifetime = timeout

    async def q(name, rtype):
        try:
            ans = await res.resolve(name, rtype, lifetime=timeout)
            out = []
            for r in ans:
                if rtype == "MX":
                    out.append(f"{r.preference} {r.exchange.to_text().rstrip('.')}")
                elif rtype == "TXT":
                    out.append(b"".join(r.strings).decode("utf-8", "ignore"))
                else:
                    out.append(r.to_text().rstrip("."))
            return out
        except Exception:
            return []

    reg = _registered(host)
    a, aaaa, mx, ns, txt, dmarc, cname = await asyncio.gather(
        q(host, "A"), q(host, "AAAA"), q(reg, "MX"), q(reg, "NS"), q(reg, "TXT"), q(f"_dmarc.{reg}", "TXT"),
        q(host, "CNAME"))
    out = {"a": a, "aaaa": aaaa, "mx": mx, "ns": ns, "txt": txt[:20], "cname": cname,
           "spf": any(t.lower().startswith("v=spf1") for t in txt),
           "dmarc": any(t.lower().startswith("v=dmarc1") for t in dmarc),
           "resolves": bool(a or aaaa)}
    if out["resolves"] or ns:
        DNS_CACHE.set(host, out)
    return out


# --------------------------------------------------------------------------------------------- WHOIS


def _first(v):
    if isinstance(v, (list, tuple)):
        v = [x for x in v if x]
        return v[0] if v else None
    return v


def _as_dt(v) -> datetime | None:
    if isinstance(v, (list, tuple)):
        ds = [_as_dt(x) for x in v]
        ds = [d for d in ds if d]
        return min(ds) if ds else None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day, tzinfo=timezone.utc)
    if isinstance(v, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d"):
            try:
                return datetime.strptime(v.strip()[:19], fmt).replace(tzinfo=timezone.utc)
            except Exception:
                continue
    return None


def _whois_sync(domain: str) -> dict:
    import whois  # python-whois
    w = whois.whois(domain, quiet=True, timeout=6)
    data = dict(w) if w else {}
    created = _as_dt(data.get("creation_date"))
    expiry = _as_dt(data.get("expiration_date"))
    updated = data.get("updated_date")
    updated = _as_dt(max(updated) if isinstance(updated, list) and all(isinstance(x, datetime) for x in updated)
                     and updated else updated)
    now = _now()
    blob = " ".join(str(data.get(k) or "") for k in ("name", "org", "registrant_name", "emails", "registrant",
                                                     "registrar", "address")).lower()
    privacy = any(p in blob for p in PRIVACY_WORDS)
    registrar = _first(data.get("registrar"))
    country = _first(data.get("country")) or _first(data.get("registrant_country"))
    found = bool(registrar or created or data.get("domain_name"))
    return {
        "registrar": str(registrar) if registrar else None,
        "creation_date": _iso(created),
        "expiry_date": _iso(expiry),
        "updated_date": _iso(updated),
        "age_days": (now - created).days if created else None,
        "days_to_expiry": (expiry - now).days if expiry else None,
        "registration_length_days": (expiry - created).days if (expiry and created) else None,
        "privacy_protected": privacy,
        "country": str(country).upper()[:3] if country else None,
        "name_servers": sorted({str(n).lower().rstrip(".") for n in (data.get("name_servers") or [])
                                if n})[:8] if isinstance(data.get("name_servers"), (list, set, tuple))
        else ([str(data.get("name_servers")).lower()] if data.get("name_servers") else []),
        "org": str(_first(data.get("org"))) if _first(data.get("org")) else None,
        "found": found,
    }


async def whois_lookup(domain: str, timeout: float, use_rdap: bool = True) -> dict:
    """System WHOIS first; RDAP fallback when whois is missing/fails or has no creation date."""
    cached = WHOIS_CACHE.get(domain)
    if cached:
        return cached
    res, err = None, None
    try:
        res = await asyncio.wait_for(asyncio.to_thread(_whois_sync, domain), timeout)
        res["source"] = "whois"
    except asyncio.TimeoutError:
        err = f"WHOIS timed out after {timeout:.1f}s"
    except Exception as e:
        err = f"WHOIS failed: {type(e).__name__}: {e}"[:200]
    if use_rdap and (res is None or not res.get("creation_date")):
        r = await rdap.lookup_domain(domain, min(4.0, timeout))
        if r.get("found"):
            res = {**(res or {}), **{k: v for k, v in r.items() if v not in (None, [], "")}}
            res["source"] = "rdap"
        elif res is None:
            err = f"{err}; RDAP: {r.get('error')}"
    if res is None:
        raise RuntimeError(err or "WHOIS unavailable")
    WHOIS_CACHE.set(domain, res)
    return res


# --------------------------------------------------------------------------------------------- Geo


async def geo_lookup(ip: str, timeout: float) -> dict:
    cached = GEO_CACHE.get(ip)
    if cached:
        return cached
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            out = {"country": None, "country_code": None, "city": None, "asn": None, "org": "Private network",
                   "isp": None, "lat": None, "lon": None, "hosting": False, "private": True}
            return out
    except ValueError:
        pass
    j = None
    async with httpx.AsyncClient(timeout=timeout) as c:
        try:
            r = await c.get(f"http://ip-api.com/json/{ip}",
                            params={"fields": "status,message,country,countryCode,city,lat,lon,isp,org,as,hosting"})
            if r.status_code == 200:
                j = r.json()
        except Exception:
            j = None
        if not j or j.get("status") != "success":
            # fallback provider (free, no key) – used when ip-api rate-limits (45 req/min)
            r2 = await c.get(f"https://ipwho.is/{ip}")
            k = r2.json()
            if not k.get("success"):
                raise RuntimeError(k.get("message") or "geo lookup failed")
            conn = k.get("connection") or {}
            j = {"country": k.get("country"), "countryCode": k.get("country_code"), "city": k.get("city"),
                 "lat": k.get("latitude"), "lon": k.get("longitude"), "isp": conn.get("isp"), "org": conn.get("org"),
                 "as": f"AS{conn.get('asn')} {conn.get('org') or ''}" if conn.get("asn") else "", "hosting": None}
    asn = None
    m = re.match(r"AS(\d+)", j.get("as") or "")
    if m:
        asn = f"AS{m.group(1)}"
    out = {"country": j.get("country"), "country_code": j.get("countryCode"), "city": j.get("city"),
           "asn": asn, "as_name": (j.get("as") or "").split(" ", 1)[1] if " " in (j.get("as") or "") else None,
           "org": j.get("org"), "isp": j.get("isp"), "lat": j.get("lat"), "lon": j.get("lon"),
           "hosting": None if j.get("hosting") is None else bool(j.get("hosting"))}
    GEO_CACHE.set(ip, out)
    return out


# --------------------------------------------------------------------------------------------- SSL


def _decode_der(der: bytes) -> dict:
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def _name(rdns) -> dict:
    out = {}
    for rdn in rdns or ():
        for k, v in rdn:
            out[k] = v
    return out


def _ssl_sync(host: str, port: int, timeout: float, ip: str | None = None) -> dict:
    out = {"enabled": False, "valid": False, "issuer": None, "issuer_org": None, "subject": None, "san": [],
           "not_before": None, "not_after": None, "days_left": None, "age_days": None, "protocol": None,
           "cipher": None, "self_signed": False, "error": None}
    verify_error = None
    der = None
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip or host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                out["protocol"] = s.version()
                out["cipher"] = (s.cipher() or [None])[0]
                out["valid"] = True
    except ssl.SSLCertVerificationError as e:
        verify_error = e
    except ssl.SSLError as e:
        out["error"] = f"TLS handshake failed: {e.reason or e}"
        return out
    except (socket.timeout, TimeoutError):
        out["error"] = "Connection to port 443 timed out"
        return out
    except OSError as e:
        out["error"] = f"Port 443 unreachable: {e.strerror or e}"
        return out

    if verify_error is not None:
        out["error"] = f"Certificate verification failed: {verify_error.verify_message or verify_error.reason}"
        code = getattr(verify_error, "verify_code", None)
        if code in (18, 19):
            out["self_signed"] = True
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip or host, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as s:
                    der = s.getpeercert(binary_form=True)
                    out["protocol"] = s.version()
                    out["cipher"] = (s.cipher() or [None])[0]
        except Exception as e:
            out["error"] += f"; retry failed: {e}"
    out["enabled"] = der is not None
    if not der:
        return out
    try:
        cert = _decode_der(der)
    except Exception as e:
        out["error"] = (out["error"] or "") + f" (could not decode cert: {e})"
        return out
    issuer = _name(cert.get("issuer"))
    subject = _name(cert.get("subject"))
    out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    out["issuer_org"] = issuer.get("organizationName")
    out["issuer_cn"] = issuer.get("commonName")
    out["subject"] = subject.get("commonName") or subject.get("organizationName")
    out["subject_org"] = subject.get("organizationName")
    out["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:50]
    out["serial"] = cert.get("serialNumber")
    try:
        nb = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
        na = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        now = _now()
        out["not_before"], out["not_after"] = _iso(nb), _iso(na)
        out["days_left"] = (na - now).days
        out["age_days"] = (now - nb).days
        out["validity_days"] = (na - nb).days
        if na < now and out["valid"] is False and not out["error"]:
            out["error"] = "Certificate expired"
    except Exception:
        pass
    if issuer and issuer == subject:
        out["self_signed"] = True
    # free DV / EV hint
    org = (out["issuer"] or "").lower()
    out["free_cert"] = any(x in org for x in ("let's encrypt", "zerossl", "cloudflare", "google trust", "buypass"))
    return out


async def ssl_lookup(host: str, timeout: float, port: int = 443) -> dict:
    key = f"{host}:{port}"
    c = SSL_CACHE.get(key)
    if c:
        return c
    try:  # SSRF guard: only public addresses, and connect to the validated IP
        ips = await net_safety.check_host(host, port, timeout=min(4.0, timeout))
    except net_safety.UnsafeTarget as e:
        return {**_empty_ssl(e.error), "blocked": True}
    except net_safety.ResolutionError as e:
        return _empty_ssl(str(e))
    res = await asyncio.wait_for(asyncio.to_thread(_ssl_sync, host, port, timeout, ips[0]), timeout + 1)
    SSL_CACHE.set(key, res)
    return res


# --------------------------------------------------------------------------------------------- HTTP


UGC_HOSTS = {"sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "storage.googleapis.com",
             "firebasestorage.googleapis.com", "script.google.com", "raw.githubusercontent.com", "gist.github.com",
             "dl.dropboxusercontent.com", "dropboxusercontent.com", "forms.office.com", "1drv.ms", "onedrive.live.com",
             "s3.amazonaws.com", "translate.goog", "googleusercontent.com", "blob.core.windows.net",
             "web.core.windows.net", "sharepoint.com", "my.sharepoint.com", "github.io", "pages.github.com"}


def is_ugc_host(host: str) -> bool:
    host = (host or "").lower()
    return any(host == h or host.endswith("." + h) for h in UGC_HOSTS)


def _same_site(a: str, b: str) -> bool:
    if not a or not b:
        return True
    return _registered(a) == _registered(b)


async def http_probe(url: str, timeout: float) -> tuple[dict, str]:
    """Fetch URL following redirects manually; every hop passes the SSRF guard. Returns (http_info, html_text)."""
    info: dict = {"reachable": False, "final_url": None, "status_code": None, "response_ms": None,
                  "redirect_chain": [], "server": None, "content_type": None, "title": None,
                  "security_headers": {}, "technologies": [], "forms": {"count": 0, "password_fields": 0,
                                                                        "external_actions": 0, "login_form": False},
                  "links": {"internal": 0, "external": 0, "null_links": 0, "external_ratio": 0.0},
                  "iframes": 0, "hidden_iframes": 0, "external_scripts": 0, "meta_refresh": None, "page_size_kb": 0,
                  "favicon_external": False, "suspicious_js": [], "error": None, "cross_domain_redirects": 0,
                  "headers": {}}
    headers = {"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.9"}
    r = await net_safety.fetch(url, headers=headers, timeout=timeout, max_bytes=MAX_BODY, max_redirects=10,
                               same_site=_same_site)
    info["redirect_chain"] = r.chain
    info["cross_domain_redirects"] = r.cross_domain_redirects
    info["response_ms"] = r.elapsed_ms
    info["error"] = r.error
    if r.blocked is not None:  # a hop (or the start URL) points at a non-public address / forbidden port
        info.update(blocked=True, blocked_reason=r.blocked.reason, blocked_kind=r.blocked.kind,
                    blocked_url=r.blocked.url, error=r.blocked.error)
        return info, ""
    if r.status is None or r.headers is None:
        return info, ""
    current = r.final_url or url
    body = r.body
    info["reachable"] = True
    info["final_url"] = current
    info["status_code"] = r.status
    h = r.headers
    info["server"] = h.get("server")
    info["content_type"] = h.get("content-type")
    info["security_headers"] = {
        "hsts": "strict-transport-security" in h, "csp": "content-security-policy" in h,
        "x_frame_options": "x-frame-options" in h, "x_content_type_options": "x-content-type-options" in h,
        "referrer_policy": "referrer-policy" in h, "permissions_policy": "permissions-policy" in h,
    }
    keep = ["server", "content-type", "x-powered-by", "via", "cf-ray", "x-cache", "strict-transport-security",
            "content-security-policy", "x-frame-options", "set-cookie", "x-generator", "cache-control", "location"]
    info["headers"] = {k: (h.get(k) or "")[:300] for k in keep if k in h}
    info["page_size_kb"] = round(len(body) / 1024, 1)
    enc = r.encoding or "utf-8"
    try:
        text = body.decode(enc, "replace")
    except Exception:
        text = body.decode("utf-8", "replace")
    techs = _fingerprint(h, text)
    if "html" in (info["content_type"] or "html").lower() or text.lstrip()[:200].lower().startswith(("<!doctype", "<html")):
        try:
            _analyse_html(info, text, current)
        except Exception as e:
            info["error"] = (info["error"] or "") + f" html-parse: {e}"
    info["technologies"] = techs
    return info, text


def _fingerprint(h: httpx.Headers, text: str) -> list[str]:
    t: list[str] = []
    server = (h.get("server") or "").lower()
    powered = (h.get("x-powered-by") or "").lower()
    cookies = " ".join(h.get_list("set-cookie")).lower() if hasattr(h, "get_list") else (h.get("set-cookie") or "").lower()
    for name, cond in [
        ("Cloudflare", "cloudflare" in server or "cf-ray" in h), ("nginx", "nginx" in server),
        ("Apache", "apache" in server), ("Microsoft IIS", "iis" in server), ("LiteSpeed", "litespeed" in server),
        ("OpenResty", "openresty" in server), ("Caddy", "caddy" in server), ("gws (Google)", server == "gws"),
        ("Envoy", "envoy" in server), ("AmazonS3", "amazons3" in server), ("Vercel", "x-vercel-id" in h or "vercel" in server),
        ("Netlify", "x-nf-request-id" in h or "netlify" in server), ("GitHub infrastructure", "x-github-request-id" in h),
        ("Amazon CloudFront", "x-amz-cf-id" in h), ("Akamai", "akamai" in server or "x-akamai-transformed" in h),
        ("Fastly", "x-fastly-request-id" in h or "fastly" in (h.get("via") or "").lower()),
        ("Varnish", "varnish" in (h.get("via") or "").lower() or "x-varnish" in h),
        ("Shopify", "x-shopid" in h or "x-shopify-stage" in h), ("PHP", "php" in powered or "phpsessid" in cookies),
        ("ASP.NET", "asp.net" in powered or "x-aspnet-version" in h or "asp.net_sessionid" in cookies),
        ("Express", "express" in powered), ("Next.js", "next.js" in powered), ("Java", "jsessionid" in cookies),
        ("Laravel", "laravel_session" in cookies), ("Django", "csrftoken" in cookies and "django" in text[:50000].lower()),
        ("WordPress", "wordpress" in (h.get("x-generator") or "").lower() or "wp-" in (h.get("link") or "")),
        ("Drupal", "x-drupal-cache" in h or "drupal" in (h.get("x-generator") or "").lower()),
    ]:
        if cond and name not in t:
            t.append(name)
    snippet = text[:400000]
    for name, rx in _TECH_RX:
        if name not in t and rx.search(snippet):
            t.append(name)
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{2,60})', snippet, re.I)
    if m:
        g = m.group(1).strip()
        if not any(g.lower().startswith(x.lower()) for x in t):
            t.append(g)
    return t


def _analyse_html(info: dict, text: str, base_url: str) -> None:
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(text[:MAX_BODY], "html.parser")
    base_host = urlsplit(base_url).hostname or ""
    title = soup.title.string.strip() if soup.title and soup.title.string else None
    info["title"] = title[:300] if title else None

    # forms
    forms = soup.find_all("form")
    pw_total, ext_actions, login, pw_external, sensitive = 0, 0, False, False, set()
    for f in forms:
        action = (f.get("action") or "").strip()
        pw = len(f.find_all("input", attrs={"type": re.compile("^password$", re.I)}))
        pw_total += pw
        external = False
        if action and not action.startswith(("#", "javascript:")):
            if action.startswith("mailto:"):
                external = True
            else:
                ah = urlsplit(urljoin(base_url, action)).hostname or ""
                external = bool(ah) and not _same_site(ah, base_host)
        if external:
            ext_actions += 1
        if pw:
            login = True
            if external:
                pw_external = True
        for inp in f.find_all(["input", "select", "textarea"]):
            attrs = " ".join(str(inp.get(a) or "") for a in ("name", "id", "placeholder", "autocomplete", "aria-label"))
            m = SENSITIVE_INPUT_RX.search(attrs)
            if m:
                sensitive.add(m.group(0).lower())
    # password inputs outside forms (JS-submitted kits)
    loose_pw = len(soup.find_all("input", attrs={"type": re.compile("^password$", re.I)})) - pw_total
    if loose_pw > 0:
        pw_total += loose_pw
        login = True
    info["forms"] = {"count": len(forms), "password_fields": pw_total, "external_actions": ext_actions,
                     "login_form": login, "password_to_external": pw_external, "sensitive_inputs": sorted(sensitive)[:10]}

    # links
    internal = external = null = 0
    for a in soup.find_all("a"):
        href = (a.get("href") or "").strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
            null += 1
            continue
        if href.startswith(("mailto:", "tel:")):
            continue
        hh = urlsplit(urljoin(base_url, href)).hostname or ""
        if not hh or _same_site(hh, base_host):
            internal += 1
        else:
            external += 1
    total = internal + external + null
    info["links"] = {"internal": internal, "external": external, "null_links": null,
                     "external_ratio": round(external / total, 3) if total else 0.0,
                     "null_ratio": round(null / total, 3) if total else 0.0, "total": total}

    # iframes
    ifr = soup.find_all("iframe")
    hidden = 0
    for i in ifr:
        st = (i.get("style") or "").replace(" ", "").lower()
        if i.get("width") in ("0", "1") or i.get("height") in ("0", "1") or "display:none" in st or \
                "visibility:hidden" in st or i.has_attr("hidden"):
            hidden += 1
    info["iframes"], info["hidden_iframes"] = len(ifr), hidden

    # scripts
    ext_scripts = 0
    inline_js = []
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            sh = urlsplit(urljoin(base_url, src)).hostname or ""
            if sh and not _same_site(sh, base_host):
                ext_scripts += 1
        elif s.string:
            inline_js.append(s.string)
    info["external_scripts"] = ext_scripts

    # meta refresh
    for m in soup.find_all("meta"):
        if (m.get("http-equiv") or "").lower() == "refresh":
            content = m.get("content") or ""
            mm = re.search(r"url\s*=\s*['\"]?([^'\"\s>]+)", content, re.I)
            target = urljoin(base_url, mm.group(1)) if mm else None
            info["meta_refresh"] = {"content": content[:200], "target": target,
                                    "external": bool(target) and not _same_site(urlsplit(target).hostname or "", base_host)}
            break

    # favicon
    for l in soup.find_all("link"):
        rel = " ".join(l.get("rel") or []).lower()
        if "icon" in rel and l.get("href"):
            fh = urlsplit(urljoin(base_url, l["href"])).hostname or ""
            info["favicon_external"] = bool(fh) and not _same_site(fh, base_host)
            info["favicon_url"] = urljoin(base_url, l["href"])[:300]
            break

    # suspicious JS (inline scripts + event handler attributes)
    js_blob = "\n".join(inline_js)[:600000]
    attr_js = " ".join(f"{k}={v}" for tag in soup.find_all(True)[:5000] for k, v in tag.attrs.items()
                       if isinstance(k, str) and k.startswith("on") and isinstance(v, str))
    blob = js_blob + "\n" + attr_js
    found = []
    for pid, rx, desc in _JS_RX:
        if rx.search(blob):
            found.append({"id": pid, "description": desc})
    info["suspicious_js"] = found

    # visible text features
    try:
        for t in soup(["script", "style", "noscript"]):
            t.decompose()
        vis = " ".join(soup.get_text(" ").split())[:30000]
    except Exception:
        vis = ""
    low = vis.lower()
    info["urgency_phrases"] = [p for p in URGENCY_PHRASES if p in low][:10]
    info["text_length"] = len(vis)
    info["_visible_text"] = vis[:20000]


# --------------------------------------------------------------------------------------------- reputation


async def gsb_lookup(url: str, key: str, timeout: float) -> dict:
    body = {"client": {"clientId": "phishguard", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                           "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": url}]}}
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": key}, json=body)
    if r.status_code != 200:
        return {"name": "Google Safe Browsing", "listed": False, "detail": f"API error HTTP {r.status_code}", "error": True}
    matches = r.json().get("matches") or []
    if matches:
        types = sorted({m.get("threatType", "") for m in matches})
        return {"name": "Google Safe Browsing", "listed": True, "detail": "Flagged: " + ", ".join(types)}
    return {"name": "Google Safe Browsing", "listed": False, "detail": "No threats found"}


async def vt_lookup(url: str, key: str, timeout: float) -> dict:
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    async with httpx.AsyncClient(timeout=timeout, headers={"x-apikey": key}) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/urls/{uid}")
        if r.status_code == 404:
            # submit for analysis (best-effort), report not found
            try:
                await c.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, timeout=min(3.0, timeout))
            except Exception:
                pass
            return {"name": "VirusTotal", "listed": False, "detail": "URL not yet known to VirusTotal (submitted for analysis)"}
    if r.status_code != 200:
        return {"name": "VirusTotal", "listed": False, "detail": f"API error HTTP {r.status_code}", "error": True}
    attrs = (r.json().get("data") or {}).get("attributes") or {}
    st = attrs.get("last_analysis_stats") or {}
    mal, sus = int(st.get("malicious", 0)), int(st.get("suspicious", 0))
    total = sum(int(v) for v in st.values() if isinstance(v, int))
    listed = mal >= 2 or (mal + sus) >= 3
    return {"name": "VirusTotal", "listed": listed,
            "detail": f"{mal} malicious, {sus} suspicious of {total} engines", "malicious": mal, "suspicious": sus,
            "engines": total}


# --------------------------------------------------------------------------------------------- orchestration


async def _guard(coro, timeout: float, name: str, errors: dict):
    try:
        return await asyncio.wait_for(coro, timeout)
    except asyncio.TimeoutError:
        errors[name] = f"timed out after {timeout:.1f}s"
    except Exception as e:
        errors[name] = f"{type(e).__name__}: {e}"[:300]
    return None


def _empty_ssl(err=None):
    return {"enabled": False, "valid": False, "issuer": None, "subject": None, "san": [], "not_before": None,
            "not_after": None, "days_left": None, "age_days": None, "protocol": None, "self_signed": False, "error": err}


def _empty_http(err=None):
    return {"reachable": False, "final_url": None, "status_code": None, "response_ms": None, "redirect_chain": [],
            "server": None, "title": None, "security_headers": {k: False for k in (
                "hsts", "csp", "x_frame_options", "x_content_type_options", "referrer_policy", "permissions_policy")},
            "technologies": [], "forms": {"count": 0, "password_fields": 0, "external_actions": 0, "login_form": False},
            "links": {"internal": 0, "external": 0, "null_links": 0, "external_ratio": 0.0}, "iframes": 0,
            "external_scripts": 0, "meta_refresh": None, "page_size_kb": 0, "favicon_external": False,
            "suspicious_js": [], "error": err}


def _empty_whois(err=None):
    return {"registrar": None, "creation_date": None, "expiry_date": None, "updated_date": None, "age_days": None,
            "days_to_expiry": None, "privacy_protected": None, "country": None, "error": err}


def _empty_geo():
    return {"country": None, "country_code": None, "city": None, "asn": None, "org": None, "isp": None,
            "lat": None, "lon": None, "hosting": None}


async def run_checks(url: str, settings: dict) -> dict:
    """Run all checks. Never raises."""
    t0 = time.perf_counter()
    try:
        settings = settings or {}
        timeout = float(settings.get("timeout_s") or 8)
        budget = max(timeout + 2, TOTAL_BUDGET_S)
        res = await asyncio.wait_for(_run(url, settings), budget + 3)
    except Exception as e:
        res = _fallback(url, settings or {}, f"{type(e).__name__}: {e}")
    res["timings"] = {**(res.get("timings") or {}), "total_ms": int((time.perf_counter() - t0) * 1000)}
    return _jsonable(res)


def _fallback(url, settings, err):
    try:
        u = normalize_url(url)
        di = parse_domain(u)
    except Exception:
        u, di = url, {"domain": None, "registered_domain": None, "subdomain": None, "tld": None, "is_ip": False,
                      "punycode": None, "ip": None}
    di.update({"whois": _empty_whois(err), "dns": {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": []},
               "geo": _empty_geo()})
    return {"url": u, "domain_info": di, "ssl": _empty_ssl(err), "http": _empty_http(err),
            "brand": {"impersonated_brand": None, "similarity": 0, "technique": None, "details": ""},
            "reputation": {"blacklisted": False, "sources": [], "engines": [],
                           "engine_ratio": {"flagged": 0, "total": 0}}, "screenshot_url": None,
            "checks": [_check("engine", "network", "Analysis engine", "error", err, 0)], "heuristic_score": 0,
            "errors": {"engine": err}, "dom_html": None, "content": None, "summary_points": [],
            "popularity": {"rank": None, "tier": None, "source": "Tranco"},
            "coverage": {"network": False, "checks_total": 1, "checks_errored": 1}}


async def _target_block(url: str, host: str, timeout: float):
    """SSRF pre-check of the scanned URL -> UnsafeTarget or None. Address problems are checked before the port
    so that e.g. http://127.0.0.1:8000/ is reported as a private host."""
    reason = net_safety.literal_block_reason(host)
    if reason:
        return net_safety.UnsafeTarget(reason, kind="address", url=url, host=host)
    sp = urlsplit(url)
    port = net_safety.port_of(sp)
    try:
        ips = await net_safety.resolve(host, port or 443, timeout)
    except net_safety.ResolutionError:
        ips = []  # DNS failure is reported by the normal probes, not as a block
    for ip in ips:
        r = net_safety.ip_block_reason(ip)
        if r:
            return net_safety.UnsafeTarget(f"{host} resolves to {ip} ({r})", kind="address", url=url, host=host, ip=ip)
    if port not in net_safety.ALLOWED_PORTS:
        return net_safety.UnsafeTarget(f"port {port} not allowed (only 80, 443, 8080, 8443)", kind="port", url=url,
                                       host=host, port=port)
    return None


def _engines(sources: list[dict], dnsbl_results: list[dict]) -> tuple[list[dict], dict]:
    """reputation.engines (one per local feed + API lookups + DNSBL zones) and engine_ratio."""
    engines = []
    for s in sources:
        listed = None if s.get("error") else bool(s.get("listed"))
        cat = "error" if listed is None else "clean" if not listed else "malware" if s["name"] == "URLhaus" else "phishing"
        engines.append({"name": s["name"], "type": "feed" if s["name"] in feeds.FEEDS else "api", "listed": listed,
                        "detail": s.get("detail") or "", "category": cat})
    for e in dnsbl_results:
        if not isinstance(e, dict) or e.get("not_applicable"):
            continue
        engines.append({"name": e.get("name"), "type": "dnsbl", "listed": e.get("listed"),
                        "detail": e.get("detail") or "", "category": e.get("category") or "error"})
    definite = [e for e in engines if e["listed"] is not None]
    return engines, {"flagged": sum(1 for e in definite if e["listed"]), "total": len(definite)}


# Plain-English titles for failing/warning checks whose name is phrased as the "good" outcome.
_BAD_TITLE = {
    "ip_host": "Hostname is a raw IP address", "at_symbol": "URL contains an '@' symbol",
    "punycode": "Punycode / look-alike (IDN homograph) domain", "shortener": "URL shortener hides the real destination",
    "https_scheme": "Page is not served over HTTPS", "port": "Non-standard port in the URL",
    "embedded_url": "Another URL is embedded in the path", "random_domain": "Domain name looks auto-generated",
    "file_download": "URL points to an executable/archive download", "free_hosting": "Hosted on free / dynamic hosting",
    "suspicious_tld": "High-risk top-level domain", "blacklist": "Listed on threat-intelligence blocklists",
    "domain_age": "Domain age", "ssl_valid": "SSL certificate is not valid", "ssl_self_signed": "Self-signed SSL certificate",
    "ssl_enabled": "HTTPS is not available", "dns_resolves": "Domain does not resolve in DNS",
    "reachable": "Website could not be reached", "password_external": "Form sends data to an external domain",
    "dnsbl_listed": "Listed on DNS blocklists", "engine_ratio": "Flagged by reputation engines",
    "private_network_host": "Host resolves to a private/internal network address",
}


def _summary_points(checks: list[dict], content_points: list[str], brand: dict, pop: dict) -> list[str]:
    """Up to 10 plain-English facts, most severe first (fails by weight, content findings, warnings, positives)."""
    def text(c):
        title = _BAD_TITLE.get(c["id"], c.get("name") or c["id"])
        d = str(c.get("detail") or "").strip()
        return f"{title} – {d}" if d and d.lower() != title.lower() else title

    fails = sorted((c for c in checks if c.get("status") == "fail"), key=lambda c: -(c.get("weight") or 0))
    warns = sorted((c for c in checks if c.get("status") == "warn"), key=lambda c: -(c.get("weight") or 0))
    pts = [text(c) for c in fails] + [str(p) for p in content_points if p] + [text(c) for c in warns if c.get("weight")]
    rank = pop.get("rank")
    if brand.get("official_domain") and brand.get("details"):
        pts.append(str(brand["details"]))
    if rank and rank <= 10000:
        pts.append(f"Popular website – Tranco rank #{rank} (top 10k)")
    if not fails:
        pts.append("No high-risk indicators were found")
    out: list[str] = []
    for p in pts:
        if p not in out:
            out.append(p)
    return out[:10]


async def _run(raw_url: str, settings: dict) -> dict:
    timings: dict[str, int] = {}
    errors: dict[str, str] = {}
    timeout = float(settings.get("timeout_s") or 8)
    timeout = max(2.0, min(timeout, 20.0))
    network = bool(settings.get("enable_network_checks", True))
    use_dnsbl = bool(settings.get("enable_dnsbl", True))
    use_rdap = bool(settings.get("enable_rdap", True))
    url = normalize_url(raw_url)
    di = parse_domain(url)
    host = di["domain"]
    reg = di.get("registered_domain")

    async def timed(name, coro, to):
        t = time.perf_counter()
        r = await _guard(coro, to, name, errors)
        timings[f"{name}_ms"] = int((time.perf_counter() - t) * 1000)
        return r

    def skip():
        return asyncio.sleep(0, None)

    # local lookups in threads (first call loads the feed sets / Tranco index from disk)
    feeds_task = asyncio.create_task(timed("feeds", asyncio.to_thread(feeds.lookup, url), max(timeout, 6)))
    pop_task = asyncio.create_task(timed("popularity", asyncio.to_thread(popularity.lookup, host or ""), 3.0))

    dns_info = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": []}
    whois_info = _empty_whois()
    geo = _empty_geo()
    ssl_info = _empty_ssl("Network checks disabled" if not network else None)
    http_info = _empty_http("Network checks disabled" if not network else None)
    html = ""
    rep_sources: list[dict] = []
    dnsbl_results: list[dict] = []

    # SSRF guard: never contact private/internal targets (lexical + third-party lookups still run)
    blocked = None
    literal_blocked = bool(host) and net_safety.literal_block_reason(host) is not None
    if network and host:
        blocked = await timed("net_safety", _target_block(url, host, min(timeout, 4)), min(timeout, 4) + 0.5)
    if blocked is not None:
        errors["network"] = f"{blocked.error} – live probes of the site skipped ({blocked.reason})"
        ssl_info = {**_empty_ssl(blocked.error), "blocked": True}
        http_info = {**_empty_http(blocked.error), "blocked": True, "blocked_reason": blocked.reason,
                     "blocked_kind": blocked.kind}

    if network and host and not literal_blocked:
        async def dns_geo():
            d = None
            ip = di["ip"]
            if not di["is_ip"]:
                d = await timed("dns", dns_lookup(host, min(timeout, 5)), min(timeout, 5) + 0.5)
                if d and (d.get("a") or d.get("aaaa")):
                    ip = (d.get("a") or d.get("aaaa"))[0]
            g = ip_bl = None
            if ip and net_safety.is_public_ip(ip):
                g, ip_bl = await asyncio.gather(
                    timed("geo", geo_lookup(ip, min(timeout, 4)), min(timeout, 4) + 0.5),
                    timed("dnsbl_ip", dnsbl.check_ip(ip, 2.0), 4.0) if use_dnsbl and ":" not in ip else skip())
            return d, ip, g, ip_bl

        gsb_key = settings.get("google_safe_browsing_api_key")
        vt_key = settings.get("virustotal_api_key")
        tasks = [
            dns_geo(),
            timed("whois", whois_lookup(reg, min(timeout, 4.5), use_rdap), min(timeout, 4.5) + 5)
            if not di["is_ip"] and reg else skip(),
            timed("ssl", ssl_lookup(host, min(timeout, 5), 443), min(timeout, 5) + 1.5) if blocked is None else skip(),
            timed("http", http_probe(url, timeout), timeout + 1) if blocked is None else skip(),
            timed("dnsbl", dnsbl.check_domain(reg, 2.0), 4.0) if use_dnsbl and not di["is_ip"] and reg else skip(),
            timed("gsb", gsb_lookup(url, gsb_key, min(timeout, 5)), min(timeout, 5) + 0.5) if gsb_key else skip(),
            timed("virustotal", vt_lookup(url, vt_key, min(timeout, 6)), min(timeout, 6) + 0.5) if vt_key else skip(),
        ]
        dg, w, s, h, dbl, g_res, vt_res = await asyncio.gather(*tasks, return_exceptions=True)
        if isinstance(dbl, list):
            dnsbl_results += dbl
        if isinstance(dg, tuple):
            d, ip, g, ip_bl = dg
            if d:
                dns_info = d
            if ip:
                di["ip"] = ip
            if g:
                geo = g
            if isinstance(ip_bl, list):
                dnsbl_results += ip_bl
        if isinstance(w, dict):
            whois_info = w
        elif not di["is_ip"]:
            whois_info = _empty_whois(errors.get("whois", "WHOIS unavailable"))
        if blocked is None:
            ssl_info = s if isinstance(s, dict) else _empty_ssl(errors.get("ssl", "SSL check failed"))
            if isinstance(h, tuple):
                http_info, html = h
            else:
                http_info = _empty_http(errors.get("http", "HTTP probe failed"))
        for r in (g_res, vt_res):
            if isinstance(r, dict):
                rep_sources.append(r)
        if gsb_key and not isinstance(g_res, dict):
            rep_sources.append({"name": "Google Safe Browsing", "listed": False,
                                "detail": f"Lookup failed: {errors.get('gsb', 'error')}", "error": True})
        if vt_key and not isinstance(vt_res, dict):
            rep_sources.append({"name": "VirusTotal", "listed": False,
                                "detail": f"Lookup failed: {errors.get('virustotal', 'error')}", "error": True})

    feed_hits = await feeds_task or []
    listed_names = {f["name"] for f in feed_hits}
    sources = []
    for f in feeds.FEEDS:
        hit = next((x for x in feed_hits if x["name"] == f), None)
        sources.append(hit or {"name": f, "listed": False, "detail": "Not listed"})
    sources += rep_sources
    blacklisted = any(s.get("listed") for s in sources)
    pop = await pop_task or {"rank": None, "tier": None, "source": "Tranco", "note": "Tranco lookup unavailable"}

    # brand detection: URL first, then page title/content on the final URL
    visible = http_info.pop("_visible_text", "") if isinstance(http_info, dict) else ""
    brand = detect_brand(url)
    final_url = http_info.get("final_url") or url
    final_host = (urlsplit(final_url).hostname or host or "").lower()
    if not brand.get("impersonated_brand") and not brand.get("official_domain"):
        if final_url != url:
            fb = detect_brand(final_url)
            if fb.get("impersonated_brand") or fb.get("official_domain"):
                brand = dict(fb)
                brand["details"] = "(final URL) " + brand["details"]
        if not brand.get("impersonated_brand") and not brand.get("official_domain") and (http_info.get("title") or visible):
            cb = detect_brand(final_url, http_info.get("title") or "", visible[:20000])
            if cb.get("impersonated_brand"):
                brand = dict(cb)
    brand = dict(brand)
    # defensive registration: look-alike domain that simply redirects to the brand's official site
    if brand.get("impersonated_brand") and http_info.get("reachable") and final_host:
        fin_reg = _registered(final_host)
        legit_of = is_legit_domain(fin_reg, final_host)
        if legit_of and legit_of == brand["impersonated_brand"] and not is_ugc_host(final_host):
            brand["defensive_redirect"] = True
            brand["details"] += f" – but it redirects to the official {legit_of} site ({fin_reg}); likely a defensive registration"

    # page content analysis (ENGINE-B module); never fatal
    content, content_checks, content_points = None, [], []
    for k in ("resources", "contacted_domains", "trackers"):
        http_info.setdefault(k, [])
    if html and http_info.get("reachable"):
        t = time.perf_counter()
        try:
            from .content import analyze_content
            out = await asyncio.wait_for(asyncio.to_thread(
                analyze_content, html, final_url, http_info.get("title"), list(dns_info.get("ns") or [])), 4.0)
            out = out if isinstance(out, dict) else {}
            content = out.get("content") or None
            for k in ("resources", "contacted_domains", "trackers"):
                http_info[k] = list(out.get(k) or [])
            content_checks = [c for c in (out.get("checks") or []) if isinstance(c, dict) and c.get("id")]
            content_points = [str(p) for p in (out.get("summary_points") or []) if p]
        except Exception as e:
            errors["content"] = f"{type(e).__name__}: {e}"[:300]
        timings["content_ms"] = int((time.perf_counter() - t) * 1000)

    di.update({"whois": whois_info, "dns": dns_info, "geo": geo})
    shot = None
    if settings.get("enable_screenshots"):
        shot = f"https://image.thum.io/get/width/1200/crop/800/noanimate/{url}"

    checks = build_checks(url, di, ssl_info, http_info, brand, sources, blacklisted, network, settings)
    ids = {c["id"] for c in checks}

    # SSRF block (start URL or any redirect hop / TLS target)
    hop_blocked = http_info.get("blocked") or ssl_info.get("blocked")
    if blocked is not None and blocked.kind != "address":
        checks.append(_check("private_network_host", "network", "Public network host", "warn",
                             f"{blocked.reason} – live probes skipped for safety", 2))
    elif blocked is not None or hop_blocked:
        why = blocked.reason if blocked is not None else (http_info.get("blocked_reason") or "a redirect hop / TLS "
                                                          "target resolves to a non-public address")
        checks.append(_check("private_network_host", "network", "Host resolves to a private/internal network address",
                             "fail", f"{why} – the site was not contacted", 8))
    elif network and host:
        checks.append(_check("private_network_host", "network", "Public network host", "pass",
                             "Host resolves to public internet addresses", 0))

    # popularity (Tranco)
    rank = pop.get("rank")
    if rank:
        strong = rank <= 10000
        checks.append(_check("popular_site", "reputation", "Popular website (Tranco)", "pass",
                             f"Tranco rank #{rank} ({pop.get('tier')})" +
                             (" – one of the most visited sites on the web (strong safe signal)" if strong else ""), 0))
    else:
        checks.append(_check("popular_site", "reputation", "Popular website (Tranco)", "info",
                             pop.get("note") or "Not in the Tranco top 1M list", 0))

    # DNS blocklists + multi-engine ratio
    engines, ratio = _engines(sources, dnsbl_results)
    bl_hits = [e for e in dnsbl_results if e.get("listed")]
    if bl_hits:
        checks.append(_check("dnsbl_listed", "reputation", "DNS blocklists",
                             "warn" if all(e.get("abused_legit") for e in bl_hits) else "fail",
                             "; ".join(f"{e['name']}: {e.get('detail')}" for e in bl_hits), 8))
    elif any(e.get("listed") is False for e in dnsbl_results):
        n = sum(1 for e in dnsbl_results if e.get("listed") is False)
        checks.append(_check("dnsbl_listed", "reputation", "DNS blocklists", "pass", f"Not listed on {n} DNS blocklist(s)", 0))
    if ratio["total"]:
        checks.append(_check("engine_ratio", "reputation", "Reputation engines", "fail" if ratio["flagged"] else "pass",
                             f"{ratio['flagged']}/{ratio['total']} engines flagged this URL", 0))

    # content checks from ENGINE-B (count in heuristic_score); skip ids we already have
    for c in content_checks:
        if c["id"] in ids:
            continue
        st = c.get("status") if c.get("status") in ("pass", "warn", "fail", "info", "error") else "info"
        try:
            wt = int(c.get("weight") or 0)
        except (TypeError, ValueError):
            wt = 0
        checks.append({**c, **_check(c["id"], c.get("category") or "content", c.get("name") or c["id"], st,
                                     c.get("detail") or "", wt)})

    score, reasons = score_checks(checks, di, brand, blacklisted, http_info, ssl_info, network, popularity_info=pop)
    dom_html = None
    if html:
        raw = html.encode("utf-8", "ignore")
        dom_html = html if len(raw) <= MAX_DOM else raw[:MAX_DOM].decode("utf-8", "ignore")
    return {
        "url": url,
        "domain_info": di,
        "ssl": ssl_info,
        "http": http_info,
        "brand": brand,
        "reputation": {"blacklisted": blacklisted, "sources": sources, "feeds_listed": sorted(listed_names),
                       "engines": engines, "engine_ratio": ratio},
        "screenshot_url": shot,
        "checks": checks,
        "heuristic_score": score,
        "score_reasons": reasons,
        "network_checks": network,
        "timings": timings,
        "errors": errors,
        "dom_html": dom_html,
        "popularity": pop,
        "content": content,
        "summary_points": _summary_points(checks, content_points, brand, pop),
        "coverage": {"network": bool(network and blocked is None), "checks_total": len(checks),
                     "checks_errored": sum(1 for c in checks if c.get("status") == "error")},
    }


# --------------------------------------------------------------------------------------------- checks


def build_checks(url, di, ssl_info, http_info, brand, sources, blacklisted, network, settings) -> list[dict]:
    C = []
    sp = urlsplit(url)
    host = di.get("domain") or ""
    reg = di.get("registered_domain") or ""
    tld = (di.get("tld") or "").lower()
    last_tld = tld.split(".")[-1] if tld else ""
    path_q = (sp.path or "") + ("?" + sp.query if sp.query else "")
    lower_url = url.lower()
    official = brand.get("official_domain") and not is_ugc_host(host)

    # ---------------- lexical
    L = len(url)
    C.append(_check("url_length", "lexical", "URL length", "fail" if L > 120 else "warn" if L > 75 else "pass",
                    f"{L} characters" + (" (long URLs often hide the real domain)" if L > 75 else ""), 3))
    C.append(_check("ip_host", "lexical", "Hostname is not a raw IP address", "fail" if di.get("is_ip") else "pass",
                    f"Host is IP address {di.get('ip')}" if di.get("is_ip") else "Host is a domain name", 9))
    at = "@" in (sp.netloc or "") or "@" in sp.path
    C.append(_check("at_symbol", "lexical", "No '@' in URL", "fail" if at else "pass",
                    "'@' makes browsers ignore everything before it" if at else "No '@' symbol", 6))
    sub = di.get("subdomain") or ""
    nsub = len([s for s in sub.split(".") if s and s != "www"]) if sub else 0
    C.append(_check("subdomain_count", "lexical", "Subdomain depth",
                    "fail" if nsub >= 4 else "warn" if nsub >= 3 else "pass", f"{nsub} subdomain level(s)", 4))
    label = reg.split(".")[0] if reg else ""
    hy = host.count("-")
    C.append(_check("hyphens", "lexical", "Hyphens in hostname", "fail" if hy >= 4 else "warn" if hy >= 2 else "pass",
                    f"{hy} hyphen(s) in hostname", 3))
    if not di.get("is_ip"):
        st = "fail" if last_tld in HIGH_RISK_TLDS else "warn" if last_tld in SUSPICIOUS_TLDS else "pass"
        C.append(_check("suspicious_tld", "lexical", "Top-level domain reputation", st,
                        f".{tld} is {'heavily abused for phishing' if st == 'fail' else 'frequently abused' if st == 'warn' else 'a common TLD'}",
                        6))
    puny = "xn--" in host
    C.append(_check("punycode", "lexical", "No punycode / IDN homograph", "fail" if puny else "pass",
                    f"Punycode host decodes to '{di.get('punycode')}'" if puny else "ASCII hostname", 7))
    short = host in SHORTENERS or reg in SHORTENERS
    C.append(_check("shortener", "lexical", "Not a URL shortener", "warn" if short else "pass",
                    f"{reg} is a URL shortening service – destination hidden" if short else "Not a known shortener", 4))
    C.append(_check("https_scheme", "lexical", "Uses HTTPS", "pass" if sp.scheme == "https" else "warn",
                    f"Scheme is {sp.scheme}", 2))
    try:
        port = sp.port
    except ValueError:
        port = None
    C.append(_check("port", "lexical", "Standard port", "warn" if port and port not in (80, 443) else "pass",
                    f"Non-standard port {port}" if port and port not in (80, 443) else "Default port", 4))
    words = sorted({w for w in SENSITIVE_WORDS if w in lower_url.replace(reg, "") or w in (sub or "").lower()})
    if official:
        words = []
    C.append(_check("sensitive_words", "lexical", "Sensitive keywords in URL",
                    "fail" if len(words) >= 3 else "warn" if words else "pass",
                    ("Contains: " + ", ".join(words[:8])) if words else "None found", 4))
    embedded = bool(re.search(r"(https?:|www\.)", path_q[1:] if path_q else "", re.I)) or "//" in (sp.path or "")[1:]
    C.append(_check("embedded_url", "lexical", "No embedded URL / redirect in path", "warn" if embedded else "pass",
                    "Path/query contains another URL or '//' (open-redirect pattern)" if embedded else "Clean path", 3))
    ent = _entropy(label)
    digits = sum(ch.isdigit() for ch in label)
    rand = (len(label) >= 12 and ent > 3.8) or digits >= 5 or bool(re.search(r"[bcdfghjklmnpqrstvwxz]{6,}", label))
    if not di.get("is_ip"):
        C.append(_check("random_domain", "lexical", "Domain looks human-readable", "warn" if rand else "pass",
                        f"Label '{label}' entropy {ent:.2f}, {digits} digit(s)" + (" – looks auto-generated" if rand else ""), 3))
    pct = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    C.append(_check("encoding", "lexical", "Excessive URL encoding", "warn" if pct > 6 else "pass",
                    f"{pct} percent-encoded characters", 2))
    ext_hit = next((e for e in SUSPICIOUS_EXT if (sp.path or "").lower().endswith(e)), None)
    C.append(_check("file_download", "lexical", "No executable/archive download", "fail" if ext_hit else "pass",
                    f"URL points to a {ext_hit} file (possible malware)" if ext_hit else "Not a file download", 7))
    fh = next((f for f in FREE_HOSTING if host == f or host.endswith("." + f)), None)
    C.append(_check("free_hosting", "lexical", "Not on free / dynamic hosting",
                    "warn" if fh and not official else "pass",
                    f"Hosted on {fh} (free hosting is heavily abused by phishing kits)" if fh and not official
                    else "Not a free-hosting platform", 4))

    # ---------------- brand
    b = brand.get("impersonated_brand")
    tech = brand.get("technique")
    if official:
        C.append(_check("brand_official", "brand", "Official brand domain", "pass", brand.get("details") or "", 0))
    elif brand.get("official_domain"):
        C.append(_check("brand_official", "brand", "User-generated content on brand domain", "warn",
                        f"{host} serves user-created content (forms, sites, file sharing) – the brand does not vouch for it", 3))
    if b:
        strong = tech in ("typosquat", "homoglyph", "combosquat", "punycode", "subdomain") and \
            not brand.get("defensive_redirect")
        has_form = bool((http_info.get("forms") or {}).get("login_form") or
                        (http_info.get("forms") or {}).get("sensitive_inputs"))
        weak_status = "warn" if (tech != "content" or has_form) else "info"
        C.append(_check("brand_impersonation", "brand", "Brand impersonation",
                        "fail" if strong else weak_status,
                        f"Possible {b} impersonation via {tech} (similarity {brand.get('similarity', 0):.2f}): "
                        f"{brand.get('details')}", 10 if strong else 5 if has_form else 3))
    else:
        C.append(_check("brand_impersonation", "brand", "Brand impersonation", "pass",
                        brand.get("details") or "No brand impersonation detected", 10))

    # ---------------- reputation
    feed_listed = [s for s in sources if s.get("listed") and s["name"] in feeds.FEEDS]
    C.append(_check("blacklist", "reputation", "Threat-intel blocklists",
                    "fail" if feed_listed else "pass",
                    ("Listed in " + ", ".join(f"{s['name']} ({s.get('match', 'url')} match)" for s in feed_listed))
                    if feed_listed else f"Not listed in {len(feeds.FEEDS)} local feeds", 10))
    for s in sources:
        if s["name"] in ("Google Safe Browsing", "VirusTotal"):
            st = "error" if s.get("error") else "fail" if s.get("listed") else "pass"
            C.append(_check("gsb" if s["name"].startswith("Google") else "virustotal", "reputation", s["name"], st,
                            s.get("detail", ""), 10))

    if not network:
        return C

    # ---------------- domain
    w = di.get("whois") or {}
    dns_i = di.get("dns") or {}
    if not di.get("is_ip"):
        age = w.get("age_days")
        if age is None:
            C.append(_check("domain_age", "domain", "Domain age", "error" if w.get("error") else "warn",
                            w.get("error") or "Creation date not available in WHOIS (hidden or unsupported TLD)",
                            2 if not w.get("error") else 0))
        else:
            st = "fail" if age < 30 else "warn" if age < 180 else "pass"
            C.append(_check("domain_age", "domain", "Domain age", st,
                            f"Registered {age} days ago ({w.get('creation_date')})", 9 if st == "fail" else 6))
        rl = w.get("registration_length_days")
        dte = w.get("days_to_expiry")
        if dte is not None:
            st = "warn" if (rl is not None and rl <= 366 and (age or 0) < 365) or dte < 30 else "pass"
            C.append(_check("domain_expiry", "domain", "Registration period", st,
                            f"Expires in {dte} days" + (f"; registered for {rl} days" if rl else ""), 2))
        if w.get("privacy_protected") is not None:
            C.append(_check("whois_privacy", "domain", "WHOIS identity", "info" if w.get("privacy_protected") else "pass",
                            "Registrant hidden behind privacy/redaction service" if w.get("privacy_protected")
                            else f"Registrant visible ({w.get('registrar') or 'registrar unknown'})", 1))
        resolves = bool(dns_i.get("a") or dns_i.get("aaaa"))
        C.append(_check("dns_resolves", "domain", "DNS resolves", "pass" if resolves else "fail",
                        f"A: {', '.join(dns_i.get('a', [])[:3]) or '-'}" if resolves else "No A/AAAA records", 5))
        has_mx = bool(dns_i.get("mx"))
        C.append(_check("mx_records", "domain", "Mail (MX) records", "pass" if has_mx else "info",
                        f"{len(dns_i.get('mx', []))} MX record(s)" if has_mx else "No MX records", 1))
        auth = [n for n in ("spf", "dmarc") if dns_i.get(n)]
        C.append(_check("email_auth", "domain", "SPF / DMARC", "pass" if len(auth) == 2 else "warn" if not auth else "info",
                        f"SPF: {'yes' if dns_i.get('spf') else 'no'}, DMARC: {'yes' if dns_i.get('dmarc') else 'no'}", 1))
        C.append(_check("nameservers", "domain", "Name servers", "pass" if dns_i.get("ns") else "warn",
                        ", ".join(dns_i.get("ns", [])[:4]) or "No NS records", 2))

    # ---------------- network
    geo = di.get("geo") or {}
    if geo.get("country") or geo.get("org"):
        C.append(_check("hosting_geo", "network", "Hosting location", "info",
                        f"{geo.get('city') or ''}{', ' if geo.get('city') else ''}{geo.get('country') or ''} – "
                        f"{geo.get('org') or geo.get('isp') or ''} {geo.get('asn') or ''}"
                        f"{' (datacenter/hosting)' if geo.get('hosting') else ''}".strip(), 0))
    reach = http_info.get("reachable")
    C.append(_check("reachable", "network", "Website reachable", "pass" if reach else "warn",
                    f"HTTP {http_info.get('status_code')} in {http_info.get('response_ms')} ms" if reach
                    else (http_info.get("error") or "Unreachable"), 2))

    # ---------------- ssl
    if ssl_info.get("enabled"):
        C.append(_check("ssl_enabled", "ssl", "HTTPS available", "pass", f"{ssl_info.get('protocol')}", 4))
        C.append(_check("ssl_valid", "ssl", "Valid SSL certificate", "pass" if ssl_info.get("valid") else "fail",
                        f"Issued by {ssl_info.get('issuer')} to {ssl_info.get('subject')}" if ssl_info.get("valid")
                        else (ssl_info.get("error") or "Invalid certificate"), 8))
        if ssl_info.get("self_signed"):
            C.append(_check("ssl_self_signed", "ssl", "Not self-signed", "fail", "Certificate is self-signed", 6))
        ca = ssl_info.get("age_days")
        if ca is not None:
            C.append(_check("ssl_age", "ssl", "Certificate age", "warn" if ca < 7 else "pass",
                            f"Certificate issued {ca} day(s) ago" + (" – brand-new certs are common on phishing sites"
                                                                     if ca < 7 else ""), 3))
        dl = ssl_info.get("days_left")
        if dl is not None:
            C.append(_check("ssl_expiry", "ssl", "Certificate expiry", "fail" if dl < 0 else "warn" if dl < 7 else "pass",
                            f"{dl} day(s) left", 2))
    else:
        C.append(_check("ssl_enabled", "ssl", "HTTPS available", "warn",
                        ssl_info.get("error") or "No TLS on port 443", 4))

    # ---------------- content / http
    if reach:
        chain = http_info.get("redirect_chain") or []
        hops = max(0, len(chain) - 1)
        xd = http_info.get("cross_domain_redirects", 0)
        st = "fail" if xd >= 2 or hops >= 5 else "warn" if xd == 1 or hops >= 3 else "pass"
        C.append(_check("redirects", "content", "Redirect behaviour", st,
                        f"{hops} redirect(s), {xd} to other domain(s); final: {http_info.get('final_url')}", 6))
        sc = http_info.get("status_code") or 0
        C.append(_check("http_status", "content", "HTTP status", "pass" if sc < 400 else "warn", f"HTTP {sc}", 1))
        sh = http_info.get("security_headers") or {}
        n = sum(1 for v in sh.values() if v)
        C.append(_check("security_headers", "content", "Security headers", "pass" if n >= 3 else "warn" if n <= 1 else "info",
                        f"{n}/6 present: " + (", ".join(k for k, v in sh.items() if v) or "none"), 2))
        f = http_info.get("forms") or {}
        if f.get("password_to_external"):
            C.append(_check("password_external", "content", "Password form posts to own domain", "fail",
                            "A password form submits to a different domain – classic credential harvesting", 10))
        elif f.get("external_actions"):
            C.append(_check("password_external", "content", "Forms post to own domain", "warn",
                            f"{f['external_actions']} form(s) submit to external domain", 4))
        else:
            C.append(_check("password_external", "content", "Forms post to own domain", "pass",
                            f"{f.get('count', 0)} form(s), none external", 10))
        if f.get("login_form"):
            st = "pass" if official else "fail" if b else "warn"
            C.append(_check("login_form", "content", "Login form", st,
                            f"{f.get('password_fields')} password field(s)" +
                            (f" on page impersonating {b}" if b and not official else "" if official
                             else " on a non-brand domain – verify before entering credentials"), 6 if st == "fail" else 3))
        sens = f.get("sensitive_inputs") or []
        if sens:
            C.append(_check("sensitive_inputs", "content", "Sensitive data fields", "pass" if official else "fail",
                            "Asks for: " + ", ".join(sens), 6))
        lk = http_info.get("links") or {}
        tot = lk.get("total") or 0
        nr = lk.get("null_ratio", 0)
        C.append(_check("null_links", "content", "Dead/null links", "warn" if tot >= 4 and nr > 0.5 else "pass",
                        f"{lk.get('null_links', 0)} of {tot} links are '#'/javascript: ({nr:.0%})", 3))
        er = lk.get("external_ratio", 0)
        C.append(_check("external_links", "content", "External link ratio",
                        "warn" if tot >= 5 and er > 0.8 and not official else "pass",
                        f"{lk.get('external', 0)} external / {tot} total ({er:.0%})", 2))
        if http_info.get("hidden_iframes"):
            C.append(_check("hidden_iframes", "content", "Hidden iframes", "warn",
                            f"{http_info['hidden_iframes']} hidden iframe(s)", 3))
        sj = http_info.get("suspicious_js") or []
        C.append(_check("suspicious_js", "content", "Suspicious JavaScript",
                        "fail" if any(x["id"] in ("telegram_exfil", "discord_webhook", "keylogger", "eval_atob",
                                                  "docwrite_unescape", "location_obfuscated", "packer") for x in sj)
                        else "warn" if sj else "pass",
                        "; ".join(x["description"] for x in sj) if sj else "No obfuscation patterns found", 7))
        mr = http_info.get("meta_refresh")
        if mr:
            C.append(_check("meta_refresh", "content", "Meta refresh redirect", "warn" if mr.get("external") else "info",
                            f"Refresh to {mr.get('target') or mr.get('content')}", 3))
        if http_info.get("favicon_external"):
            C.append(_check("favicon_external", "content", "Favicon from external domain",
                            "warn" if not official else "info", f"Favicon loaded from {http_info.get('favicon_url')}", 3))
        urg = http_info.get("urgency_phrases") or []
        if urg:
            C.append(_check("urgency_language", "content", "Urgency / social-engineering language",
                            "warn" if not official else "info", "Found: " + ", ".join(f"“{u}”" for u in urg[:5]), 3))
    return C


def score_checks(checks, di, brand, blacklisted, http_info, ssl_info, network,
                 popularity_info: dict | None = None) -> tuple[int, list[str]]:
    raw = 0.0
    for c in checks:
        if c["status"] == "fail":
            raw += c["weight"]
        elif c["status"] == "warn":
            raw += c["weight"] * 0.4
    score = 100 * (1 - math.exp(-raw / 18.0))
    reasons = []
    by = {c["id"]: c for c in checks}

    def floor(v, why):
        nonlocal score
        if score < v:
            score = v
        reasons.append(why)

    if blacklisted:
        floor(92, "Listed on threat-intelligence blocklist")
    if brand.get("impersonated_brand") and by.get("brand_impersonation", {}).get("status") == "fail":
        floor(75, f"Impersonates {brand['impersonated_brand']} ({brand.get('technique')})")
    if by.get("password_external", {}).get("status") == "fail":
        floor(80, "Password form posts to external domain")
    if di.get("is_ip"):
        floor(55, "Raw IP address host")
    if by.get("domain_age", {}).get("status") == "fail":
        floor(55, "Domain younger than 30 days")
    if by.get("ssl_valid", {}).get("status") == "fail":
        floor(45, "Invalid SSL certificate")
    if by.get("redirects", {}).get("status") == "fail":
        floor(50, "Excessive or cross-domain redirects")
    if by.get("suspicious_tld", {}).get("status") == "fail":
        floor(35, "High-risk TLD")
    if by.get("suspicious_js", {}).get("status") == "fail":
        floor(60, "Malicious JavaScript patterns")
    if by.get("punycode", {}).get("status") == "fail":
        floor(50, "Punycode homograph domain")
    # combined signals
    if brand.get("impersonated_brand") and (http_info.get("forms") or {}).get("login_form"):
        floor(85, "Brand impersonation with credential form")
    if brand.get("official_domain") and not blacklisted and not is_ugc_host(di.get("domain") or ""):
        score = min(score, 15)
        reasons.append("Official brand domain")
    rank = (popularity_info or {}).get("rank")
    hard = any(by.get(i, {}).get("status") == "fail" for i in (
        "brand_impersonation", "password_external", "suspicious_js", "dnsbl_listed", "private_network_host"))
    if rank and rank <= 10000 and not blacklisted and not hard:
        score = min(score, 20)
        reasons.append(f"Top-10k site (Tranco #{rank})")
    return int(round(min(100, max(0, score)))), reasons
