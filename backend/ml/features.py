"""Lexical URL feature extraction (no network access).

All features are computed from the URL string only so prediction is instant.
The URL is normalised first (trim, lower-case, default scheme, trailing slash
removed) so that training data and runtime inputs are treated identically.

Brand features use token / label boundaries (host split on "." and "-", path split on
non-alphanumerics) and an allowlist of official brand-owned domains, so e.g. "purchase" does not
match "chase" and googleusercontent.com / microsoftonline.com are not flagged.

`extract_features` returns every feature in FEATURE_LABELS (for display). The trained model may use
only a subset of them; the exact model inputs are stored in ml/artifacts/metrics.json ("features").
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, unquote, urlsplit

import tldextract

# Offline extractor: uses the public-suffix snapshot bundled with tldextract (never hits the network).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Single-token keywords. Keywords of length >= 5 also match as a prefix/suffix of a token
# ("loginverify", "netbanking", "accounts"); shorter ones must be a whole token ("auth", "kyc").
SUSPICIOUS_KEYWORDS = (
    "login", "logon", "signin", "signon", "verify", "verification", "verified", "secure", "security",
    "account", "update", "confirm", "bank", "banking", "password", "passwd", "credential", "suspend",
    "suspended", "unlock", "locked", "billing", "invoice", "payment", "wallet", "recover", "recovery",
    "restore", "validate", "validation", "authenticate", "authentication", "auth", "support",
    "service", "alert", "limited", "unusual", "expire", "free", "bonus", "gift", "claim", "prize",
    "lucky", "reward", "kyc", "refund", "ebayisapi", "webscr", "admin", "client", "token", "airdrop",
    "seed", "phrase", "helpdesk", "mailbox", "webmail", "sso", "dispute", "unblock", "reactivate",
)
SUSPICIOUS_PHRASES = ("wp-admin", "wp-content", "wp-includes", "log-in", "sign-in", "log-on", "sign-on")
_KW_SET = frozenset(SUSPICIOUS_KEYWORDS)

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "club", "online", "site", "website",
    "live", "icu", "buzz", "monster", "rest", "fit", "work", "click", "link", "support", "info",
    "ru", "cn", "su", "ws", "biz", "zip", "mov", "cyou", "cfd", "sbs", "quest", "bond", "lol",
    "store", "shop", "vip", "win", "loan", "men", "date", "download", "review", "country",
    "stream", "gdn", "kim", "science", "party", "trade", "accountant", "racing", "host",
    "space", "tech", "today", "life", "world", "ink", "best", "autos", "boats", "beauty", "hair",
    "makeup", "skin", "motorcycles", "yachts", "homes", "pics", "uno", "asia", "ltd", "digital",
}

SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "bitly.com",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "lnkd.in", "s.id",
    "v.gd", "qr.ae", "shorte.st", "bl.ink", "short.io", "soo.gd", "clck.ru", "u.to", "x.co",
    "trib.al", "tr.im", "mcaf.ee", "su.pr", "yourls.org", "bit.do", "2.gy", "urlz.fr", "rotf.lol",
    "qrco.de", "q-r.to", "ead.me", "bitly.ws", "gg.gg", "cutt.us", "qrfy.io", "shorturl.asia",
    "tinu.be", "l.ead.me", "kutt.it", "surl.li", "linkin.bio", "shrtco.de", "t2m.io", "goo.su",
}

# Platforms where anyone can host content on a sub-domain / path (abused heavily by phishers).
FREE_HOSTING = {
    "firebaseapp.com", "web.app", "webflow.io", "vercel.app", "netlify.app", "repl.co",
    "replit.dev", "replit.app", "godaddysites.com", "weebly.com", "weeblysite.com", "wixsite.com",
    "wixstudio.com", "wixstudio.io", "000webhostapp.com", "glitch.me", "herokuapp.com", "pages.dev",
    "workers.dev", "surge.sh", "ipfs.io", "infura-ipfs.io", "cloudflare-ipfs.com", "cf-ipfs.com",
    "dweb.link", "nftstorage.link", "w3s.link", "4everland.io", "arweave.net", "blogspot.com",
    "sites.google.com", "square.site", "myshopify.com", "wordpress.com", "github.io", "gitbook.io",
    "azurewebsites.net", "blob.core.windows.net", "web.core.windows.net", "appspot.com",
    "firebasestorage.googleapis.com", "storage.googleapis.com", "ngrok.io", "ngrok-free.app",
    "ngrok.app", "trycloudflare.com", "duckdns.org", "no-ip.com", "ddns.net", "hopto.org",
    "zapto.org", "sytes.net", "myftp.org", "serveftp.com", "freeddns.org", "dynu.net", "hpage.com",
    "jimdosite.com", "yolasite.com", "mystrikingly.com", "framer.app", "framer.website",
    "framer.media", "framer.ai", "carrd.co", "backname.io", "r2.dev", "onrender.com", "fly.dev",
    "translate.goog", "webcindario.com", "start.page", "webwave.dev", "myportfolio.com",
    "w3spaces.com", "ukit.me", "bolt.host", "typedream.app", "lovable.app", "ghost.io",
    "m-pages.com", "edgeone.app", "edgeone.dev", "zapier.app", "iceiy.com", "plutio.com",
    "wasmer.app", "systeme.io", "mybluehost.me", "craftum.io", "cprapid.com", "backblazeb2.com",
    "plesk.page", "pantheonsite.io", "appdomain.cloud", "usrfiles.com", "filesusr.com",
    "ewp.live", "xsph.ru", "swtest.ru", "tmweb.ru", "tw1.ru", "co.vu", "eu.cc", "us.cc",
    "cleverapps.io", "tempurl.host", "zyns.com", "net16.net", "hsforms.com", "jotform.com",
    "campaign-archive.com", "notion.site", "canva.site", "my.canva.site", "teemill.com",
    "boxmode.io", "teachable.com", "github.dev", "codesandbox.io", "csb.app", "stackblitz.io",
    "telegra.ph", "beget.tech", "site123.me", "webnode.page", "simdif.com", "tilda.ws",
    "business.site", "web.core.windows.net", "pythonanywhere.com", "deno.dev", "render.com",
}

BRANDS = (
    "paypal", "venmo", "zelle", "cashapp", "apple", "appleid", "icloud", "itunes", "google", "gmail",
    "youtube", "microsoft", "office365", "microsoft365", "outlook", "hotmail", "onedrive",
    "sharepoint", "azure", "xbox", "amazon", "facebook", "instagram", "whatsapp", "netflix",
    "linkedin", "dropbox", "adobe", "docusign", "dhl", "fedex", "usps", "dpd", "evri", "royalmail",
    "postnl", "auspost", "canadapost", "laposte", "correos", "posteitaliane", "ebay", "metamask",
    "coinbase", "binance", "kucoin", "kraken", "trezor", "ledgerlive", "opensea", "uniswap", "bybit",
    "bitget", "okx", "yahoo", "aol", "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "barclays", "santander", "natwest", "lloyds", "usaa", "navyfederal", "capitalone", "americanexpress",
    "amex", "mastercard", "sbi", "onlinesbi", "hdfc", "icici", "axisbank", "kotak", "paytm", "flipkart",
    "phonepe", "airtel", "jio", "irs", "hmrc", "ameli", "twitter", "telegram", "discord", "roblox",
    "steamcommunity", "steampowered", "spotify", "trustwallet", "walmart", "costco", "att", "verizon",
    "tmobile", "xfinity", "comcast", "airbnb", "alibaba", "aliexpress", "samsung", "yandex",
    "allegro", "bradesco", "itau", "optus", "telstra", "rakuten", "mufg", "smbc",
)
_BRAND_SET = frozenset(BRANDS)

# Official brand-owned registered domains (besides "<brand>.<normal tld>", which is also accepted).
OFFICIAL_DOMAINS = {
    "google.com", "googleusercontent.com", "gstatic.com", "googleapis.com", "googlevideo.com",
    "ggpht.com", "googletagmanager.com", "google-analytics.com", "googlesyndication.com",
    "doubleclick.net", "youtube.com", "youtu.be", "ytimg.com", "gmail.com", "android.com",
    "chrome.com", "blogger.com", "withgoogle.com", "goo.gl", "g.co", "google.dev", "web.dev",
    "microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com",
    "microsoft365.com", "msn.com", "bing.com", "azure.com", "windows.net", "windows.com",
    "sharepoint.com", "onedrive.com", "skype.com", "xbox.com", "msftauth.net", "msauth.net",
    "aka.ms", "visualstudio.com", "hotmail.com", "linkedin.com", "licdn.com", "github.com",
    "apple.com", "icloud.com", "me.com", "mzstatic.com", "itunes.com", "apple.news",
    "paypal.com", "paypal.me", "paypalobjects.com", "venmo.com", "zellepay.com", "cash.app",
    "amazon.com", "amazonaws.com", "media-amazon.com", "ssl-images-amazon.com", "amazon.dev",
    "a2z.com", "amzn.to", "primevideo.com", "facebook.com", "fb.com", "fbcdn.net", "messenger.com",
    "instagram.com", "cdninstagram.com", "whatsapp.com", "whatsapp.net", "wa.me", "meta.com",
    "netflix.com", "nflxext.com", "nflximg.net", "dropbox.com", "dropboxusercontent.com", "db.tt",
    "adobe.com", "adobelogin.com", "adobe.io", "typekit.net", "acrobat.com", "docusign.com",
    "docusign.net", "dhl.com", "fedex.com", "usps.com", "ups.com", "royalmail.com", "auspost.com.au",
    "canadapost-postescanada.ca", "laposte.fr", "laposte.net", "poste.it", "posteitaliane.it",
    "ebay.com", "ebaystatic.com", "ebayimg.com", "metamask.io", "coinbase.com", "binance.com",
    "binance.us", "kucoin.com", "kraken.com", "trezor.io", "ledger.com", "opensea.io", "uniswap.org",
    "bybit.com", "okx.com", "bitget.com", "yahoo.com", "yimg.com", "aol.com", "chase.com",
    "jpmorganchase.com", "jpmorgan.com", "wellsfargo.com", "wf.com", "bankofamerica.com", "bofa.com",
    "citi.com", "citibank.com", "hsbc.com", "hsbc.co.uk", "barclays.co.uk", "barclays.com",
    "santander.com", "santander.co.uk", "natwest.com", "lloydsbank.com", "usaa.com",
    "navyfederal.org", "capitalone.com", "americanexpress.com", "aexp.com", "mastercard.com",
    "visa.com", "onlinesbi.sbi", "sbi.co.in", "sbicard.com", "hdfcbank.com", "hdfc.com",
    "icicibank.com", "axisbank.com", "kotak.com", "paytm.com", "paytm.in", "flipkart.com",
    "phonepe.com", "airtel.in", "airtel.com", "jio.com", "irs.gov", "hmrc.gov.uk", "gov.uk", "ameli.fr",
    "twitter.com", "x.com", "twimg.com", "t.co", "telegram.org", "telegram.me", "t.me", "discord.com",
    "discord.gg", "discordapp.com", "roblox.com", "rbxcdn.com", "steampowered.com",
    "steamcommunity.com", "spotify.com", "scdn.co", "trustwallet.com", "walmart.com", "costco.com",
    "att.com", "att.net", "verizon.com", "verizonwireless.com", "t-mobile.com", "xfinity.com",
    "comcast.com", "comcast.net", "airbnb.com", "alibaba.com", "aliexpress.com", "alicdn.com",
    "samsung.com", "yandex.ru", "yandex.com", "ya.ru", "allegro.pl", "bradesco.com.br", "itau.com.br",
    "optus.com.au", "telstra.com.au", "rakuten.co.jp", "rakuten.com", "mufg.jp", "smbc.co.jp",
}

SUSPICIOUS_EXTENSIONS = (".php", ".exe", ".zip", ".rar", ".apk", ".scr", ".bat", ".js", ".jar",
                         ".msi", ".asp", ".aspx", ".cgi", ".bin", ".dll", ".vbs", ".htm")
_COMMON_TLD_TOKENS = frozenset({"com", "net", "org", "gov", "edu"})
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})
# real words that sit one edit away from a brand and must not count as look-alikes
_NOT_TYPO = frozenset({"apply", "goggle", "goggles", "adore", "chose", "chaste", "amazin", "costo"})

FEATURE_LABELS: dict[str, str] = {
    "url_length": "URL length (excluding scheme)",
    "hostname_length": "Hostname length",
    "path_length": "Path length",
    "query_length": "Query string length",
    "num_dots": "Number of dots",
    "num_hyphens": "Number of hyphens",
    "num_underscores": "Number of underscores",
    "num_at": "Number of '@' symbols",
    "num_question": "Number of '?' symbols",
    "num_equals": "Number of '=' symbols",
    "num_ampersand": "Number of '&' symbols",
    "num_slashes": "Number of slashes",
    "num_special": "Other special characters (~+!*,;$%)",
    "num_digits": "Digits in URL",
    "digit_ratio": "Digit ratio of URL",
    "host_digits": "Digits in hostname",
    "host_hyphens": "Hyphens in hostname",
    "num_subdomains": "Number of subdomains",
    "subdomain_length": "Subdomain length",
    "domain_length": "Registered domain name length",
    "domain_entropy": "Domain name entropy",
    "domain_vowel_ratio": "Vowel ratio of domain name",
    "tld_length": "TLD length",
    "is_ip": "Host is an IP address",
    "uses_https": "Uses HTTPS",
    "has_punycode": "Punycode / IDN (xn--) host",
    "has_port": "Explicit port number",
    "double_slash_redirect": "'//' redirect inside path",
    "suspicious_keywords": "Suspicious keywords (login, verify, ...)",
    "suspicious_tld": "Suspicious / abused TLD",
    "is_shortener": "URL shortener domain",
    "free_hosting": "Free hosting / user-content platform",
    "brand_mismatch": "Brand name outside official domain",
    "brand_in_subdomain": "Brand name in subdomain of unrelated domain",
    "brand_typosquat": "Look-alike brand in domain (e.g. amaz0n)",
    "embedded_domain": "Embedded domain in hostname (e.g. apple.com.evil.ru)",
    "http_token": "'http(s)' token inside host or path",
    "longest_token": "Longest token length",
    "avg_token_length": "Average token length",
    "path_depth": "Path depth",
    "num_query_params": "Number of query parameters",
    "suspicious_extension": "Suspicious file extension (.php, .exe, ...)",
    "percent_encoded": "Percent-encoded characters",
    "hex_token": "Long hex/random token present",
    "url_entropy": "URL entropy",
}

FEATURE_NAMES: list[str] = list(FEATURE_LABELS)
# Features derived purely from the URL scheme (excluded from the model when training "without scheme").
SCHEME_FEATURES = ("uses_https",)

_TOKEN_SPLIT = re.compile(r"[/\.\-_?=&:@~+%#,;!]+")
_ALNUM_SPLIT = re.compile(r"[^a-z0-9]+")
_HEX_TOKEN = re.compile(r"[0-9a-f]{16,}|[a-z0-9]{32,}")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://")


def normalize_url(url: str) -> str:
    """Canonical form used for both training and inference."""
    u = str(url or "").strip().strip('"\'').lower()
    if not _SCHEME.match(u):
        u = "http://" + u
    while u.endswith("/") and not u.endswith("://"):
        u = u[:-1]
    return u


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _is_ip(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # hex / integer encoded IPs, e.g. http://0x7f000001 or http://3232235777
    return bool(re.fullmatch(r"0x[0-9a-f]{6,8}|\d{8,10}", h))


def on_free_hosting(host: str) -> bool:
    labels = host.split(".")
    if any(".".join(labels[i:]) in FREE_HOSTING for i in range(len(labels))):
        return True
    if ".blogspot." in "." + host or host.startswith("blogspot."):
        return True
    # user S3 buckets: bucket.s3.amazonaws.com, bucket.s3-eu-west-1.amazonaws.com, s3.region.amazonaws.com
    return host.endswith(".amazonaws.com") and bool(re.search(r"(^|\.)s3[.-]", host))


def _confusable(t: str) -> str:
    return t.translate(_LEET).replace("rn", "m").replace("vv", "w")


def _edit1(a: str, b: str) -> bool:
    """True if a and b are exactly one substitution / insertion / deletion apart."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def _token_brand(t: str) -> str | None:
    """Brand named by a single token: exact, or brand + digits / short or keyword affix."""
    if t in _BRAND_SET:
        return t
    for b in BRANDS:
        if len(b) >= 5 and len(t) > len(b):
            if t.startswith(b):
                rem = t[len(b):]
            elif t.endswith(b):
                rem = t[:-len(b)]
            else:
                continue
            if rem.isdigit() or len(rem) <= 2 or rem in _KW_SET:
                return b
    return None


def _lookalike(t: str) -> str | None:
    """Brand imitated by a domain-label token (leet / homoglyph / one typo)."""
    c = _confusable(t)
    hit = _token_brand(c) if c != t else None
    if hit:
        return hit
    if len(t) >= 6 and t not in _NOT_TYPO:
        for b in BRANDS:
            if len(b) >= 6 and (_edit1(t, b) or _edit1(c, b)):
                return b
    return None


def is_official(domain: str, suffix: str) -> bool:
    registered = f"{domain}.{suffix}" if suffix else domain
    if registered in OFFICIAL_DOMAINS:
        return True
    last = suffix.split(".")[-1] if suffix else ""
    return domain in _BRAND_SET and last not in SUSPICIOUS_TLDS


def _keyword_count(tokens: list[str], rest: str) -> int:
    found = set()
    for t in tokens:
        if t in _KW_SET:
            found.add(t)
            continue
        if len(t) > 5:
            for k in SUSPICIOUS_KEYWORDS:
                if len(k) >= 5 and (t.startswith(k) or t.endswith(k)):
                    found.add(k)
    for p in SUSPICIOUS_PHRASES:
        if p in rest:
            found.add(p)
    return len(found)


def _empty() -> dict[str, float]:
    return {k: 0.0 for k in FEATURE_NAMES}


def extract_features(url: str) -> dict[str, float]:
    try:
        return _extract(url)
    except Exception:  # never raise
        f = _empty()
        f["url_length"] = float(len(str(url or "")))
        return f


def _extract(url: str) -> dict[str, float]:
    u = normalize_url(url)
    scheme, _, rest = u.partition("://")
    parts = urlsplit(u)
    netloc = parts.netloc
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    has_port = port is not None or bool(re.search(r":\d+$", netloc))
    path = parts.path or ""
    query = parts.query or ""

    is_ip = _is_ip(host)
    ext = _EXTRACT(host)
    domain = "" if is_ip else ext.domain
    suffix = "" if is_ip else ext.suffix
    sub = "" if is_ip else ext.subdomain
    registered = f"{domain}.{suffix}" if suffix else domain
    sub_labels = [s for s in sub.split(".") if s and s != "www"]
    sub_clean = ".".join(sub_labels)

    tokens = [t for t in _TOKEN_SPLIT.split(rest) if t]
    alnum_tokens = [t for t in _ALNUM_SPLIT.split(rest) if t]
    digits = sum(ch.isdigit() for ch in rest)
    path_q = path + "?" + query

    # ---- brand features (token / label boundaries + official-domain allowlist)
    official = (not is_ip) and is_official(domain, suffix)
    sub_tokens = [t for t in re.split(r"[.\-]+", sub_clean) if t]
    dom_tokens = [t for t in domain.split("-") if t] if domain else []
    path_tokens = [t for t in _ALNUM_SPLIT.split(path_q) if t][:200]  # bounded cost on huge URLs
    brand_sub = brand_path = brand_typo = 0.0
    if not official:
        if any(_token_brand(t) or _token_brand(_confusable(t)) for t in sub_tokens):
            brand_sub = 1.0
        if any(_token_brand(t) for t in path_tokens):
            brand_path = 1.0
        if dom_tokens and any(_token_brand(t) or _lookalike(t) for t in dom_tokens):
            brand_typo = 1.0
    # a domain-like token (com/net/org/...) before the real registered domain
    host_tokens_wo_suffix = sub_tokens + dom_tokens if not is_ip else []
    embedded = float(any(t in _COMMON_TLD_TOKENS for t in host_tokens_wo_suffix))

    vowels = sum(ch in "aeiou" for ch in domain)
    f = {
        "url_length": len(rest),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": rest.count("."),
        "num_hyphens": rest.count("-"),
        "num_underscores": rest.count("_"),
        "num_at": rest.count("@"),
        "num_question": rest.count("?"),
        "num_equals": rest.count("="),
        "num_ampersand": rest.count("&"),
        "num_slashes": rest.count("/"),
        "num_special": sum(rest.count(c) for c in "~+!*,;$%"),
        "num_digits": digits,
        "digit_ratio": digits / max(len(rest), 1),
        "host_digits": sum(ch.isdigit() for ch in host),
        "host_hyphens": host.count("-"),
        "num_subdomains": 0 if is_ip else len(sub_labels),
        "subdomain_length": 0 if is_ip else len(sub_clean),
        "domain_length": len(domain),
        "domain_entropy": _entropy(domain),
        "domain_vowel_ratio": vowels / max(len(domain), 1),
        "tld_length": len(suffix),
        "is_ip": float(is_ip),
        "uses_https": float(scheme == "https"),
        "has_punycode": float("xn--" in host),
        "has_port": float(has_port),
        "double_slash_redirect": float("//" in rest),
        "suspicious_keywords": _keyword_count(alnum_tokens[:300], rest),
        "suspicious_tld": float(suffix.split(".")[-1] in SUSPICIOUS_TLDS) if suffix else 0.0,
        "is_shortener": float(registered in SHORTENERS or host in SHORTENERS),
        "free_hosting": float(on_free_hosting(host)),
        "brand_mismatch": float(brand_sub or brand_path),
        "brand_in_subdomain": brand_sub,
        "brand_typosquat": brand_typo,
        "embedded_domain": embedded,
        "http_token": float("http" in rest),
        "longest_token": max((len(t) for t in tokens), default=0),
        "avg_token_length": sum(len(t) for t in tokens) / max(len(tokens), 1),
        "path_depth": len([p for p in path.split("/") if p]),
        "num_query_params": len(parse_qsl(query, keep_blank_values=True)),
        "suspicious_extension": float(any(path.endswith(e) or (e + "/") in path for e in SUSPICIOUS_EXTENSIONS)),
        "percent_encoded": len(re.findall(r"%[0-9a-f]{2}", rest)),
        "hex_token": float(bool(_HEX_TOKEN.search(unquote(path_q)))),
        "url_entropy": _entropy(rest),
    }
    return {k: float(f[k]) for k in FEATURE_NAMES}
