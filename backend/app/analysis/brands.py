"""Brand impersonation detection (typosquat, homoglyph, combosquat, subdomain, punycode, path, content)."""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract

EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# brand -> (keywords (labels used for matching), legit registered domains)
BRANDS: dict[str, dict] = {
    "PayPal": {"kw": ["paypal"], "domains": ["paypal.com", "paypal.me", "paypalobjects.com"]},
    "Apple": {"kw": ["apple", "icloud", "itunes"], "domains": ["apple.com", "icloud.com", "itunes.com", "apple.co"]},
    "Microsoft": {"kw": ["microsoft", "office365", "onedrive", "sharepoint", "msonline"],
                  "domains": ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
                              "onedrive.com", "sharepoint.com", "msn.com", "azure.com", "windows.net", "bing.com"]},
    "Office 365": {"kw": ["office"], "domains": ["office.com", "office365.com", "microsoft.com"]},
    "Outlook": {"kw": ["outlook", "hotmail"], "domains": ["outlook.com", "live.com", "hotmail.com", "microsoft.com"]},
    "Google": {"kw": ["google", "gmail"], "domains": ["google.com", "gmail.com", "google.co.in", "googleusercontent.com",
                                                      "youtube.com", "gstatic.com", "googleapis.com", "g.co"]},
    "YouTube": {"kw": ["youtube"], "domains": ["youtube.com", "youtu.be", "google.com"]},
    "Amazon": {"kw": ["amazon", "amzn"], "domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp",
                                                     "amazon.ca", "amazon.fr", "amazon.it", "amazon.es", "amazon.com.au",
                                                     "amazonaws.com", "amzn.to", "a2z.com", "primevideo.com"]},
    "AWS": {"kw": ["aws"], "domains": ["amazonaws.com", "aws.amazon.com", "amazon.com"]},
    "Netflix": {"kw": ["netflix"], "domains": ["netflix.com", "nflxext.com"]},
    "Facebook": {"kw": ["facebook", "fb"], "domains": ["facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com"]},
    "Meta": {"kw": ["meta"], "domains": ["meta.com", "facebook.com"]},
    "Instagram": {"kw": ["instagram", "insta"], "domains": ["instagram.com"]},
    "WhatsApp": {"kw": ["whatsapp"], "domains": ["whatsapp.com", "whatsapp.net", "wa.me"]},
    "Twitter / X": {"kw": ["twitter"], "domains": ["twitter.com", "x.com", "t.co"]},
    "LinkedIn": {"kw": ["linkedin"], "domains": ["linkedin.com", "lnkd.in"]},
    "TikTok": {"kw": ["tiktok"], "domains": ["tiktok.com"]},
    "Telegram": {"kw": ["telegram"], "domains": ["telegram.org", "t.me", "telegram.me"]},
    "Discord": {"kw": ["discord"], "domains": ["discord.com", "discord.gg", "discordapp.com"]},
    "Snapchat": {"kw": ["snapchat"], "domains": ["snapchat.com"]},
    "Yahoo": {"kw": ["yahoo"], "domains": ["yahoo.com", "yahoo.co.jp", "yahoo.co.in"]},
    "AOL": {"kw": ["aol"], "domains": ["aol.com"]},
    "Dropbox": {"kw": ["dropbox"], "domains": ["dropbox.com", "dropboxusercontent.com"]},
    "DocuSign": {"kw": ["docusign"], "domains": ["docusign.com", "docusign.net"]},
    "Adobe": {"kw": ["adobe"], "domains": ["adobe.com", "adobelogin.com"]},
    "WeTransfer": {"kw": ["wetransfer"], "domains": ["wetransfer.com", "we.tl"]},
    "Zoom": {"kw": ["zoom"], "domains": ["zoom.us", "zoom.com"]},
    "Slack": {"kw": ["slack"], "domains": ["slack.com"]},
    "GitHub": {"kw": ["github"], "domains": ["github.com", "github.io", "githubusercontent.com"]},
    "Steam": {"kw": ["steam", "steamcommunity", "steampowered"], "domains": ["steampowered.com", "steamcommunity.com", "steamgames.com"]},
    "Roblox": {"kw": ["roblox"], "domains": ["roblox.com"]},
    "Epic Games": {"kw": ["epicgames", "fortnite"], "domains": ["epicgames.com", "fortnite.com"]},
    "Spotify": {"kw": ["spotify"], "domains": ["spotify.com"]},
    "eBay": {"kw": ["ebay"], "domains": ["ebay.com", "ebay.in", "ebay.co.uk", "ebay.de"]},
    "Walmart": {"kw": ["walmart"], "domains": ["walmart.com"]},
    "Alibaba": {"kw": ["alibaba", "aliexpress"], "domains": ["alibaba.com", "aliexpress.com"]},
    "Flipkart": {"kw": ["flipkart"], "domains": ["flipkart.com"]},
    "Myntra": {"kw": ["myntra"], "domains": ["myntra.com"]},
    "Paytm": {"kw": ["paytm"], "domains": ["paytm.com", "paytm.in", "paytmbank.com"]},
    "PhonePe": {"kw": ["phonepe"], "domains": ["phonepe.com"]},
    "Google Pay": {"kw": ["gpay"], "domains": ["pay.google.com", "google.com"]},
    "SBI": {"kw": ["sbi", "onlinesbi", "statebank", "sbicard", "yonosbi", "yono"],
            "domains": ["onlinesbi.sbi", "sbi.co.in", "onlinesbi.com", "sbicard.com", "sbi", "yonosbi.com", "statebankofindia.com"]},
    "HDFC Bank": {"kw": ["hdfc", "hdfcbank"], "domains": ["hdfcbank.com", "hdfc.com", "hdfcbank.net"]},
    "ICICI Bank": {"kw": ["icici", "icicibank"], "domains": ["icicibank.com", "icici.com"]},
    "Axis Bank": {"kw": ["axisbank"], "domains": ["axisbank.com"]},
    "Kotak": {"kw": ["kotak"], "domains": ["kotak.com"]},
    "PNB": {"kw": ["pnbindia", "netpnb"], "domains": ["pnbindia.in", "netpnb.com"]},
    "Bank of Baroda": {"kw": ["bankofbaroda"], "domains": ["bankofbaroda.in", "bankofbaroda.com"]},
    "IRCTC": {"kw": ["irctc"], "domains": ["irctc.co.in"]},
    "India Post": {"kw": ["indiapost"], "domains": ["indiapost.gov.in"]},
    "Income Tax India": {"kw": ["incometax", "incometaxindia"], "domains": ["incometax.gov.in", "incometaxindia.gov.in"]},
    "Chase": {"kw": ["chase", "jpmorgan"], "domains": ["chase.com", "jpmorgan.com", "jpmorganchase.com"]},
    "Wells Fargo": {"kw": ["wellsfargo"], "domains": ["wellsfargo.com"]},
    "Bank of America": {"kw": ["bankofamerica", "bofa"], "domains": ["bankofamerica.com", "bofa.com"]},
    "Citi": {"kw": ["citibank", "citi"], "domains": ["citi.com", "citibank.com"]},
    "Capital One": {"kw": ["capitalone"], "domains": ["capitalone.com"]},
    "American Express": {"kw": ["americanexpress", "amex"], "domains": ["americanexpress.com", "amex.com"]},
    "HSBC": {"kw": ["hsbc"], "domains": ["hsbc.com", "hsbc.co.uk", "hsbc.co.in"]},
    "Barclays": {"kw": ["barclays"], "domains": ["barclays.co.uk", "barclays.com"]},
    "Santander": {"kw": ["santander"], "domains": ["santander.com", "santander.co.uk"]},
    "Visa": {"kw": ["visa"], "domains": ["visa.com"]},
    "Mastercard": {"kw": ["mastercard"], "domains": ["mastercard.com"]},
    "Stripe": {"kw": ["stripe"], "domains": ["stripe.com"]},
    "Venmo": {"kw": ["venmo"], "domains": ["venmo.com"]},
    "Cash App": {"kw": ["cashapp"], "domains": ["cash.app", "cashapp.com"]},
    "Coinbase": {"kw": ["coinbase"], "domains": ["coinbase.com"]},
    "Binance": {"kw": ["binance"], "domains": ["binance.com", "binance.us"]},
    "MetaMask": {"kw": ["metamask"], "domains": ["metamask.io"]},
    "Trust Wallet": {"kw": ["trustwallet"], "domains": ["trustwallet.com"]},
    "Ledger": {"kw": ["ledger"], "domains": ["ledger.com"]},
    "Kraken": {"kw": ["kraken"], "domains": ["kraken.com"]},
    "Blockchain.com": {"kw": ["blockchain"], "domains": ["blockchain.com"]},
    "OpenSea": {"kw": ["opensea"], "domains": ["opensea.io"]},
    "Uniswap": {"kw": ["uniswap"], "domains": ["uniswap.org"]},
    "DHL": {"kw": ["dhl"], "domains": ["dhl.com", "dhl.de", "dhl.co.in"]},
    "FedEx": {"kw": ["fedex"], "domains": ["fedex.com"]},
    "UPS": {"kw": ["ups"], "domains": ["ups.com"]},
    "USPS": {"kw": ["usps"], "domains": ["usps.com"]},
    "Royal Mail": {"kw": ["royalmail"], "domains": ["royalmail.com"]},
    "Booking.com": {"kw": ["booking"], "domains": ["booking.com"]},
    "Airbnb": {"kw": ["airbnb"], "domains": ["airbnb.com"]},
    "AT&T": {"kw": ["att"], "domains": ["att.com", "att.net"]},
    "Verizon": {"kw": ["verizon"], "domains": ["verizon.com"]},
    "Comcast / Xfinity": {"kw": ["xfinity", "comcast"], "domains": ["xfinity.com", "comcast.net", "comcast.com"]},
    "IRS": {"kw": ["irs"], "domains": ["irs.gov"]},
    "Jio": {"kw": ["jio", "reliancejio"], "domains": ["jio.com"]},
    "Airtel": {"kw": ["airtel"], "domains": ["airtel.in", "airtel.com"]},
    "Swiggy": {"kw": ["swiggy"], "domains": ["swiggy.com"]},
    "Zomato": {"kw": ["zomato"], "domains": ["zomato.com"]},
    "Steam Community": {"kw": ["steamcommunity"], "domains": ["steamcommunity.com"]},
    "Outlook Web App": {"kw": ["owa"], "domains": ["outlook.com", "office.com"]},
    "Webmail / cPanel": {"kw": ["cpanel", "roundcube"], "domains": ["cpanel.net", "roundcube.net"]},
}
# Short keywords that are too generic for substring/fuzzy matching (exact label only)
SHORT_EXACT = {"fb", "ups", "att", "irs", "aws", "owa", "jio", "sbi", "visa", "meta", "citi", "amex", "bofa",
               "yono", "zoom", "chase", "apple", "office", "steam", "ledger", "booking", "insta", "slack", "stripe",
               "kraken", "blockchain", "gpay"}
# Real words / legit brands that are 1-2 edits from a brand keyword
NOT_TYPO = {"finance", "codebase", "paypay", "google", "apply", "outlooks", "instant", "yahoo", "chaser",
            "amazing", "dropbear", "adobes", "telegraph", "booking", "ebays", "visas", "hdfcs", "zoomy",
            "netlify", "spotify", "shopify", "discover", "steamy", "roblex", "mastercraft", "verizons",
            "flipboard", "linkedln"} - {"linkedln"}
# Some keywords are only meaningful as a fuzzy target if length >= 5
FUZZY_MIN_LEN = 5

KW_TO_BRAND: dict[str, str] = {}
for _b, _v in BRANDS.items():
    for _k in _v["kw"]:
        KW_TO_BRAND.setdefault(_k, _b)
ALL_LEGIT: dict[str, str] = {}
for _b, _v in BRANDS.items():
    for _d in _v["domains"]:
        ALL_LEGIT.setdefault(_d, _b)

COMBO_WORDS = ["login", "logon", "signin", "sign-in", "secure", "security", "support", "verify", "verification",
               "account", "accounts", "update", "billing", "payment", "pay", "wallet", "auth", "service", "services",
               "help", "helpdesk", "online", "web", "official", "alert", "unlock", "recovery", "confirm", "customer",
               "care", "bank", "banking", "mail", "id", "app", "mobile", "portal", "access", "center", "team", "info",
               "notice", "kyc", "reward", "rewards", "gift", "claim", "refund", "track", "tracking", "delivery",
               "parcel", "connect", "my", "user", "client", "check", "restore", "limited", "suspended", "network"]

# Confusables: map look-alike glyphs to ASCII skeleton
CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s", "@": "a", "|": "l",
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "ԛ": "q", "ԝ": "w", "ү": "y", "ɑ": "a", "ο": "o", "ν": "v", "α": "a", "ρ": "p", "ι": "i", "κ": "k",
    "τ": "t", "ε": "e", "χ": "x", "ı": "i", "ł": "l", "ß": "b", "đ": "d", "ħ": "h",
}
MULTI_CONFUSABLES = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"), ("ii", "u")]


def skeleton(s: str) -> str:
    s = s.lower()
    out = []
    for ch in s:
        if ch in CONFUSABLES:
            out.append(CONFUSABLES[ch])
            continue
        n = unicodedata.normalize("NFKD", ch)
        n = "".join(c for c in n if not unicodedata.combining(c))
        out.append(n if n.isascii() else ch)
    return "".join(out)


def skeleton_variants(s: str) -> set[str]:
    base = skeleton(s)
    res = {base}
    for a, b in MULTI_CONFUSABLES:
        if a in base:
            res.add(base.replace(a, b))
    # "1" may also be "i"
    if "1" in s:
        res.add(skeleton(s.replace("1", "i")))
    return res


def damerau(a: str, b: str) -> int:
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return 1 - damerau(a, b) / max(len(a), len(b))


def is_legit_domain(registered: str, host: str = "") -> str | None:
    """Return brand name if registered domain (or host) is an official domain of a brand."""
    if registered in ALL_LEGIT:
        return ALL_LEGIT[registered]
    if host:
        parts = host.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in ALL_LEGIT:
                return ALL_LEGIT[cand]
    return None


def _decode_idna(host: str) -> str:
    try:
        return ".".join(p.encode().decode("idna") if p.startswith("xn--") else p for p in host.split("."))
    except Exception:
        return host


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def _result(brand=None, sim=0.0, tech=None, details="", legit=False, keyword=None):
    return {"impersonated_brand": brand, "similarity": round(float(sim), 3), "technique": tech,
            "details": details, "official_domain": legit, "matched_keyword": keyword}


@lru_cache(maxsize=4096)
def detect_brand(url: str, title: str = "", content: str = "") -> dict:
    """Detect brand impersonation from URL (and optionally page title/content). Never raises."""
    try:
        return _detect(url, title or "", content or "")
    except Exception as e:  # pragma: no cover
        return _result(details=f"brand detection error: {e}")


def _detect(url: str, title: str, content: str) -> dict:
    if "://" not in url:
        url = "http://" + url
    sp = urlsplit(url)
    host = (sp.hostname or "").lower().strip(".")
    host_u = _decode_idna(host)
    ext = EXTRACT(host)
    registered = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    registered = registered or host
    label = ext.domain or host
    label_u = _decode_idna(label)
    sub = ext.subdomain or ""

    legit = is_legit_domain(registered, host)
    if legit:
        return _result(None, 1.0, None, f"{registered} is an official domain of {legit}", legit=True, keyword=None)

    is_puny = "xn--" in host

    # 1. exact keyword equals label (e.g. paypal.xyz / paypal.com-something)
    if label_u in KW_TO_BRAND:
        b = KW_TO_BRAND[label_u]
        return _result(b, 0.95, "punycode" if is_puny else "combosquat",
                       f"Registered label '{label_u}' matches brand {b} but on unofficial domain {registered}", keyword=label_u)

    # 2. homoglyph / punycode skeleton match
    for sk in skeleton_variants(label_u):
        if sk != label_u and sk in KW_TO_BRAND:
            b = KW_TO_BRAND[sk]
            tech = "punycode" if is_puny else "homoglyph"
            return _result(b, 0.97, tech, f"'{label_u}' visually resembles '{sk}' ({b}) via look-alike characters", keyword=sk)

    toks = _tokens(label_u.replace("-", " "))
    sk_label = skeleton(label_u)
    # homoglyph inside a combo label (e.g. arnazon-secure-login): check skeleton variants token-wise
    for var in skeleton_variants(label_u):
        if var == label_u:
            continue
        vtoks = _tokens(var)
        for kw, b in sorted(KW_TO_BRAND.items(), key=lambda x: -len(x[0])):
            if len(kw) >= 4 and kw not in SHORT_EXACT and kw in vtoks and kw not in toks:
                return _result(b, 0.93, "punycode" if is_puny else "homoglyph",
                               f"'{label_u}' contains look-alike spelling of '{kw}' ({b}) combined with other words",
                               keyword=kw)
    # 3. combosquat: brand keyword + extra words with hyphen or concatenated
    for kw, b in sorted(KW_TO_BRAND.items(), key=lambda x: -len(x[0])):
        if kw in SHORT_EXACT or len(kw) < 4:
            if kw in toks and len(toks) > 1:
                return _result(b, 0.85, "combosquat", f"Brand token '{kw}' combined with other words in '{label_u}'", keyword=kw)
            continue
        if kw in toks and len(toks) > 1:
            return _result(b, 0.9, "combosquat", f"Brand '{kw}' combined with '{'-'.join(t for t in toks if t != kw)}' in {registered}", keyword=kw)
        if len(kw) >= 5 and (kw in sk_label) and sk_label != kw:
            rest = sk_label.replace(kw, " ").strip()
            if any(w.replace("-", "") in rest for w in COMBO_WORDS) or len(rest) <= 12:
                return _result(b, 0.85, "combosquat", f"Brand '{kw}' embedded in domain label '{label_u}'", keyword=kw)

    # 4. typosquat via edit distance against keyword (and each token)
    best = (0.0, None, None)
    cands = {sk_label, label_u.replace("-", "")} | set(toks)
    for kw, b in KW_TO_BRAND.items():
        if len(kw) < FUZZY_MIN_LEN or kw in SHORT_EXACT:
            continue
        for c in cands:
            if abs(len(c) - len(kw)) > 2 or len(c) < 5 or c in NOT_TYPO:
                continue
            s = similarity(c, kw)
            if s > best[0]:
                best = (s, b, kw)
    if best[0] >= 0.75 and best[2] is not None:
        d = min(damerau(c, best[2]) for c in cands if c)
        if d == 1 or (d == 2 and len(best[2]) >= 8):
            tech = "punycode" if is_puny else "typosquat"
            return _result(best[1], best[0], tech, f"'{label_u}' is {d} edit(s) away from '{best[2]}' ({best[1]})", keyword=best[2])

    # 5. brand in subdomain (paypal.com.evil.xyz / login-paypal.evil.com)
    sub_toks = _tokens(sub)
    sub_joined = sub.lower()
    for kw, b in sorted(KW_TO_BRAND.items(), key=lambda x: -len(x[0])):
        if (kw in sub_toks) or (len(kw) >= 5 and kw in sub_joined):
            legit_hint = any(d in host for d in BRANDS[b]["domains"])
            det = (f"Brand domain embedded in subdomain of {registered} ({host})" if legit_hint
                   else f"Brand '{kw}' appears in subdomain '{sub}' of unrelated domain {registered}")
            return _result(b, 0.8 if legit_hint else 0.7, "subdomain", det, keyword=kw)

    # 6. brand in path / query
    path = (sp.path + " " + sp.query).lower()
    ptoks = set(_tokens(path))
    for kw, b in sorted(KW_TO_BRAND.items(), key=lambda x: -len(x[0])):
        if len(kw) >= 5 and kw not in SHORT_EXACT and (kw in ptoks or any("." in d and d in path for d in BRANDS[b]["domains"])):
            return _result(b, 0.55, "path", f"Brand '{kw}' appears in URL path but domain is {registered}", keyword=kw)

    # 7. brand in page title/content
    if title or content:
        t = (title or "").lower()
        ttoks = set(_tokens(t))
        for kw, b in sorted(KW_TO_BRAND.items(), key=lambda x: -len(x[0])):
            if len(kw) >= 4 and kw in ttoks:
                return _result(b, 0.6, "content", f"Page title mentions '{kw}' ({b}) but domain is {registered}", keyword=kw)
        if content:
            c = content[:20000].lower()
            hits = {}
            for kw, b in KW_TO_BRAND.items():
                if len(kw) >= 5:
                    n = len(re.findall(r"\b" + re.escape(kw) + r"\b", c))
                    if n:
                        hits[b] = hits.get(b, 0) + n
            if hits:
                b, n = max(hits.items(), key=lambda x: x[1])
                if n >= 3:
                    return _result(b, 0.45, "content", f"Page content mentions {b} {n} times but domain is {registered}")

    return _result(None, round(best[0], 3) if best[0] < 0.75 else 0.0, None, "No brand impersonation detected")


def guess_target(url: str) -> str | None:
    r = detect_brand(url)
    return r.get("impersonated_brand")
