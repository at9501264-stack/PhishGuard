"""dnstwist-style domain permutation generator + async DNS resolution."""
from __future__ import annotations

import asyncio
import re

import dns.asyncresolver
import dns.exception
import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

QWERTY = {
    "1": "2q", "2": "3wq1", "3": "4ew2", "4": "5re3", "5": "6tr4", "6": "7yt5", "7": "8uy6", "8": "9iu7",
    "9": "0oi8", "0": "po9", "q": "12wa", "w": "3esaq2", "e": "4rdsw3", "r": "5tfde4", "t": "6ygfr5",
    "y": "7uhgt6", "u": "8ijhy7", "i": "9okju8", "o": "0plki9", "p": "lo0", "a": "qwsz", "s": "edxzaw",
    "d": "rfcxse", "f": "tgvcdr", "g": "yhbvft", "h": "ujnbgy", "j": "ikmnhu", "k": "olmji", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
HOMOGLYPHS = {
    "a": ["à", "á", "â", "ã", "ä", "å", "ɑ", "а", "4"], "b": ["d", "lb", "ʙ", "6"], "c": ["e", "ϲ", "с", "ç"],
    "d": ["b", "cl", "dl", "ԁ"], "e": ["c", "é", "è", "ê", "ë", "е", "3"], "f": ["ƒ"], "g": ["q", "ɡ", "9"],
    "h": ["lh", "һ"], "i": ["1", "l", "í", "ì", "ï", "і"], "j": ["ј"], "k": ["lk", "ik", "lc", "κ"],
    "l": ["1", "i", "ӏ", "ł"], "m": ["n", "nn", "rn", "rr"], "n": ["m", "r", "ո"], "o": ["0", "ο", "о", "ö", "ó"],
    "p": ["ρ", "р"], "q": ["g", "ԛ"], "r": ["ʀ", "г"], "s": ["ѕ", "5", "$"], "t": ["τ", "7"], "u": ["μ", "υ", "ս", "ü"],
    "v": ["ν", "ѵ"], "w": ["vv", "ѡ", "ԝ"], "x": ["х"], "y": ["у", "ү"], "z": ["ʐ", "ż"],
}
VOWELS = "aeiou"
COMMON_TLDS = ["com", "net", "org", "info", "co", "io", "in", "biz", "xyz", "top", "online", "site", "app", "shop",
               "live", "us", "uk", "co.in", "co.uk", "me", "cc", "club", "store", "support", "click", "link", "ru", "cn"]
_VALID = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def _split(domain: str) -> tuple[str, str, str]:
    domain = domain.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0].split(":", 1)[0].strip(".")
    ext = _EXTRACT(domain)
    return ext.subdomain, ext.domain or domain, ext.suffix or "com"


def _ascii_ok(label: str) -> bool:
    return bool(_VALID.match(label)) and len(label) <= 63


def _idna(label: str) -> str | None:
    if label.isascii():
        return label if _ascii_ok(label) else None
    try:
        return label.encode("idna").decode()
    except Exception:
        return None


def generate_permutations(domain: str) -> list[dict]:
    """Generate dnstwist-style permutations. Returns [{"domain","technique"}] (unique, original excluded)."""
    try:
        _sub, name, tld = _split(domain)
    except Exception:
        return []
    if not name:
        return []
    orig = f"{name}.{tld}"
    out: dict[str, str] = {}

    def add(lbl: str, technique: str, suffix: str | None = None):
        if not lbl:
            return
        enc = _idna(lbl)
        if not enc or enc.startswith("-") or enc.endswith("-"):
            return
        d = f"{enc}.{suffix or tld}"
        if d != orig and d not in out:
            out[d] = technique

    n = len(name)
    # addition
    for c in "abcdefghijklmnopqrstuvwxyz0123456789":
        add(name + c, "addition")
    # bitsquatting
    for i, ch in enumerate(name):
        for mask in (1, 2, 4, 8, 16, 32, 64, 128):
            b = chr(ord(ch) ^ mask)
            if b.isascii() and (b.isalnum() or b == "-") and b.lower() == b:
                add(name[:i] + b + name[i + 1:], "bitsquatting")
    # homoglyph
    for i, ch in enumerate(name):
        for g in HOMOGLYPHS.get(ch, []):
            add(name[:i] + g + name[i + 1:], "homoglyph")
    for a, b in (("m", "rn"), ("w", "vv"), ("d", "cl"), ("rn", "m"), ("vv", "w"), ("cl", "d")):
        if a in name:
            add(name.replace(a, b, 1), "homoglyph")
    # hyphenation
    for i in range(1, n):
        if name[i - 1] != "-" and name[i] != "-":
            add(name[:i] + "-" + name[i:], "hyphenation")
    # insertion (keyboard adjacent)
    for i, ch in enumerate(name):
        for k in QWERTY.get(ch, ""):
            add(name[:i] + k + name[i:], "insertion")
            add(name[:i + 1] + k + name[i + 1:], "insertion")
    # omission
    for i in range(n):
        add(name[:i] + name[i + 1:], "omission")
    # repetition
    for i, ch in enumerate(name):
        if ch.isalnum():
            add(name[:i] + ch + name[i:], "repetition")
    # replacement
    for i, ch in enumerate(name):
        for k in QWERTY.get(ch, ""):
            add(name[:i] + k + name[i + 1:], "replacement")
    # subdomain (insert dot)
    for i in range(1, n):
        if name[i] != "-" and name[i - 1] != "-":
            left, right = name[:i], name[i:]
            if _ascii_ok(left) and _ascii_ok(right):
                d = f"{left}.{right}.{tld}"
                if d not in out:
                    out[d] = "subdomain"
    # transposition
    for i in range(n - 1):
        if name[i] != name[i + 1]:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "transposition")
    # vowel swap
    for i, ch in enumerate(name):
        if ch in VOWELS:
            for v in VOWELS:
                if v != ch:
                    add(name[:i] + v + name[i + 1:], "vowel-swap")
    # dictionary-ish combos (combosquat)
    for w in ("login", "secure", "support", "account", "verify", "online", "app", "help", "my"):
        add(f"{name}-{w}", "dictionary")
        add(f"{w}-{name}", "dictionary")
    # TLD swap
    for t in COMMON_TLDS:
        if t != tld:
            add(name, "tld-swap", t)
    return [{"domain": d, "technique": t} for d, t in out.items()]


_PRIORITY = ["homoglyph", "tld-swap", "omission", "transposition", "replacement", "repetition", "addition",
             "hyphenation", "dictionary", "vowel-swap", "bitsquatting", "insertion", "subdomain"]


def _prioritise(perms: list[dict], limit: int) -> list[dict]:
    """Pick a representative subset: round-robin across techniques, ordered by phishing likelihood."""
    buckets: dict[str, list[dict]] = {}
    for p in perms:
        buckets.setdefault(p["technique"], []).append(p)
    order = [t for t in _PRIORITY if t in buckets] + [t for t in buckets if t not in _PRIORITY]
    out: list[dict] = []
    idx = 0
    while len(out) < limit and any(buckets.get(t) for t in order):
        for t in order:
            if buckets.get(t) and len(out) < limit:
                # prefer ascii-only first (more likely registered)
                out.append(buckets[t].pop(0))
        idx += 1
    return out


async def _resolve(resolver, domain: str, sem: asyncio.Semaphore) -> dict:
    async with sem:
        ip, mx = None, False
        try:
            ans = await resolver.resolve(domain, "A", lifetime=3.0)
            ip = next((r.to_text() for r in ans), None)
        except Exception:
            ip = None
        if ip is None:
            try:
                ans = await resolver.resolve(domain, "AAAA", lifetime=2.0)
                ip = next((r.to_text() for r in ans), None)
            except Exception:
                pass
        if ip is not None:
            try:
                await resolver.resolve(domain, "MX", lifetime=2.0)
                mx = True
            except Exception:
                mx = False
        return {"resolves": ip is not None, "ip": ip, "mx": mx}


async def check_permutations(domain: str, limit: int = 60) -> list[dict]:
    """Resolve up to `limit` permutations concurrently (max 30 in flight). Resolving ones listed first."""
    try:
        perms = generate_permutations(domain)
        if not perms:
            return []
        chosen = _prioritise(perms, max(1, int(limit)))
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        sem = asyncio.Semaphore(30)
        res = await asyncio.wait_for(
            asyncio.gather(*[_resolve(resolver, p["domain"], sem) for p in chosen], return_exceptions=True),
            timeout=25,
        )
        out = []
        for p, r in zip(chosen, res):
            if isinstance(r, BaseException):
                r = {"resolves": False, "ip": None, "mx": False}
            out.append({**p, **r})
        out.sort(key=lambda x: (not x["resolves"]))
        return out
    except Exception:
        return [{**p, "resolves": False, "ip": None, "mx": False} for p in generate_permutations(domain)[:limit]]
