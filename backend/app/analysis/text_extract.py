"""Extract URLs (including defanged and bare domains) from email / SMS text."""
from __future__ import annotations

import html
import re

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

_REFANG = [
    (re.compile(r"h[xX]{2}p(s?)", re.I), r"http\1"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)|\s\[?dot\]?\s", re.I), "."),
    (re.compile(r"\[\s*:\s*\]|\(\s*:\s*\)"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"(?<=\w)\s*\[\s*\.\s*(?=\w)"), "."),  # half-bracket "example[.com"
]

_SCHEME_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.I)
_WWW_URL = re.compile(r"\bwww\d{0,3}\.[^\s<>\"'`]+", re.I)
_BARE = re.compile(
    r"(?<![@\w.-])((?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+"
    r"(?:[a-z¡-￿]{2,24}|xn--[a-z0-9-]{2,30}))(?::\d{2,5})?(/[^\s<>\"'`]*)?",
    re.I,
)
_IP_URL = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?/[^\s<>\"'`]*")
_TRAIL = ".,;:!?)]}>'\"*"
_FILE_EXT = {"png", "jpg", "jpeg", "gif", "pdf", "doc", "docx", "xls", "xlsx", "txt", "zip", "exe", "js", "css",
             "py", "json", "csv", "mp4", "mp3", "html", "htm", "php"}


def _refang(text: str) -> str:
    t = html.unescape(text)
    for rx, rep in _REFANG:
        t = rx.sub(rep, t)
    return t


def _clean(u: str) -> str:
    # strip trailing punctuation, balance parentheses
    while u and u[-1] in _TRAIL:
        if u[-1] == ")" and u.count("(") >= u.count(")"):
            break
        u = u[:-1]
    return u


def _valid_bare(host: str) -> bool:
    host = host.lower().rstrip(".")
    ext = _EXTRACT(host)
    if not ext.suffix or not ext.domain:
        return False
    if ext.suffix in _FILE_EXT and not ext.subdomain and len(ext.domain) < 3:
        return False
    return True


def extract_urls(text: str) -> list[str]:
    """Return de-duplicated URLs in order of appearance. Never raises."""
    try:
        if not text:
            return []
        t = _refang(text)
        found: list[tuple[int, str]] = []
        spans: list[tuple[int, int]] = []

        def overl(a, b):
            return any(not (b <= s or a >= e) for s, e in spans)

        for rx in (_SCHEME_URL, _WWW_URL, _IP_URL):
            for m in rx.finditer(t):
                if overl(m.start(), m.end()):
                    continue
                u = _clean(m.group(0))
                if not u:
                    continue
                if not re.match(r"^[a-z]+://", u, re.I):
                    u = "http://" + u
                found.append((m.start(), u))
                spans.append((m.start(), m.end()))
        for m in _BARE.finditer(t):
            if overl(m.start(), m.end()):
                continue
            host = m.group(1)
            # skip email addresses
            if m.start() > 0 and t[m.start() - 1] == "@":
                continue
            if not _valid_bare(host):
                continue
            # skip things like "file.pdf" with no path and a file extension TLD
            suffix = host.rsplit(".", 1)[-1].lower()
            if suffix in _FILE_EXT and not m.group(2):
                continue
            u = _clean(m.group(0))
            found.append((m.start(), "http://" + u))
            spans.append((m.start(), m.end()))

        found.sort(key=lambda x: x[0])
        seen, out = set(), []
        for _, u in found:
            key = u.rstrip("/").lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(u)
        return out
    except Exception:
        try:
            return list(dict.fromkeys(re.findall(r"https?://\S+", text or "")))
        except Exception:
            return []
