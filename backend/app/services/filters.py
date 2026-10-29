"""Scan filters shared by GET /api/scans and /api/scans/export.

Everything is parameterised SQL; column names come only from the whitelists below.
"""
from __future__ import annotations

import re
from typing import Any

from app import db

# filter name -> column for comma-separated "IN" filters (case-insensitive)
LIST_FILTERS = {"verdict": "verdict", "source": "source", "threat_type": "threat_type", "category": "category",
                "tier": "tier"}
FILTER_KEYS = ("q", "verdict", "source", "tld", "brand", "min_risk", "max_risk", "date_from", "date_to", "tag",
               "domain", "blacklisted", "ip", "asn", "registrar", "category", "threat_type", "tier")
SORT_COLUMNS = {"created_at": "created_at", "risk_score": "risk_score", "domain": "domain",
                "duration_ms": "duration_ms", "confidence": "confidence", "trust_score": "trust_score"}


def norm_asn(v: Any) -> str | None:
    """15169 / "AS15169" / "as 15169 Google" -> "AS15169"."""
    if v is None or v == "" or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return f"AS{int(v)}"
    m = re.match(r"\s*(?:AS)?\s*(\d+)", str(v), re.I)
    return f"AS{m.group(1)}" if m else None


def _like_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _split(val: Any) -> list[str]:
    items = [str(x) for x in val] if isinstance(val, (list, tuple, set)) else str(val).split(",")
    return [x.strip() for x in items if x and x.strip()]


def _bool(v: Any) -> bool | None:
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def build_filters(filters: dict | None = None, alias: str = "", **kw: Any) -> tuple[str, list]:
    """Return (" WHERE ...", params) for the given filters (unknown/None/"" values are ignored)."""
    f = {**(filters or {}), **kw}
    a = f"{alias}." if alias else ""
    c: list[str] = []
    p: list[Any] = []

    q = f.get("q")
    if q not in (None, ""):
        c.append(f"({a}url LIKE ? OR {a}domain LIKE ? OR {a}brand LIKE ? OR {a}notes LIKE ? OR {a}ip = ?)")
        p += [f"%{q}%"] * 4 + [str(q).strip()]
    for key, col in LIST_FILTERS.items():
        vals = [v.lower() for v in _split(f[key])] if f.get(key) not in (None, "") else []
        if vals:
            c.append(f"LOWER({a}{col}) IN ({','.join('?' for _ in vals)})")
            p += vals
    if f.get("tld") not in (None, ""):
        vals = [v.lstrip(".").lower() for v in _split(f["tld"])]
        if vals:
            c.append(f"LOWER({a}tld) IN ({','.join('?' for _ in vals)})")
            p += vals
    if f.get("brand") not in (None, ""):
        c.append(f"LOWER({a}brand) = LOWER(?)")
        p.append(str(f["brand"]).strip())
    if f.get("domain") not in (None, ""):
        d = str(f["domain"]).strip().lower()
        c.append(f"({a}domain = ? OR {a}registered_domain = ?)")
        p += [d, d]
    for key, op in (("min_risk", ">="), ("max_risk", "<=")):
        v = f.get(key)
        if v not in (None, ""):
            try:
                p.append(int(float(v)))
                c.append(f"{a}risk_score {op} ?")
            except (TypeError, ValueError):
                pass
    if f.get("date_from"):
        d = db.parse_iso(f["date_from"])
        if d:
            c.append(f"{a}created_at >= ?")
            p.append(db.to_iso(d))
    if f.get("date_to"):
        raw = str(f["date_to"])
        d = db.parse_iso(raw)
        if d:
            s = db.to_iso(d)
            if len(raw.strip()) == 10:
                s = s[:10] + "T23:59:59Z"
            c.append(f"{a}created_at <= ?")
            p.append(s)
    if f.get("tag") not in (None, ""):
        c.append(f"{a}tags LIKE ?")
        p.append(f'%"{f["tag"]}"%')
    bl = _bool(f.get("blacklisted"))
    if bl is not None:
        c.append(f"{a}blacklisted = ?")
        p.append(1 if bl else 0)
    # ---- v2 pivots: ip / asn exact (comma lists), registrar case-insensitive substring
    if f.get("ip") not in (None, ""):
        vals = _split(f["ip"])
        c.append(f"{a}ip IN ({','.join('?' for _ in vals)})")
        p += vals
    if f.get("asn") not in (None, ""):
        vals = [x for x in (norm_asn(v) for v in _split(f["asn"])) if x] or ["AS-invalid"]
        c.append(f"UPPER({a}asn) IN ({','.join('?' for _ in vals)})")
        p += vals
    if f.get("registrar") not in (None, ""):
        c.append(f"{a}registrar LIKE ? ESCAPE '\\'")
        p.append(f"%{_like_escape(str(f['registrar']).strip())}%")
    return (" WHERE " + " AND ".join(c)) if c else "", p


def active_filters(filters: dict) -> dict:
    return {k: v for k, v in (filters or {}).items() if k in FILTER_KEYS and v not in (None, "")}
