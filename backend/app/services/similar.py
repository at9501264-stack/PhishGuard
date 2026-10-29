"""Similar scans for GET /api/scans/{id}/similar: other domains sharing this scan's IP, ASN or registrar.

Each list holds the newest scan per domain, excludes the scan's own domain and is capped at 20.
"""
from __future__ import annotations

from app import db
from app.services.analytics import field
from app.services.scanner import row_to_summary

LIMIT = 20
PIVOTS = ("ip", "asn", "registrar")


def similar(scan_id: int) -> dict | None:
    """{scan_id, pivots: {ip, asn, registrar}, same_ip, same_asn, same_registrar}, or None if the scan is missing."""
    pivot_sql = ", ".join(f"{field(k)} AS {k}" for k in PIVOTS)
    s = db.query_one(f"SELECT domain, {pivot_sql} FROM scans WHERE id = ?", (scan_id,))
    if not s:
        return None
    # every column except the large scan JSON -> works before and after the v2 columns exist
    cols = ", ".join(sorted(db.table_columns("scans") - {"data"}))
    out: dict = {"scan_id": scan_id, "pivots": {k: s[k] for k in PIVOTS}}
    for k in PIVOTS:
        items, seen = [], {s["domain"]}
        if s[k]:
            for r in db.query(f"SELECT {cols} FROM scans WHERE {field(k)} = ? AND domain != ? "
                              "ORDER BY created_at DESC, id DESC LIMIT 500", (s[k], s["domain"])):
                if r["domain"] in seen:
                    continue
                seen.add(r["domain"])
                items.append(row_to_summary(r))
                if len(items) >= LIMIT:
                    break
        out[f"same_{k}"] = items
    return out
