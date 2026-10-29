"""Scan endpoints: scan, history (+ v2 pivot filters), detail, rescan, tags/notes, compare, export,
DOM snapshot, timeline, domain view. (GET /api/scans/{id}/similar lives in routers/insights.py.)"""
from __future__ import annotations

import csv
import io
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app import db
from app.services.events import event_out, log_event
from app.services.filters import SORT_COLUMNS, active_filters, build_filters
from app.services.scanner import (SUMMARY_COLS, InvalidURL, get_dom, get_scan, normalize_url, perform_scan,
                                  row_to_result, row_to_summary)

router = APIRouter(prefix="/api", tags=["Scans"])

SortT = Literal["created_at", "risk_score", "domain", "duration_ms", "confidence", "trust_score"]


class ScanRequest(BaseModel):
    url: str = Field(..., description="URL to analyse (http:// is added if the scheme is missing)",
                     examples=["paypal-login.example-verify.com/signin"])
    deep: bool = Field(True, description="Run network checks (WHOIS, DNS, SSL, HTTP, content). False = lexical + ML only")
    source: Optional[Literal["web", "api", "bulk", "text", "qr", "watch", "extension"]] = "web"


class ScanPatch(BaseModel):
    tags: Optional[list[str]] = None
    notes: Optional[str] = None


@router.post("/scan", summary="Scan a URL", description="Runs the ML model and the analysis engine concurrently, "
             "computes a risk score and verdict, persists and returns the full ScanResult.")
async def scan(req: ScanRequest):
    try:
        return await perform_scan(req.url, source=req.source or "web", deep=req.deep)
    except InvalidURL as e:
        raise HTTPException(status_code=422, detail=str(e))


def scan_filters(
        q: Optional[str] = Query(None, description="Search URL, domain, brand, notes (substring) or exact IP"),
        verdict: Optional[str] = Query(None, description="Comma list: legitimate,suspicious,phishing"),
        source: Optional[str] = None, tld: Optional[str] = None, brand: Optional[str] = None,
        min_risk: Optional[int] = Query(None, ge=0, le=100), max_risk: Optional[int] = Query(None, ge=0, le=100),
        date_from: Optional[str] = None, date_to: Optional[str] = None, tag: Optional[str] = None,
        domain: Optional[str] = None, blacklisted: Optional[bool] = None,
        ip: Optional[str] = Query(None, description="v2: exact IP (comma list)"),
        asn: Optional[str] = Query(None, description="v2: ASN, e.g. AS15169 or 15169 (comma list)"),
        registrar: Optional[str] = Query(None, description="v2: registrar (case-insensitive substring)"),
        category: Optional[str] = Query(None, description="v2: content category (comma list)"),
        threat_type: Optional[str] = Query(None, description="v2: malware|social_engineering|unwanted_software|none"),
        tier: Optional[str] = Query(None, description="v2: Trusted|Favorable|Neutral|Questionable|Untrusted")) -> dict:
    return {"q": q, "verdict": verdict, "source": source, "tld": tld, "brand": brand, "min_risk": min_risk,
            "max_risk": max_risk, "date_from": date_from, "date_to": date_to, "tag": tag, "domain": domain,
            "blacklisted": blacklisted, "ip": ip, "asn": asn, "registrar": registrar, "category": category,
            "threat_type": threat_type, "tier": tier}


@router.get("/scans", summary="List scans (history)", description="Paginated, filterable list of ScanSummary. "
            "`verdict`, `source`, `tld`, `category`, `threat_type`, `tier`, `ip`, `asn` accept comma-separated lists.")
async def list_scans(f: dict = Depends(scan_filters), sort: SortT = "created_at",
                     order: Literal["asc", "desc"] = "desc", page: int = Query(1, ge=1),
                     page_size: int = Query(25, ge=1, le=500)):
    w, p = build_filters(f)
    col = SORT_COLUMNS[sort]
    o = "ASC" if order == "asc" else "DESC"
    total = db.scalar(f"SELECT COUNT(*) FROM scans{w}", p, 0)
    rows = db.query(f"SELECT {SUMMARY_COLS} FROM scans{w} ORDER BY {col} {o}, id {o} LIMIT ? OFFSET ?",
                    [*p, page_size, (page - 1) * page_size])
    return {"items": [row_to_summary(r) for r in rows], "total": total, "page": page, "page_size": page_size,
            "filters": active_filters(f)}


EXPORT_COLS = ["id", "created_at", "url", "domain", "registered_domain", "tld", "verdict", "risk_score", "confidence",
               "ml_prob", "heuristic_score", "source", "brand", "brand_technique", "country_code", "country",
               "blacklisted", "duration_ms", "tags", "notes",
               # v2
               "trust_score", "tier", "threat_type", "tested_depth", "category", "ip", "asn", "registrar"]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(v):
    """Neutralise spreadsheet formula injection: text cells starting with = + - @ (or TAB/CR) get a leading quote."""
    if isinstance(v, str) and v.startswith(_FORMULA_PREFIXES):
        return "'" + v
    return v


@router.get("/scans/export", summary="Export scans", description="Download scans matching the same filters as "
            "`GET /api/scans` as CSV (summary columns, formula-injection safe) or JSON (full ScanResult objects). "
            "Max 10,000 rows.")
async def export_scans(format: Literal["csv", "json"] = "csv", f: dict = Depends(scan_filters),
                       sort: SortT = "created_at", order: Literal["asc", "desc"] = "desc"):
    w, p = build_filters(f)
    col = SORT_COLUMNS[sort]
    o = "ASC" if order == "asc" else "DESC"
    stamp = db.now_iso().replace(":", "").replace("-", "")[:15]
    if format == "json":
        rows = db.query(f"SELECT * FROM scans{w} ORDER BY {col} {o}, id {o} LIMIT 10000", p)
        dom_ids = {r["scan_id"] for r in db.query("SELECT scan_id FROM scan_dom")}
        body = db.dumps([row_to_result(r, live_community=False, dom=r["id"] in dom_ids) for r in rows])
        media, fname = "application/json", f"phishguard-scans-{stamp}.json"
    else:
        rows = db.query(f"SELECT {', '.join(EXPORT_COLS)} FROM scans{w} ORDER BY {col} {o}, id {o} LIMIT 10000", p)
        buf = io.StringIO()
        wr = csv.writer(buf)
        wr.writerow(EXPORT_COLS)
        for r in rows:
            r["tags"] = ";".join(db.loads(r["tags"], []) or [])
            r["blacklisted"] = bool(r["blacklisted"])
            wr.writerow([csv_safe(r[c]) for c in EXPORT_COLS])
        body = buf.getvalue()
        media, fname = "text/csv; charset=utf-8", f"phishguard-scans-{stamp}.csv"
    log_event("export", f"Exported {len(rows)} scans as {format.upper()}",
              {"format": format, "count": len(rows), "filters": active_filters(f)})
    return Response(content=body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{fname}"'})


def _get_or_404(scan_id: int) -> dict:
    s = get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    return s


@router.get("/scans/{scan_id}", summary="Get full scan result")
async def get_scan_ep(scan_id: int):
    return _get_or_404(scan_id)


@router.delete("/scans/{scan_id}", summary="Delete a scan")
async def delete_scan(scan_id: int):
    s = _get_or_404(scan_id)
    db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    db.execute("DELETE FROM scan_dom WHERE scan_id = ?", (scan_id,))
    db.execute("UPDATE bulk_items SET scan_id = NULL WHERE scan_id = ?", (scan_id,))
    log_event("delete", f"Deleted scan #{scan_id} ({s['domain']})", {"scan_id": scan_id, "url": s["url"]},
              entity_type="scan", entity_id=scan_id, scan_id=scan_id, domain=s["domain"])
    return {"deleted": True, "id": scan_id}


@router.post("/scans/{scan_id}/rescan", summary="Rescan", description="Re-runs the full pipeline for the scan's URL. "
             "Creates and returns a NEW scan (tags are carried over) so history can be compared.")
async def rescan(scan_id: int, deep: bool = True):
    s = _get_or_404(scan_id)
    tags = [t for t in (s.get("tags") or []) if t != "demo"]
    src = s.get("source") or "web"
    if src in ("seed", "community"):
        src = "web"
    return await perform_scan(s["url"], source=src, deep=deep, tags=tags, event_type="rescan",
                              event_meta={"previous_scan_id": scan_id})


@router.patch("/scans/{scan_id}", summary="Update tags / notes")
async def patch_scan(scan_id: int, body: ScanPatch):
    s = _get_or_404(scan_id)
    vals = {}
    if body.tags is not None:
        vals["tags"] = db.dumps(sorted({t.strip() for t in body.tags if t and t.strip()}))
    if body.notes is not None:
        vals["notes"] = body.notes or None
    db.update("scans", scan_id, vals)
    log_event("scan_update", f"Updated scan #{scan_id}", {"scan_id": scan_id, "tags": body.tags,
                                                          "notes_changed": body.notes is not None},
              entity_type="scan", entity_id=scan_id, scan_id=scan_id, domain=s["domain"])
    return _get_or_404(scan_id)


def _dig(d: dict, path: str):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


COMPARE_FIELDS = ["url", "created_at", "verdict", "risk_score", "confidence", "duration_ms", "ml.probability_phishing",
                  "ml.model_version", "domain_info.ip", "domain_info.whois.registrar", "domain_info.whois.age_days",
                  "domain_info.geo.country", "domain_info.geo.asn", "ssl.valid", "ssl.issuer", "ssl.days_left",
                  "http.reachable", "http.status_code", "http.final_url", "http.title", "http.server",
                  "http.forms.login_form", "http.forms.password_fields", "brand.impersonated_brand", "brand.technique",
                  "reputation.blacklisted", "screenshot_url",
                  # v2
                  "trust_score", "tier", "threat_type", "tested_depth", "reputation.engine_ratio.flagged",
                  "reputation.engine_ratio.total", "popularity.rank", "content.category", "content.language",
                  "content.parked.parked"]


@router.get("/scans/{scan_id}/compare/{other_id}", summary="Compare two scans")
async def compare(scan_id: int, other_id: int):
    a, b = _get_or_404(scan_id), _get_or_404(other_id)
    diff = []
    for f in COMPARE_FIELDS:
        va, vb = _dig(a, f), _dig(b, f)
        if va != vb:
            diff.append({"field": f, "a": va, "b": vb})
    ca = {c.get("id"): c for c in a.get("checks") or [] if isinstance(c, dict)}
    cb = {c.get("id"): c for c in b.get("checks") or [] if isinstance(c, dict)}
    for cid in sorted(set(ca) | set(cb), key=str):
        sa, sb = (ca.get(cid) or {}).get("status"), (cb.get(cid) or {}).get("status")
        if sa != sb:
            diff.append({"field": f"checks.{cid}", "a": sa, "b": sb})
    ra = sorted(str(s.get("name")) for s in a["reputation"].get("sources") or [] if isinstance(s, dict) and s.get("listed"))
    rb = sorted(str(s.get("name")) for s in b["reputation"].get("sources") or [] if isinstance(s, dict) and s.get("listed"))
    if ra != rb:
        diff.append({"field": "reputation.listed_sources", "a": ra, "b": rb})
    return {"a": a, "b": b, "diff": diff}


@router.get("/scans/{scan_id}/dom", summary="DOM / HTML snapshot (v2)",
            description="The stored HTML of the final page (gzipped in `scan_dom`), max 500 KB. "
                        "404 if the scan has no snapshot.")
async def scan_dom(scan_id: int):
    if not db.scalar("SELECT 1 FROM scans WHERE id = ?", (scan_id,), 0):
        raise HTTPException(status_code=404, detail="Scan not found")
    d = get_dom(scan_id)
    if not d:
        raise HTTPException(status_code=404, detail="No DOM snapshot for this scan")
    return d


@router.get("/scans/{scan_id}/timeline", summary="Scan / domain timeline (v2)",
            description="Activity-log events for this scan (entity scan) and its domain (entity domain, or any event "
                        "related to the same host / registered domain), newest first.")
async def scan_timeline(scan_id: int, limit: int = Query(200, ge=1, le=1000)):
    row = db.query_one("SELECT id, domain, registered_domain FROM scans WHERE id = ?", (scan_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    doms = sorted({d for d in (row["domain"], row["registered_domain"]) if d})
    ph = ",".join("?" for _ in doms) or "''"
    rows = db.query(
        f"SELECT * FROM events WHERE (entity_type = 'scan' AND entity_id = ?) OR scan_id = ? "
        f"OR (entity_type = 'domain' AND entity_id IN ({ph})) OR domain IN ({ph}) "
        "ORDER BY created_at DESC, id DESC LIMIT ?", [str(scan_id), scan_id, *doms, *doms, limit])
    return [event_out(r) for r in rows]


domains_router = APIRouter(prefix="/api", tags=["Domains"])


@domains_router.get("/domains/{domain}", summary="Domain intelligence",
                    description="All scans for a host or registered domain, with risk trend and latest full result.")
async def domain_view(domain: str):
    d = domain.strip().lower()
    if "://" in d:
        try:
            d = normalize_url(d)[2]
        except InvalidURL:
            pass
    rows = db.query(f"SELECT {SUMMARY_COLS} FROM scans WHERE domain = ? OR registered_domain = ? ORDER BY created_at DESC",
                    (d, d))
    if not rows:
        return {"domain": d, "scans": [], "first_seen": None, "last_seen": None, "scan_count": 0, "avg_risk": None,
                "latest": None, "risk_trend": []}
    latest = get_scan(rows[0]["id"])
    return {"domain": d, "scans": [row_to_summary(r) for r in rows[:200]],
            "first_seen": rows[-1]["created_at"], "last_seen": rows[0]["created_at"], "scan_count": len(rows),
            "avg_risk": round(sum(r["risk_score"] or 0 for r in rows) / len(rows), 1), "latest": latest,
            "risk_trend": [{"t": r["created_at"], "risk": r["risk_score"], "scan_id": r["id"]} for r in reversed(rows)]}
