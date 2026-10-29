"""Scan pipeline: normalise -> ML + analysis engine (concurrently) -> score (v1 + v2 finalize) -> persist -> log."""
from __future__ import annotations

import asyncio
import gzip
import ipaddress
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

import tldextract

from app import db, scoring
from app.scoring import compute_score
from app.services.events import create_alert, log_event
from app.services.filters import norm_asn
from app.services.settings_service import get_settings

log = logging.getLogger("phishguard.scanner")

_extract = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled public suffix list
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$", re.I)
SOURCES = {"web", "api", "bulk", "text", "qr", "watch", "extension", "community", "seed"}
DOM_MAX_BYTES = 500 * 1024
# engine output keys that are copied into the ScanResult as-is (defaults when the engine does not provide them)
V2_PASSTHROUGH = {"popularity": None, "content": None, "summary_points": [], "coverage": None}
ENGINE_SKIP = {"dom_html", "url", "network_checks"}


class InvalidURL(ValueError):
    pass


# --------------------------------------------------------------------------- URL helpers
def split_host(host: str) -> dict:
    host = (host or "").lower().strip(".")
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        return {"registered_domain": host, "tld": "", "subdomain": "", "is_ip": True}
    ext = _extract(host)
    reg = ".".join(p for p in (ext.domain, ext.suffix) if p) if ext.suffix else host
    return {"registered_domain": reg, "tld": ext.suffix or host.rsplit(".", 1)[-1],
            "subdomain": ext.subdomain, "is_ip": False}


def normalize_url(raw: str) -> tuple[str, str, str]:
    """Returns (url, normalized_url, host). Raises InvalidURL."""
    if raw is None:
        raise InvalidURL("URL is required")
    url = str(raw).strip()
    if not url:
        raise InvalidURL("URL is required")
    if any(c.isspace() for c in url):
        raise InvalidURL("URL must not contain whitespace")
    if len(url) > 4096:
        raise InvalidURL("URL too long")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url.lstrip("/")
    try:
        parts = urlsplit(url)
    except ValueError as e:
        raise InvalidURL(f"Invalid URL: {e}")
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidURL("Only http and https URLs are supported")
    host = (parts.hostname or "").lower()
    if not host:
        raise InvalidURL("URL has no host")
    try:
        port = parts.port
    except ValueError:
        raise InvalidURL("Invalid port")
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if not is_ip and host != "localhost":
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except Exception:
            ascii_host = host
        labels = ascii_host.strip(".").split(".")
        if len(labels) < 2 or not all(_LABEL_RE.match(lb) for lb in labels):
            raise InvalidURL(f"Invalid host: {host}")
        if not re.match(r"^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$", labels[-1], re.I):
            raise InvalidURL(f"Invalid top-level domain: {labels[-1]}")
    netloc = host if not (":" in host and is_ip) else f"[{host}]"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc += f":{port}"
    if parts.username:
        userinfo = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{userinfo}@{netloc}"
    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return url, normalized, host


# --------------------------------------------------------------------------- community
def community_for(domain: str | None, url: str | None = None) -> dict:
    rows = db.query("SELECT label, status, phishing_votes, legitimate_votes FROM reports WHERE domain = ? OR url = ?",
                    (domain or "", url or ""))
    if not rows:
        return {"reports": 0, "phishing_votes": 0, "legitimate_votes": 0, "status": "none"}
    statuses = {r["status"] for r in rows}
    status = "verified" if "verified" in statuses else "rejected" if statuses == {"rejected"} else "pending"
    return {"reports": len(rows), "phishing_votes": sum(r["phishing_votes"] or 0 for r in rows),
            "legitimate_votes": sum(r["legitimate_votes"] or 0 for r in rows), "status": status}


# --------------------------------------------------------------------------- pipeline pieces
def _ml_predict(url: str) -> dict:
    try:
        from ml.predictor import predict
        res = predict(url) or {}
        return res
    except Exception as e:
        log.exception("ML predict failed")
        feats = {}
        try:
            from ml.features import extract_features
            feats = extract_features(url)
        except Exception:
            pass
        return {"model_name": "unavailable", "model_version": "n/a", "probability_phishing": 0.5,
                "per_model": [], "explanations": [], "features": feats, "error": str(e)}


def _empty_engine(err: str | None = None) -> dict:
    checks = []
    if err:
        checks.append({"id": "engine", "category": "network", "name": "Analysis engine", "status": "error",
                       "detail": err, "weight": 0})
    return {"domain_info": {}, "ssl": {}, "http": {},
            "brand": {"impersonated_brand": None, "similarity": 0, "technique": None, "details": ""},
            "reputation": {"blacklisted": False, "sources": []}, "screenshot_url": None,
            "checks": checks, "heuristic_score": 0}


def engine_budget(engine_settings: dict) -> float:
    return max(25.0, float(engine_settings.get("timeout_s") or 8) * 2 + 10)


async def _engine(url: str, engine_settings: dict) -> dict:
    try:
        from app.analysis.engine import run_checks
        res = await asyncio.wait_for(run_checks(url, engine_settings), timeout=engine_budget(engine_settings))
        return res if isinstance(res, dict) and res else _empty_engine("engine returned nothing")
    except asyncio.TimeoutError:
        return _empty_engine("analysis timed out")
    except Exception as e:
        log.exception("engine failed")
        return _empty_engine(f"engine error: {e}")


def _feed_lookup(url: str) -> list[dict]:
    try:
        from app.analysis.feeds import lookup
        return lookup(url) or []
    except Exception:
        return []


def _geo(domain_info: dict) -> tuple[str | None, str | None]:
    geo = (domain_info or {}).get("geo") or {}
    cc = geo.get("country_code") or None
    name = geo.get("country") or None
    if not cc:
        wc = ((domain_info or {}).get("whois") or {}).get("country")
        if isinstance(wc, str) and len(wc) == 2:
            cc = wc.upper()
    return (cc.upper() if isinstance(cc, str) else None), name


def engine_settings_from(settings: dict, deep: bool = True) -> dict:
    net = bool(settings.get("enable_network_checks", True)) and deep
    return {
        "enable_network_checks": net,
        "enable_screenshots": bool(settings.get("enable_screenshots", False)) and deep,
        "timeout_s": float(settings.get("timeout_s") or 8.0),
        "virustotal_api_key": settings.get("virustotal_api_key"),
        "google_safe_browsing_api_key": settings.get("google_safe_browsing_api_key"),
        # v2
        "enable_dnsbl": bool(settings.get("enable_dnsbl", True)) and net,
        "enable_rdap": bool(settings.get("enable_rdap", True)) and net,
    }


# --------------------------------------------------------------------------- DOM storage
def take_dom(engine: dict) -> str | None:
    """Remove dom_html (top level, or http.dom_html) from the engine output and return it."""
    raw = engine.pop("dom_html", None)
    http = engine.get("http")
    if isinstance(http, dict) and "dom_html" in http:
        http = dict(http)
        raw = raw or http.pop("dom_html", None)
        engine["http"] = http
    return raw if isinstance(raw, str) and raw.strip() else None


def store_dom(scan_id: int, html: str, source: str | None = None, page_size_kb: float | None = None) -> dict:
    data = html.encode("utf-8", errors="replace")
    truncated = len(data) > DOM_MAX_BYTES
    try:
        if page_size_kb and float(page_size_kb) * 1024 > DOM_MAX_BYTES + 1024:
            truncated = True
    except (TypeError, ValueError):
        pass
    if len(data) > DOM_MAX_BYTES:
        data = data[:DOM_MAX_BYTES].decode("utf-8", errors="ignore").encode("utf-8")
    db.execute("INSERT OR REPLACE INTO scan_dom(scan_id, html_gz, size, truncated, source, created_at) "
               "VALUES(?, ?, ?, ?, ?, ?)", (scan_id, gzip.compress(data, 6), len(data), 1 if truncated else 0,
                                           source, db.now_iso()))
    return {"size": len(data), "truncated": truncated}


def get_dom(scan_id: int) -> dict | None:
    r = db.query_one("SELECT html_gz, size, truncated, source FROM scan_dom WHERE scan_id = ?", (scan_id,))
    if not r:
        return None
    try:
        html = gzip.decompress(r["html_gz"]).decode("utf-8", errors="replace")
    except Exception:
        return None
    return {"html": html, "size": r["size"] if r["size"] is not None else len(html.encode()),
            "truncated": bool(r["truncated"]), "source": r["source"]}


def has_dom(scan_id: int) -> bool:
    return bool(db.scalar("SELECT 1 FROM scan_dom WHERE scan_id = ?", (scan_id,), 0))


# --------------------------------------------------------------------------- indexed v2 columns
def _str_or_none(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
        if v is None:
            return None
    s = str(v).strip()
    return s or None


def v2_columns(result: dict) -> dict:
    """Indexed v2 columns (pivot filters / graph / analytics) derived from a ScanResult."""
    di = result.get("domain_info") or {}
    content = result.get("content") if isinstance(result.get("content"), dict) else {}
    return {
        "ip": _str_or_none(di.get("ip")),
        "asn": norm_asn((di.get("geo") or {}).get("asn")),
        "registrar": _str_or_none((di.get("whois") or {}).get("registrar")),
        "threat_type": result.get("threat_type"),
        "trust_score": result.get("trust_score"),
        "tier": result.get("tier"),
        "category": _str_or_none(content.get("category")),
        "tested_depth": result.get("tested_depth"),
    }


# --------------------------------------------------------------------------- the pipeline
async def perform_scan(raw_url: str, source: str = "web", deep: bool = True, tags: list[str] | None = None,
                       settings_override: dict | None = None, log_events: bool = True,
                       make_alerts: bool = True, event_type: str = "scan", event_meta: dict | None = None) -> dict:
    url, normalized, host = normalize_url(raw_url)
    source = source if source in SOURCES else "api"
    settings = get_settings()
    if settings_override:
        settings = {**settings, **settings_override}
    eng_settings = engine_settings_from(settings, deep)

    t0 = time.perf_counter()
    ml_task = asyncio.to_thread(_ml_predict, normalized)
    feed_task = asyncio.to_thread(_feed_lookup, normalized)
    ml, engine, feed_hits = await asyncio.gather(ml_task, _engine(normalized, eng_settings), feed_task)
    duration_ms = int(round((time.perf_counter() - t0) * 1000))
    dom_html = take_dom(engine)

    hp = split_host(host)
    domain_info = dict(engine.get("domain_info") or {})
    domain_info.setdefault("domain", host)
    domain_info.setdefault("registered_domain", hp["registered_domain"])
    domain_info.setdefault("subdomain", hp["subdomain"])
    domain_info.setdefault("tld", hp["tld"])
    domain_info.setdefault("is_ip", hp["is_ip"])
    domain = (domain_info.get("domain") or host).lower()
    registered_domain = domain_info.get("registered_domain") or hp["registered_domain"]
    tld = domain_info.get("tld") or hp["tld"]

    reputation = dict(engine.get("reputation") or {})
    sources = list(reputation.get("sources") or [])
    names = {str(s.get("name", "")).lower() for s in sources if isinstance(s, dict)}
    for hit in feed_hits:
        if str(hit.get("name", "")).lower() not in names:
            sources.append({"name": hit.get("name"), "listed": bool(hit.get("listed", True)),
                            "detail": hit.get("detail", "")})
        else:  # make sure a positive API-side hit is reflected in the engine's entry
            for s in sources:
                if isinstance(s, dict) and str(s.get("name", "")).lower() == str(hit.get("name", "")).lower() \
                        and not s.get("listed") and hit.get("listed", True):
                    s["listed"] = True
                    s["detail"] = hit.get("detail") or s.get("detail")
    blacklisted = bool(reputation.get("blacklisted")) or any(
        isinstance(s, dict) and s.get("listed") for s in sources)
    community = community_for(domain, normalized)
    community_verified = community["status"] == "verified"

    ml_prob = float(ml.get("probability_phishing") or 0.0)
    heuristic = float(engine.get("heuristic_score") or 0.0)
    score = compute_score(ml_prob, heuristic, blacklisted, community_verified,
                          settings.get("suspicious_threshold", 35), settings.get("phishing_threshold", 65))

    brand = engine.get("brand") or {}
    cc, country = _geo(domain_info)
    created_at = db.now_iso()
    checks = engine.get("checks") or []
    tested_depth = "full" if eng_settings["enable_network_checks"] else "lexical"
    cov = engine.get("coverage")
    if isinstance(cov, dict) and cov.get("network") is False:
        tested_depth = "lexical"
    rep_out = {**reputation, "blacklisted": blacklisted, "sources": sources, "community": community}
    result = {
        "id": None, "url": url, "normalized_url": normalized, "domain": domain,
        "registered_domain": registered_domain, "tld": tld, "created_at": created_at,
        "duration_ms": duration_ms, "source": source,
        "verdict": score["verdict"], "risk_score": score["risk_score"], "confidence": score["confidence"],
        "ml": {"model_name": ml.get("model_name"), "model_version": ml.get("model_version"),
               "probability_phishing": round(ml_prob, 4), "per_model": ml.get("per_model") or [],
               "explanations": ml.get("explanations") or []},
        "features": ml.get("features") or {},
        "checks": checks,
        "domain_info": domain_info, "ssl": engine.get("ssl") or {}, "http": engine.get("http") or {},
        "brand": brand,
        "reputation": rep_out,
        "screenshot_url": engine.get("screenshot_url"),
        "score_breakdown": score["score_breakdown"],
        "heuristic_score": round(heuristic, 1),
        "network_checks": eng_settings["enable_network_checks"],
        "tested_depth": tested_depth,
        "tags": list(tags or []), "notes": None,
    }
    for k, default in V2_PASSTHROUGH.items():
        v = engine.get(k, default)
        result[k] = v if v is not None else default
    for k, v in engine.items():
        if k not in result and k not in ENGINE_SKIP:
            result[k] = v
    if not isinstance(result.get("coverage"), dict):
        result["coverage"] = {"network": tested_depth == "full", "checks_total": len(checks),
                              "checks_errored": sum(1 for c in checks if isinstance(c, dict)
                                                    and c.get("status") == "error")}
    scoring.finalize(result, settings, community_verified=community_verified, apply_cap=True)
    result["has_dom"] = bool(dom_html)

    cols = {
        "url": url, "normalized_url": normalized, "domain": domain, "registered_domain": registered_domain,
        "tld": tld, "created_at": created_at, "duration_ms": duration_ms, "source": source,
        "verdict": result["verdict"], "risk_score": result["risk_score"], "confidence": result["confidence"],
        "ml_prob": ml_prob, "heuristic_score": heuristic, "brand": brand.get("impersonated_brand"),
        "brand_technique": brand.get("technique"), "country_code": cc, "country": country,
        "blacklisted": 1 if blacklisted else 0, "tags": db.dumps(result["tags"]), "notes": None,
        **v2_columns(result),
    }
    stored = {k: v for k, v in result.items() if k != "has_dom"}
    cols["data"] = db.dumps(stored)
    scan_id = db.insert("scans", cols)
    result["id"] = scan_id
    if dom_html:
        try:
            store_dom(scan_id, dom_html, "http", (result.get("http") or {}).get("page_size_kb"))
        except Exception:
            log.exception("DOM storage failed")
            result["has_dom"] = False

    if log_events:
        log_event(event_type, f"Scanned {domain}: {result['verdict']} ({result['risk_score']})",
                  {"scan_id": scan_id, "url": url, "verdict": result["verdict"], "risk_score": result["risk_score"],
                   "source": source, "duration_ms": duration_ms, **(event_meta or {})},
                  entity_type="scan", entity_id=scan_id, scan_id=scan_id, domain=domain)
    if make_alerts and result["verdict"] == "phishing" and (result["risk_score"] >= 80 or blacklisted):
        since = db.to_iso(datetime.now(timezone.utc) - timedelta(hours=1))
        recent = db.scalar("SELECT COUNT(*) FROM alerts a JOIN scans s ON s.id = a.scan_id "
                           "WHERE a.type='high_risk_scan' AND s.domain = ? AND a.created_at >= ?",
                           (domain, since), 0)
        if not recent:
            b = brand.get("impersonated_brand")
            create_alert("high_risk_scan", "critical",
                         f"High-risk phishing detected: {domain}",
                         f"Risk {result['risk_score']}/100" + (f", impersonating {b}" if b else "")
                         + (", blacklisted" if blacklisted else "") + f" (source: {source})",
                         scan_id=scan_id, domain=domain)
    return result


# --------------------------------------------------------------------------- reading
_ROW_FIELDS = ("url", "normalized_url", "domain", "registered_domain", "tld", "created_at", "duration_ms",
               "source", "verdict", "risk_score", "confidence")
_ROW_FIELDS_V2 = ("trust_score", "tier", "threat_type", "tested_depth")
_RESULT_DEFAULTS = (("ml", {}), ("features", {}), ("checks", []), ("domain_info", {}), ("ssl", {}), ("http", {}),
                    ("brand", {}), ("score_breakdown", []), ("screenshot_url", None), ("factors", None),
                    ("summary", ""), ("summary_points", []), ("popularity", None), ("content", None),
                    ("coverage", None), ("threat_reasons", []))


def row_to_result(row: dict, live_community: bool = True, dom: bool | None = None) -> dict:
    data = db.loads(row["data"], {}) or {}
    data["id"] = row["id"]
    for k in _ROW_FIELDS:
        data[k] = row[k]
    for k in _ROW_FIELDS_V2:
        if row.get(k) is not None:
            data[k] = row[k]
    data["tags"] = db.loads(row.get("tags"), []) or []
    data["notes"] = row.get("notes")
    rep = data.setdefault("reputation", {"blacklisted": bool(row["blacklisted"]), "sources": []})
    if live_community:
        rep["community"] = community_for(row["domain"], row["normalized_url"])
    for k, d in _RESULT_DEFAULTS:
        data.setdefault(k, d)
    data.pop("dom_html", None)
    if data.get("trust_score") is None:
        data["trust_score"] = scoring.trust_score_for(row["risk_score"])
    if not data.get("tier"):
        data["tier"] = scoring.tier_for(row["risk_score"])
    data.setdefault("threat_type", "none")
    data.setdefault("tested_depth", "full" if data.get("network_checks", True) else "lexical")
    if not isinstance(data.get("factors"), dict):
        data["factors"] = {"positive": [], "negative": []}
    data["has_dom"] = has_dom(row["id"]) if dom is None else bool(dom)
    return data


def row_to_summary(row: dict) -> dict:
    risk = row.get("risk_score")
    trust = row.get("trust_score")
    return {"id": row["id"], "url": row["url"], "domain": row["domain"], "tld": row["tld"],
            "created_at": row["created_at"], "verdict": row["verdict"], "risk_score": risk,
            "confidence": row["confidence"], "source": row["source"], "brand": row["brand"],
            "country_code": row["country_code"], "blacklisted": bool(row["blacklisted"]),
            "duration_ms": row["duration_ms"],
            "trust_score": trust if trust is not None else scoring.trust_score_for(risk),
            "tier": row.get("tier") or scoring.tier_for(risk),
            "threat_type": row.get("threat_type") or "none", "category": row.get("category")}


SUMMARY_COLS = ("id, url, domain, tld, created_at, verdict, risk_score, confidence, source, brand, "
                "country_code, blacklisted, duration_ms, trust_score, tier, threat_type, category")


def get_scan(scan_id: int) -> dict | None:
    row = db.query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    return row_to_result(row) if row else None


def get_summary(scan_id: int) -> dict | None:
    row = db.query_one(f"SELECT {SUMMARY_COLS} FROM scans WHERE id = ?", (scan_id,))
    return row_to_summary(row) if row else None


# --------------------------------------------------------------------------- v1 -> v2 backfill
def backfill_v2(limit: int = 20000) -> int:
    """Compute v2 fields/columns for scans stored before v2 (idempotent: only rows missing them).
    Historical risk/verdict are kept (no popularity cap is applied retroactively)."""
    rows = db.query("SELECT * FROM scans WHERE trust_score IS NULL OR tier IS NULL OR tested_depth IS NULL LIMIT ?",
                    (limit,))
    if not rows:
        return 0
    settings = get_settings()
    n = 0
    for row in rows:
        try:
            data = db.loads(row["data"], {}) or {}
            for k in _ROW_FIELDS:
                data[k] = row[k]
            data.pop("dom_html", None)
            data.setdefault("tested_depth", "full" if data.get("network_checks", True) else "lexical")
            data.setdefault("summary_points", [])
            for k, d in V2_PASSTHROUGH.items():
                data.setdefault(k, d)
            scoring.finalize(data, settings, community_verified=False, apply_cap=False)
            cols = v2_columns(data)
            cols["data"] = db.dumps(data)
            db.update("scans", row["id"], cols)
            n += 1
        except Exception:
            log.exception("backfill failed for scan %s", row.get("id"))
    if n:
        log.info("Backfilled v2 fields for %d scans", n)
    return n
