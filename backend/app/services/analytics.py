"""Analytics aggregations over the scans table (+ v2: threat types / tiers / categories, trust score, funnel)."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from app import db, scoring

RANGES = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30),
          "90d": timedelta(days=90), "all": None}
JSON_SCAN_LIMIT = 5000

COUNTRY_NAMES = {
    "US": "United States", "GB": "United Kingdom", "DE": "Germany", "FR": "France", "NL": "Netherlands",
    "IE": "Ireland", "CA": "Canada", "AU": "Australia", "JP": "Japan", "CN": "China", "HK": "Hong Kong",
    "SG": "Singapore", "IN": "India", "RU": "Russia", "UA": "Ukraine", "BR": "Brazil", "MX": "Mexico",
    "KR": "South Korea", "TW": "Taiwan", "SE": "Sweden", "NO": "Norway", "FI": "Finland", "DK": "Denmark",
    "PL": "Poland", "IT": "Italy", "ES": "Spain", "PT": "Portugal", "CH": "Switzerland", "AT": "Austria",
    "BE": "Belgium", "CZ": "Czechia", "RO": "Romania", "BG": "Bulgaria", "TR": "Turkey", "IR": "Iran",
    "IL": "Israel", "AE": "United Arab Emirates", "SA": "Saudi Arabia", "ZA": "South Africa", "NG": "Nigeria",
    "EG": "Egypt", "KE": "Kenya", "ID": "Indonesia", "VN": "Vietnam", "TH": "Thailand", "MY": "Malaysia",
    "PH": "Philippines", "PK": "Pakistan", "BD": "Bangladesh", "AR": "Argentina", "CL": "Chile",
    "CO": "Colombia", "PE": "Peru", "NZ": "New Zealand", "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia",
    "MD": "Moldova", "SC": "Seychelles", "PA": "Panama", "BZ": "Belize", "VG": "British Virgin Islands",
    "LU": "Luxembourg", "IS": "Iceland", "HU": "Hungary", "GR": "Greece", "SK": "Slovakia", "RS": "Serbia",
    "HR": "Croatia", "SI": "Slovenia", "CY": "Cyprus", "MT": "Malta", "KZ": "Kazakhstan", "BY": "Belarus",
}

TIER_ORDER = ("Trusted", "Favorable", "Neutral", "Questionable", "Untrusted")
THREAT_ORDER = ("malware", "social_engineering", "unwanted_software", "none")
FUNNEL_STAGES = ("Scanned", "Reachable", "Login/password form", "Brand impersonation", "Feed listed",
                 "Phishing verdict")

# Where each v2 scan field lives in the stored scan JSON. field() prefers the real column once the v2 migration
# has added it (falling back to the JSON for rows that predate it). Also used by graph.py and similar.py.
JSON_PATHS = {
    "ip": "$.domain_info.ip",
    "asn": "$.domain_info.geo.asn",
    "registrar": "$.domain_info.whois.registrar",
    "threat_type": "$.threat_type",
    "trust_score": "$.trust_score",
    "tier": "$.tier",
    "category": "$.content.category",
}


def field(name: str) -> str:
    """SQL expression for a v2 scan field (see JSON_PATHS)."""
    expr = f"json_extract(data, '{JSON_PATHS[name]}')"
    return f"COALESCE({name}, {expr})" if name in db.table_columns("scans") else expr


def bounds(range_: str) -> tuple[str | None, str | None, str, timedelta | None]:
    rng = range_ if range_ in RANGES else "30d"
    now = datetime.now(timezone.utc)
    delta = RANGES[rng]
    if delta is None:
        return None, None, db.to_iso(now), None
    return db.to_iso(now - delta), db.to_iso(now - 2 * delta), db.to_iso(now), delta


def _where(start: str | None, end: str | None = None, col: str = "created_at") -> tuple[str, list]:
    clauses, params = [], []
    if start:
        clauses.append(f"{col} >= ?")
        params.append(start)
    if end:
        clauses.append(f"{col} < ?")
        params.append(end)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def _pct(cur: float, prev: float) -> float:
    if not prev:
        return 0.0 if not cur else 100.0
    return round((cur - prev) / prev * 100, 1)


def _period_stats(start: str | None, end: str | None = None) -> dict:
    w, p = _where(start, end)
    r = db.query_one(
        "SELECT COUNT(*) total, SUM(verdict='phishing') phishing, SUM(verdict='suspicious') suspicious, "
        "SUM(verdict='legitimate') legitimate, AVG(risk_score) avg_risk, AVG(duration_ms) avg_dur, "
        "COUNT(DISTINCT registered_domain) uniq, SUM(blacklisted) bl, COUNT(DISTINCT brand) brands, "
        f"AVG(COALESCE({field('trust_score')}, 100 - risk_score)) avg_trust "
        f"FROM scans{w}", p) or {}
    return {k: (v or 0) for k, v in r.items()}


def overview(range_: str) -> dict:
    start, prev_start, _, delta = bounds(range_)
    cur = _period_stats(start)
    prev = _period_stats(prev_start, start) if delta else None
    total = cur["total"]
    rw, rp = _where(start)
    return {
        "range": range_,
        "total_scans": total,
        "phishing": cur["phishing"], "suspicious": cur["suspicious"], "legitimate": cur["legitimate"],
        "detection_rate": round((cur["phishing"] + cur["suspicious"]) / total * 100, 1) if total else 0.0,
        "avg_risk": round(cur["avg_risk"], 1), "avg_duration_ms": round(cur["avg_dur"]),
        "unique_domains": cur["uniq"], "blacklisted_hits": cur["bl"], "brands_impersonated": cur["brands"],
        "reports_total": db.scalar(f"SELECT COUNT(*) FROM reports{rw}", rp, 0),
        "reports_verified": db.scalar(f"SELECT COUNT(*) FROM reports{rw}{' AND' if rw else ' WHERE'} status='verified'",
                                      rp, 0),
        "watch_count": db.scalar("SELECT COUNT(*) FROM watchlist", (), 0),
        "unread_alerts": db.scalar("SELECT COUNT(*) FROM alerts WHERE read = 0", (), 0),
        "delta": {
            "total_scans": _pct(total, prev["total"]) if prev else 0.0,
            "phishing": _pct(cur["phishing"], prev["phishing"]) if prev else 0.0,
            "avg_risk": _pct(cur["avg_risk"], prev["avg_risk"]) if prev else 0.0,
            "avg_trust_score": _pct(cur["avg_trust"], prev["avg_trust"]) if prev else 0.0,
        },
        # v2: 0-100, trust_score = 100 - risk_score
        "avg_trust_score": round(cur["avg_trust"], 1) if total else 0.0,
    }


def _bucket_start(dt: datetime, bucket: str) -> datetime:
    if bucket == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def _first_scan_time() -> datetime | None:
    return db.parse_iso(db.scalar("SELECT MIN(created_at) FROM scans"))


def _buckets(range_: str, bucket: str | None) -> tuple[str, str, list[str], datetime]:
    start, _, _, _ = bounds(range_)
    if bucket not in ("hour", "day"):
        bucket = "hour" if range_ == "24h" else "day"
    now = datetime.now(timezone.utc)
    start_dt = db.parse_iso(start) if start else (_first_scan_time() or now)
    if bucket == "hour" and (now - start_dt) > timedelta(days=90):
        start_dt = now - timedelta(days=90)
    fmt = "%Y-%m-%dT%H:00:00Z" if bucket == "hour" else "%Y-%m-%dT00:00:00Z"
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    keys = []
    t = _bucket_start(start_dt, bucket)
    end = _bucket_start(now, bucket)
    while t <= end:
        keys.append(t.strftime(fmt))
        t += step
    return bucket, fmt, keys, start_dt


def timeseries(range_: str, bucket: str | None = None) -> list[dict]:
    bucket, fmt, keys, start_dt = _buckets(range_, bucket)
    w, p = _where(db.to_iso(start_dt))
    rows = db.query(
        f"SELECT strftime('{fmt}', created_at) b, COUNT(*) total, SUM(verdict='phishing') phishing, "
        "SUM(verdict='suspicious') suspicious, SUM(verdict='legitimate') legitimate, AVG(risk_score) avg_risk "
        f"FROM scans{w} GROUP BY b", p)
    by = {r["b"]: r for r in rows}
    out = []
    for key in keys:
        r = by.get(key)
        out.append({"t": key, "total": r["total"] if r else 0, "phishing": (r["phishing"] or 0) if r else 0,
                    "suspicious": (r["suspicious"] or 0) if r else 0, "legitimate": (r["legitimate"] or 0) if r else 0,
                    "avg_risk": round(r["avg_risk"], 1) if r and r["avg_risk"] is not None else 0})
    return out


def _top(sql: str, params: list, limit: int = 10) -> list[dict]:
    return [{"name": r["name"], "value": r["value"]} for r in db.query(sql + f" LIMIT {int(limit)}", params)]


def distribution(range_: str) -> dict:
    start, _, _, _ = bounds(range_)
    w, p = _where(start)
    andw = (w + " AND") if w else " WHERE"
    verdicts = {r["verdict"]: r["c"] for r in db.query(f"SELECT verdict, COUNT(*) c FROM scans{w} GROUP BY verdict", p)}
    hist = [0] * 10
    for r in db.query(f"SELECT MIN(CAST(risk_score / 10 AS INTEGER), 9) b, COUNT(*) c FROM scans{w} GROUP BY b", p):
        if r["b"] is not None:
            hist[int(r["b"])] += r["c"]
    countries = []
    for r in db.query(f"SELECT country_code code, MAX(country) cname, COUNT(*) value FROM scans{andw} country_code IS NOT NULL "
                      "AND country_code != '' GROUP BY country_code ORDER BY value DESC LIMIT 25", p):
        countries.append({"code": r["code"], "name": COUNTRY_NAMES.get(r["code"]) or r["cname"] or r["code"],
                          "value": r["value"]})

    # heatmap (weekday 0=Monday ... 6=Sunday, UTC hours)
    heat = defaultdict(int)
    for r in db.query(f"SELECT CAST(strftime('%w', created_at) AS INTEGER) wd, CAST(strftime('%H', created_at) AS INTEGER) h, "
                      f"COUNT(*) c FROM scans{w} GROUP BY wd, h", p):
        heat[((r["wd"] + 6) % 7, r["h"])] += r["c"]
    heatmap = [{"weekday": d, "hour": h, "count": heat.get((d, h), 0)} for d in range(7) for h in range(24)]

    # JSON-derived aggregates
    checks_failed: Counter = Counter()
    check_names: dict[str, str] = {}
    ssl_c: Counter = Counter()
    age_c: Counter = Counter()
    for r in db.query(f"SELECT data FROM scans{w} ORDER BY created_at DESC LIMIT {JSON_SCAN_LIMIT}", p):
        d = db.loads(r["data"], {}) or {}
        for c in d.get("checks") or []:
            if isinstance(c, dict) and c.get("status") == "fail":
                cid = c.get("id") or c.get("name")
                checks_failed[cid] += 1
                check_names[cid] = c.get("name") or cid
        ssl = d.get("ssl") or {}
        if not ssl or (ssl.get("enabled") is None and ssl.get("valid") is None):
            ssl_c["Not checked"] += 1
        elif not ssl.get("enabled"):
            ssl_c["No HTTPS"] += 1
        elif ssl.get("self_signed"):
            ssl_c["Self-signed"] += 1
        elif ssl.get("valid"):
            ssl_c["Valid"] += 1
        else:
            ssl_c["Invalid"] += 1
        age = (((d.get("domain_info") or {}).get("whois") or {}).get("age_days"))
        if not isinstance(age, (int, float)):
            age_c["Unknown"] += 1
        elif age < 30:
            age_c["< 30 days"] += 1
        elif age < 180:
            age_c["30-180 days"] += 1
        elif age < 365:
            age_c["6-12 months"] += 1
        elif age < 365 * 5:
            age_c["1-5 years"] += 1
        else:
            age_c["5+ years"] += 1
    age_order = ["< 30 days", "30-180 days", "6-12 months", "1-5 years", "5+ years", "Unknown"]

    # v2: threat types, trust tiers, content categories (column or scan JSON; tier derived from risk if missing)
    threats: Counter = Counter()
    tiers: Counter = Counter()
    categories: Counter = Counter()
    for r in db.query(f"SELECT risk_score, {field('threat_type')} threat_type, {field('tier')} tier, "
                      f"{field('category')} category FROM scans{w}", p):
        threats[r["threat_type"] or "none"] += 1
        tiers[r["tier"] or scoring.tier_for(r["risk_score"])] += 1
        if r["category"]:
            categories[r["category"]] += 1

    return {
        "verdicts": [{"name": v, "value": verdicts.get(v, 0)} for v in ("legitimate", "suspicious", "phishing")],
        "risk_histogram": [{"bucket": f"{i * 10}-{i * 10 + 10}", "count": hist[i]} for i in range(10)],
        "tlds": _top(f"SELECT tld name, COUNT(*) value FROM scans{andw} tld IS NOT NULL AND tld != '' "
                     "GROUP BY tld ORDER BY value DESC", p, 15),
        "countries": countries,
        "brands": _top(f"SELECT brand name, COUNT(*) value FROM scans{andw} brand IS NOT NULL AND brand != '' "
                       "GROUP BY brand ORDER BY value DESC", p, 15),
        "sources": _top(f"SELECT source name, COUNT(*) value FROM scans{w} GROUP BY source ORDER BY value DESC", p, 20),
        "techniques": _top(f"SELECT brand_technique name, COUNT(*) value FROM scans{andw} brand_technique IS NOT NULL "
                           "AND brand_technique != '' GROUP BY brand_technique ORDER BY value DESC", p, 20),
        "checks_failed": [{"id": k, "name": check_names[k], "count": v} for k, v in checks_failed.most_common(15)],
        "top_domains": [{"domain": r["domain"], "count": r["c"], "avg_risk": round(r["avg_risk"] or 0, 1)}
                        for r in db.query(f"SELECT registered_domain domain, COUNT(*) c, AVG(risk_score) avg_risk FROM scans{w} "
                                          "GROUP BY registered_domain ORDER BY c DESC, avg_risk DESC LIMIT 15", p)],
        "heatmap": heatmap,
        "ssl": [{"name": k, "value": v} for k, v in ssl_c.most_common()],
        "domain_age": [{"bucket": b, "count": age_c.get(b, 0)} for b in age_order],
        # ---- v2
        "threat_types": [{"name": t, "value": threats.get(t, 0)} for t in THREAT_ORDER],
        "tiers": [{"name": t, "value": tiers.get(t, 0)} for t in TIER_ORDER],
        "categories": [{"name": k, "value": v} for k, v in categories.most_common(20)],
    }


def _percentile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0
    k = (len(sorted_vals) - 1) * q
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    return round(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f))


def performance(range_: str) -> dict:
    start, _, _, _ = bounds(range_)
    w, p = _where(start)
    vals = [r["duration_ms"] for r in db.query(f"SELECT duration_ms FROM scans{w} ORDER BY duration_ms", p)
            if r["duration_ms"] is not None]
    now = datetime.now(timezone.utc)
    start_dt = db.parse_iso(start) if start else (_first_scan_time() or now)
    if now - start_dt > timedelta(days=90):
        start_dt = now - timedelta(days=90)
    fmt = "%Y-%m-%dT%H:00:00Z"
    tw, tp = _where(db.to_iso(start_dt))
    by = {r["b"]: r["c"] for r in db.query(f"SELECT strftime('{fmt}', created_at) b, COUNT(*) c FROM scans{tw} GROUP BY b", tp)}
    thr = []
    t = _bucket_start(start_dt, "hour")
    end = _bucket_start(now, "hour")
    while t <= end:
        k = t.strftime(fmt)
        thr.append({"t": k, "count": by.get(k, 0)})
        t += timedelta(hours=1)
    seen: Counter = Counter()
    errs: Counter = Counter()
    errors = 0
    for r in db.query(f"SELECT data FROM scans{w} ORDER BY created_at DESC LIMIT {JSON_SCAN_LIMIT}", p):
        d = db.loads(r["data"], {}) or {}
        for c in d.get("checks") or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("id") or c.get("name")
            seen[cid] += 1
            if c.get("status") == "error":
                errs[cid] += 1
                errors += 1
    rates = sorted(({"id": k, "rate": round(errs[k] / seen[k], 3), "errors": errs[k], "total": seen[k]} for k in seen),
                   key=lambda x: -x["rate"])
    return {"range": range_, "count": len(vals), "p50_ms": _percentile(vals, 0.5), "p95_ms": _percentile(vals, 0.95),
            "p99_ms": _percentile(vals, 0.99), "max_ms": max(vals) if vals else 0,
            "avg_ms": round(sum(vals) / len(vals)) if vals else 0,
            "throughput_per_hour": thr, "errors": errors, "check_error_rates": rates}


def model_analytics() -> dict:
    try:
        from ml.predictor import model_info
        info = dict(model_info() or {})
    except Exception as e:
        info = {"error": str(e), "models": [], "feature_importance": [], "feature_stats": [], "dataset": {}}
    best = info.get("best_model")
    r = db.query_one("SELECT COUNT(*) n, AVG(ml_prob) avg_p FROM scans") or {}
    agree = total = 0
    for row in db.query(f"SELECT ml_prob, data FROM scans ORDER BY created_at DESC LIMIT {JSON_SCAN_LIMIT}"):
        d = db.loads(row["data"], {}) or {}
        per = (d.get("ml") or {}).get("per_model") or []
        ref = (row["ml_prob"] or 0) >= 0.5
        for m in per:
            if not isinstance(m, dict) or m.get("name") == best:
                continue
            total += 1
            agree += int(((m.get("probability") or 0) >= 0.5) == ref)
    # feedback accuracy vs decided community reports
    correct = decided = 0
    for rep in db.query("SELECT r.status, r.url, r.domain, r.scan_id FROM reports r WHERE r.status IN ('verified','rejected')"):
        s = None
        if rep["scan_id"]:
            s = db.query_one("SELECT ml_prob FROM scans WHERE id = ?", (rep["scan_id"],))
        if not s:
            s = db.query_one("SELECT ml_prob FROM scans WHERE domain = ? ORDER BY created_at DESC LIMIT 1", (rep["domain"],))
        if not s or s["ml_prob"] is None:
            continue
        decided += 1
        correct += int((s["ml_prob"] >= 0.5) == (rep["status"] == "verified"))
    info["live"] = {
        "predictions": r.get("n") or 0,
        "avg_probability": round(r.get("avg_p") or 0, 4),
        "agreement_rate": round(agree / total, 4) if total else None,
        "feedback_accuracy": round(correct / decided, 4) if decided else None,
        "feedback_samples": decided,
        "verdicts": {row["verdict"]: row["c"] for row in db.query("SELECT verdict, COUNT(*) c FROM scans GROUP BY verdict")},
    }
    return info


# ------------------------------------------------------------------------------------------------ v2
def funnel(range_: str) -> list[dict]:
    """How many scans in the range reached each stage (each stage is counted on its own)."""
    start, _, _, _ = bounds(range_)
    w, p = _where(start)
    r = db.query_one(
        "SELECT COUNT(*) scanned, "
        "SUM(COALESCE(json_extract(data, '$.http.reachable'), 0) = 1) reachable, "
        "SUM(COALESCE(json_extract(data, '$.http.forms.login_form'), 0) = 1 "
        "    OR COALESCE(json_extract(data, '$.http.forms.password_fields'), 0) > 0) login_form, "
        "SUM(COALESCE(brand, '') != '') brand, "
        "SUM(blacklisted = 1 OR EXISTS (SELECT 1 FROM json_each(data, '$.reputation.engines') e "
        "    WHERE json_extract(e.value, '$.listed') = 1 AND json_extract(e.value, '$.type') IN ('feed', 'dnsbl'))) listed, "
        f"SUM(verdict = 'phishing') phishing FROM scans{w}", p) or {}
    keys = ("scanned", "reachable", "login_form", "brand", "listed", "phishing")
    return [{"stage": stage, "count": int(r.get(k) or 0)} for stage, k in zip(FUNNEL_STAGES, keys)]
