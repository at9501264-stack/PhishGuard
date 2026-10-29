"""Risk scoring: combines the ML probability, heuristic engine score, blacklists and community data.

v1: ``risk = round(0.6 * ml_prob * 100 + 0.4 * heuristic)``; blacklist hit -> >= 90; verified community report -> >= 85.

v2 (``finalize``): popular/official-domain cap (never applied when any engine/feed lists the URL), trust score,
reputation tier (honours custom thresholds), threat type, positive/negative factors, the "PhishGuard ML" engine
appended to the multi-engine list (engine_ratio recomputed) and a plain-English summary.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

ML_WEIGHT = 0.6
HEURISTIC_WEIGHT = 0.4
BLACKLIST_FLOOR = 90
COMMUNITY_FLOOR = 85
POPULAR_CAP = 30
TRUSTED_MAX = 15

TIERS = ("Trusted", "Favorable", "Neutral", "Questionable", "Untrusted")
THREAT_TYPES = ("malware", "social_engineering", "unwanted_software", "none")
VERDICT_RANK = {"legitimate": 0, "suspicious": 1, "phishing": 2}
ML_ENGINE = "PhishGuard ML"
POPULAR_TIERS = {"top1k", "top10k"}
API_ENGINES = {"googlesafebrowsing", "virustotal"}
EXEC_EXT = (".exe", ".apk", ".scr", ".bat", ".cmd", ".msi", ".jar", ".vbs", ".ps1", ".dll", ".hta", ".zip", ".rar",
            ".7z", ".iso", ".dmg")
SPAM_ENGINE_HINTS = ("spamhaus", "surbl", "uribl", "spamcop", "dbl", "zen")

# hosting / UGC / shortener platforms: a popular registered domain does not vouch for content hosted on them
_PLATFORM_FALLBACK = {
    "000webhostapp.com", "weebly.com", "weeblysite.com", "wixsite.com", "blogspot.com", "firebaseapp.com", "web.app",
    "glitch.me", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "r2.dev", "github.io", "gitlab.io",
    "herokuapp.com", "repl.co", "replit.app", "duckdns.org", "ngrok.io", "ngrok-free.app", "appspot.com", "webflow.io",
    "wordpress.com", "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "script.google.com", "googleusercontent.com", "raw.githubusercontent.com",
    "gist.github.com", "dl.dropboxusercontent.com", "dropboxusercontent.com", "forms.office.com", "1drv.ms",
    "onedrive.live.com", "sharepoint.com", "s3.amazonaws.com", "amazonaws.com", "cloudfront.net", "azureedge.net",
    "azurewebsites.net", "blob.core.windows.net", "web.core.windows.net", "akamaihd.net", "translate.goog",
    "notion.site", "my.canva.site", "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "trycloudflare.com",
    "bit.ly", "bitly.com", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "linktr.ee", "rb.gy", "t.ly", "tiny.cc", "s.id", "lnkd.in", "qrco.de", "shorturl.at",
}
_platforms_cache: set[str] | None = None


# ----------------------------------------------------------------------------------------------- v1
def verdict_for(risk: float, suspicious_threshold: float = 35, phishing_threshold: float = 65) -> str:
    if risk >= phishing_threshold:
        return "phishing"
    if risk >= suspicious_threshold:
        return "suspicious"
    return "legitimate"


def confidence_for(risk: float, suspicious_threshold: float = 35, phishing_threshold: float = 65) -> float:
    """Distance from the nearest threshold, normalised by the width of the verdict band (0-1)."""
    s, p = float(suspicious_threshold), float(phishing_threshold)
    if risk >= p:
        span = max(100.0 - p, 1.0)
        d = risk - p
    elif risk >= s:
        span = max((p - s) / 2.0, 1.0)
        d = min(risk - s, p - risk)
    else:
        span = max(s, 1.0)
        d = s - risk
    return round(max(0.0, min(1.0, d / span)), 3)


def compute_score(ml_probability: float, heuristic_score: float, blacklisted: bool = False,
                  community_verified: bool = False, suspicious_threshold: float = 35,
                  phishing_threshold: float = 65) -> dict:
    ml_probability = max(0.0, min(1.0, float(ml_probability or 0.0)))
    heuristic_score = max(0.0, min(100.0, float(heuristic_score or 0.0)))
    ml_part = ML_WEIGHT * ml_probability * 100
    heur_part = HEURISTIC_WEIGHT * heuristic_score
    risk = round(ml_part + heur_part)
    base = risk
    if blacklisted:
        risk = max(risk, BLACKLIST_FLOOR)
    if community_verified:
        risk = max(risk, COMMUNITY_FLOOR)
    risk = int(max(0, min(100, risk)))
    verdict = verdict_for(risk, suspicious_threshold, phishing_threshold)
    confidence = confidence_for(risk, suspicious_threshold, phishing_threshold)
    if blacklisted or community_verified:
        confidence = max(confidence, 0.9)

    breakdown = [
        {"component": "ML model", "score": round(ml_probability * 100, 1), "weight": ML_WEIGHT,
         "contribution": round(ml_part, 1)},
        {"component": "Heuristic checks", "score": round(heuristic_score, 1), "weight": HEURISTIC_WEIGHT,
         "contribution": round(heur_part, 1)},
        {"component": "Blacklists", "score": 100 if blacklisted else 0, "weight": 0,
         "contribution": float(max(0, BLACKLIST_FLOOR - base)) if blacklisted else 0.0,
         "note": f"Blacklist hit raises risk to at least {BLACKLIST_FLOOR}"},
        {"component": "Community", "score": 100 if community_verified else 0, "weight": 0,
         "contribution": float(max(0, COMMUNITY_FLOOR - max(base, BLACKLIST_FLOOR if blacklisted else 0)))
         if community_verified else 0.0,
         "note": f"Verified community report raises risk to at least {COMMUNITY_FLOOR}"},
    ]
    return {"risk_score": risk, "verdict": verdict, "confidence": confidence, "score_breakdown": breakdown}


# ----------------------------------------------------------------------------------------------- v2 basics
def trust_score_for(risk: float | None) -> int:
    return int(max(0, min(100, 100 - int(round(float(risk or 0))))))


def tier_for(risk: float | None, suspicious_threshold: float = 35, phishing_threshold: float = 65) -> str:
    """Trusted [0,15) . Favorable [15,S) . Neutral [S,(S+P)/2) . Questionable [(S+P)/2,P) . Untrusted [P,100]."""
    r = float(risk or 0)
    s, p = float(suspicious_threshold), float(phishing_threshold)
    if r >= p:
        return "Untrusted"
    if r >= (s + p) / 2:
        return "Questionable"
    if r >= s:
        return "Neutral"
    if r >= TRUSTED_MAX:
        return "Favorable"
    return "Trusted"


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def _status(by: dict, cid: str) -> str | None:
    c = by.get(cid)
    return c.get("status") if isinstance(c, dict) else None


def _bad(by: dict, cid: str, verdict: str) -> bool:
    """fail always counts; warn counts only when the overall verdict is not legitimate."""
    st = _status(by, cid)
    return st == "fail" or (st == "warn" and verdict != "legitimate")


# ----------------------------------------------------------------------------------------------- engines
def engine_category(name: str, listed: bool | None, error: bool = False) -> str:
    if error or listed is None:
        return "error"
    if not listed:
        return "clean"
    n = _norm(name)
    if "urlhaus" in n:
        return "malware"
    if any(h in n for h in SPAM_ENGINE_HINTS) or "spam" in n:
        return "spam"
    return "phishing"


def build_engines(reputation: dict, sources: list | None = None) -> list[dict]:
    """Engine list = engine-provided `reputation.engines` (if any) merged with every reputation source
    (local feeds, GSB/VT, API-side feed hits). The "PhishGuard ML" entry is (re)added by finalize()."""
    engines: list[dict] = []
    seen: dict[str, dict] = {}
    raw = (reputation or {}).get("engines")
    if isinstance(raw, list):
        for e in raw:
            if not isinstance(e, dict) or not e.get("name") or e.get("name") == ML_ENGINE:
                continue
            e = dict(e)
            listed = e.get("listed")
            e["listed"] = None if listed is None else bool(listed)
            e.setdefault("type", "feed")
            e.setdefault("detail", "")
            if not e.get("category"):
                e["category"] = engine_category(e["name"], e["listed"])
            engines.append(e)
            seen[_norm(e["name"])] = e
    for s in sources if sources is not None else ((reputation or {}).get("sources") or []):
        if not isinstance(s, dict) or not s.get("name"):
            continue
        name = str(s["name"])
        err = bool(s.get("error"))
        listed = None if err else bool(s.get("listed"))
        e = seen.get(_norm(name))
        if e is None:
            e = {"name": name, "type": "api" if _norm(name) in API_ENGINES else "feed", "listed": listed,
                 "detail": s.get("detail") or ("Listed" if listed else "Not listed"),
                 "category": engine_category(name, listed, err)}
            engines.append(e)
            seen[_norm(name)] = e
        elif listed and e.get("listed") is not True:
            e["listed"] = True
            e["detail"] = s.get("detail") or e.get("detail") or "Listed"
            if e.get("category") in (None, "", "clean", "error"):
                e["category"] = engine_category(name, True)
    return engines


def engine_ratio(engines: list[dict], include_heuristic: bool = True) -> dict:
    use = [e for e in engines if include_heuristic or e.get("type") != "heuristic"]
    return {"flagged": sum(1 for e in use if e.get("listed") is True),
            "total": sum(1 for e in use if e.get("listed") is not None)}


def ml_engine(verdict: str, risk: int, ml_prob: float) -> dict:
    listed = verdict == "phishing"
    return {"name": ML_ENGINE, "type": "heuristic", "listed": listed,
            "detail": f"Risk {risk}/100 ({verdict}); ML phishing probability {round(ml_prob * 100)}%",
            "category": "phishing" if listed else ("suspicious" if verdict == "suspicious" else "clean")}


def _external_listed(engines: list[dict]) -> list[dict]:
    return [e for e in engines if e.get("listed") is True and e.get("type") != "heuristic"
            and e.get("name") != ML_ENGINE]


# ----------------------------------------------------------------------------------------------- platform test
def _platforms() -> set[str]:
    global _platforms_cache
    if _platforms_cache is None:
        s = set(_PLATFORM_FALLBACK)
        try:  # reuse the engine's lists when available (never fatal)
            from app.analysis import engine as eng
            for attr in ("FREE_HOSTING", "UGC_HOSTS", "SHORTENERS"):
                s |= {str(x).lower() for x in (getattr(eng, attr, None) or ())}
        except Exception:
            pass
        _platforms_cache = s
    return _platforms_cache


def is_platform_host(host: str) -> bool:
    host = (host or "").lower().strip(".")
    return any(host == p or host.endswith("." + p) for p in _platforms())


# ----------------------------------------------------------------------------------------------- evidence
def malware_evidence(result: dict, by: dict, engines: list[dict]) -> list[str]:
    verdict = result.get("verdict") or "legitimate"
    ev: list[str] = []
    for e in _external_listed(engines):
        if e.get("category") == "malware" or "urlhaus" in _norm(e.get("name")):
            ev.append(f"Listed as malware by {e['name']}")
    path = urlsplit(str(result.get("normalized_url") or result.get("url") or "")).path.lower()
    if verdict != "legitimate" and path.endswith(EXEC_EXT):
        ev.append("URL points to an executable/archive file")
    return list(dict.fromkeys(ev))


def social_evidence(result: dict, by: dict, engines: list[dict]) -> list[str]:
    verdict = result.get("verdict") or "legitimate"
    ev: list[str] = []
    for e in _external_listed(engines):
        if e.get("category") not in ("malware", "spam"):
            ev.append(f"Listed as phishing by {e['name']}")
    brand = result.get("brand") or {}
    b = brand.get("impersonated_brand")
    if b and not brand.get("defensive_redirect") and _bad(by, "brand_impersonation", verdict):
        ev.append(f"Impersonates {b}")
    forms = (result.get("http") or {}).get("forms") or {}
    if verdict != "legitimate" and isinstance(forms, dict) and (
            forms.get("login_form") or (forms.get("password_fields") or 0) > 0):
        ev.append("Login/password form on a suspicious site")
    if verdict == "phishing":
        ev.append("Phishing verdict")
    return list(dict.fromkeys(ev))


def unwanted_evidence(result: dict, by: dict, engines: list[dict]) -> list[str]:
    verdict = result.get("verdict") or "legitimate"
    ev: list[str] = []
    content = result.get("content") or {}
    parked = content.get("parked") if isinstance(content, dict) else None
    if (isinstance(parked, dict) and parked.get("parked")) or _status(by, "parked_domain") in ("fail", "warn"):
        ev.append("Parked domain")
    for cid, label in (("seo_spam", "SEO spam"), ("hidden_iframe", "Hidden iframe")):
        if _bad(by, cid, verdict):
            ev.append(label)
    if verdict != "legitimate":
        for e in _external_listed(engines):
            if e.get("category") == "spam":
                ev.append(f"Listed on spam blocklist {e['name']}")
    return list(dict.fromkeys(ev))


def threat_type_for(result: dict, by: dict, engines: list[dict], capped: bool = False) -> tuple[str, list[str]]:
    """malware > social_engineering > unwanted_software > none."""
    mal = malware_evidence(result, by, engines)
    if mal:
        return "malware", mal
    if capped:
        return "none", []
    soc = social_evidence(result, by, engines)
    if soc:
        return "social_engineering", soc
    unw = unwanted_evidence(result, by, engines)
    if unw:
        return "unwanted_software", unw
    return "none", []


def cap_reason(result: dict, by: dict, engines: list[dict], community_verified: bool = False) -> str | None:
    """Popular (Tranco top-10k) or official brand domain with no blocklist/feed hit -> risk cap reason."""
    rep = result.get("reputation") or {}
    if rep.get("blacklisted") or community_verified or _external_listed(engines):
        return None
    if malware_evidence(result, by, engines):
        return None
    host = (result.get("domain") or "").lower()
    platform = is_platform_host(host)
    brand = result.get("brand") or {}
    if brand.get("official_domain") and not platform and _status(by, "brand_official") != "warn":
        m = re.search(r"official domain of (.+)$", str(brand.get("details") or ""))
        return f"Official {m.group(1).strip()} domain" if m else "Official brand domain"
    pop = result.get("popularity") or {}
    if not isinstance(pop, dict):
        pop = {}
    rank = pop.get("rank")
    popular = pop.get("tier") in POPULAR_TIERS or (isinstance(rank, int) and 0 < rank <= 10000) \
        or _status(by, "popular_site") == "pass"
    if popular and not platform and _status(by, "brand_impersonation") != "fail":
        return f"Popular site (Tranco rank #{rank})" if isinstance(rank, int) else "Popular site (Tranco top 10k)"
    return None


# ----------------------------------------------------------------------------------------------- factors/summary
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}
_STRONG_POSITIVE = {"brand_official", "popular_site", "engine_ratio", "ssl_valid", "domain_age", "blacklists"}


def _severity(c: dict) -> str:
    try:
        w = float(c.get("weight") or 0)
    except (TypeError, ValueError):
        w = 0.0
    if c.get("status") == "fail":
        return "high" if w >= 6 else "medium" if w >= 3 else "low"
    return "medium" if w >= 7 else "low"


def factors_for(checks: list, ml_prob: float | None = None, ext_ratio: dict | None = None,
                cap: str | None = None) -> dict:
    pos: list[dict] = []
    neg: list[dict] = []
    for c in checks or []:
        if not isinstance(c, dict):
            continue
        st = c.get("status")
        cid = c.get("id") or c.get("name")
        try:
            w = float(c.get("weight") or 0)
        except (TypeError, ValueError):
            w = 0.0
        item = {"id": cid, "name": c.get("name") or cid, "detail": c.get("detail") or "",
                "category": c.get("category"), "weight": w}
        if st in ("fail", "warn"):
            neg.append({**item, "severity": _severity(c)})
        elif st == "pass" and (w > 0 or cid in _STRONG_POSITIVE):
            pos.append(item)
    if ml_prob is not None:
        pct = round(float(ml_prob) * 100)
        if ml_prob < 0.3:
            pos.append({"id": "ml_probability", "name": "ML model: low phishing probability",
                        "detail": f"{pct}% phishing probability from the URL model", "category": "ml", "weight": 6.0})
        elif ml_prob >= 0.5:
            neg.append({"id": "ml_probability", "name": "ML model: high phishing probability",
                        "detail": f"{pct}% phishing probability from the URL model", "category": "ml",
                        "weight": 8.0 if ml_prob >= 0.85 else 6.0 if ml_prob >= 0.7 else 3.0,
                        "severity": "high" if ml_prob >= 0.85 else "medium" if ml_prob >= 0.7 else "low"})
    ids = {f["id"] for f in pos + neg}
    if ext_ratio and ext_ratio.get("total") and "engine_ratio" not in ids:
        fl, tot = ext_ratio.get("flagged", 0), ext_ratio["total"]
        if fl == 0:
            pos.append({"id": "engine_ratio", "name": "Not listed by any reputation engine",
                        "detail": f"0/{tot} external engines flagged this URL", "category": "reputation", "weight": 5.0})
        else:
            neg.append({"id": "engine_ratio", "name": "Flagged by reputation engines",
                        "detail": f"{fl}/{tot} external engines flagged this URL", "category": "reputation", "weight": 10.0,
                        "severity": "high"})
    if cap:
        pos.insert(0, {"id": "popular_or_official", "name": "Popular or official domain", "detail": cap,
                       "category": "reputation", "weight": 10.0})
    neg.sort(key=lambda f: (_SEV_ORDER.get(f.get("severity"), 3), -(f.get("weight") or 0)))
    pos.sort(key=lambda f: -(f.get("weight") or 0))
    return {"positive": pos[:15], "negative": neg[:20]}


def derive_points(factors: dict, verdict: str) -> list[str]:
    def txt(f: dict) -> str:
        d = (f.get("detail") or "").strip().rstrip(".")
        return f"{f['name']}: {d}" if d and d.lower() != str(f["name"]).lower() else str(f["name"])
    neg = [f for f in factors.get("negative") or [] if f.get("severity") in ("high", "medium")] \
        or (factors.get("negative") or [])
    pts = [txt(f) for f in neg[:5]]
    if verdict == "legitimate" and not [f for f in neg if f.get("severity") == "high"]:
        pts = [txt(f) for f in (factors.get("positive") or [])[:4]] + pts[:1]
    return pts


VERDICT_TEXT = {"phishing": "phishing", "suspicious": "suspicious", "legitimate": "legitimate"}
THREAT_TEXT = {"malware": "malware distribution", "social_engineering": "social engineering (phishing)",
               "unwanted_software": "unwanted or deceptive content"}


def build_summary(result: dict) -> str:
    v = result.get("verdict") or "legitimate"
    risk = result.get("risk_score") or 0
    name = result.get("domain") or "This URL"
    s1 = (f"PhishGuard rates {name} as {VERDICT_TEXT.get(v, v)} with a risk score of {risk}/100 "
          f"(trust score {result.get('trust_score', trust_score_for(risk))}/100, tier {result.get('tier') or '-'}).")
    ml = result.get("ml") or {}
    p = ml.get("probability_phishing")
    engines = (result.get("reputation") or {}).get("engines") or []
    # Same ratio as the "N/M engines flagged" badge (includes the PhishGuard ML engine).
    ratio = result.get("reputation", {}).get("engine_ratio") or engine_ratio(engines)
    s2 = (f"The machine-learning model estimates a {round(float(p) * 100)}% phishing probability"
          if isinstance(p, (int, float)) else "The machine-learning model was unavailable")
    if ratio.get("total"):
        s2 += f", and {ratio['flagged']} of {ratio['total']} detection engines (including PhishGuard ML) flagged it"
    s2 += "."
    factors = result.get("factors") or {}
    if v == "legitimate":
        # Pass-check names read like warnings ("Brand impersonation"), so prefer their detail text.
        good = [(f.get("detail") or f["name"]).strip().rstrip(".") for f in (factors.get("positive") or [])[:3]]
        s3 = ("Positive signals: " + "; ".join(good) + ".") if good else None
    else:
        pts = [str(x).strip().rstrip(".") for x in (result.get("summary_points") or []) if str(x).strip()][:3]
        s3 = ("Key findings: " + "; ".join(pts) + ".") if pts else None
    s4 = None
    if result.get("tested_depth") == "lexical":
        s4 = "Only URL-based (lexical) checks and the ML model were run, so the live site is untested."
    elif result.get("threat_type") in THREAT_TEXT:
        s4 = f"Threat type: {THREAT_TEXT[result['threat_type']]}."
    return " ".join(x for x in (s1, s2, s3, s4) if x)


# ----------------------------------------------------------------------------------------------- finalize
def finalize(result: dict, settings: dict | None = None, community_verified: bool = False,
             apply_cap: bool = True) -> dict:
    """Apply all v2 scoring additions to an assembled ScanResult dict (in place) and return it."""
    settings = settings or {}
    s = float(settings.get("suspicious_threshold", 35))
    p = float(settings.get("phishing_threshold", 65))
    checks = [c for c in (result.get("checks") or []) if isinstance(c, dict)]
    by = {c.get("id"): c for c in checks}
    rep = result.setdefault("reputation", {})
    if not isinstance(rep, dict):
        rep = result["reputation"] = {}
    engines = build_engines(rep)

    cap = cap_reason(result, by, engines, community_verified) if apply_cap else None
    capped = False
    risk = int(result.get("risk_score") or 0)
    if cap and risk > POPULAR_CAP:
        capped = True
        result["risk_score"] = POPULAR_CAP
        result["verdict"] = verdict_for(POPULAR_CAP, s, p)
        result.setdefault("score_breakdown", []).append(
            {"component": "Popularity / official domain", "score": 0, "weight": 0,
             "contribution": -float(risk - POPULAR_CAP),
             "note": f"{cap} with no blocklist hit: risk capped at {POPULAR_CAP}"})
    if cap and result.get("verdict") == "legitimate":
        result["confidence"] = max(float(result.get("confidence") or 0),
                                   confidence_for(result["risk_score"], s, p), 0.8)
    elif capped:
        result["confidence"] = confidence_for(result["risk_score"], s, p)
    result["score_cap"] = {"applied": capped, "reason": cap, "cap": POPULAR_CAP}

    verdict = result.get("verdict") or "legitimate"
    risk = int(result.get("risk_score") or 0)
    ml_prob = float((result.get("ml") or {}).get("probability_phishing") or 0.0)
    engines = [e for e in engines if e.get("name") != ML_ENGINE] + [ml_engine(verdict, risk, ml_prob)]
    rep["engines"] = engines
    rep["engine_ratio"] = engine_ratio(engines)

    result["trust_score"] = trust_score_for(risk)
    result["tier"] = tier_for(risk, s, p)
    result.setdefault("tested_depth", "full")
    tt, reasons = threat_type_for(result, by, engines, capped=bool(cap))
    result["threat_type"] = tt
    result["threat_reasons"] = reasons
    result["factors"] = factors_for(checks, ml_prob, engine_ratio(engines, include_heuristic=False), cap)
    pts = [x for x in (result.get("summary_points") or []) if isinstance(x, str) and x.strip()]
    if not pts:
        pts = derive_points(result["factors"], verdict)
    result["summary_points"] = pts
    result["summary"] = build_summary(result)
    return result
