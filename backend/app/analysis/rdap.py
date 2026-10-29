"""RDAP fallback for WHOIS (used when the system ``whois`` binary is missing or fails, e.g. on Vercel).

``https://rdap.org/domain/{d}`` redirects to the authoritative RDAP server. It is a third-party lookup service
(not the scanned site), so it does not go through ``net_safety``. Results are cached for 12 h. Never raises.
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone

import httpx

UA = "PhishGuard RDAP lookup (academic project)"
CACHE_TTL = 12 * 3600
PRIVACY_WORDS = ("redacted", "privacy", "proxy", "withheld", "not disclosed", "data protected")
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


def _parse_date(s) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _vcard_name(entity: dict) -> str | None:
    """'fn' (or 'org') value of an RDAP entity's vcardArray."""
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org") and item[3]:
                v = item[3]
                return (v if isinstance(v, str) else " ".join(map(str, v))).strip() or None
    except Exception:
        pass
    return None


def _walk(entities):
    for e in entities or []:
        if isinstance(e, dict):
            yield e, [str(r).lower() for r in (e.get("roles") or [])]
            yield from _walk(e.get("entities"))


def parse(j: dict) -> dict:
    """RDAP domain JSON -> the WHOIS-shaped dict used by ``domain_info.whois``."""
    events = {}
    for ev in j.get("events") or []:
        if ev.get("eventAction") and ev.get("eventDate"):
            events.setdefault(str(ev["eventAction"]).lower(), ev["eventDate"])
    created = _parse_date(events.get("registration"))
    expiry = _parse_date(events.get("expiration"))
    updated = _parse_date(events.get("last changed") or events.get("last update of rdap database"))
    registrar, country, registrant_blob = None, None, ""
    for e, roles in _walk(j.get("entities")):
        if "registrar" in roles and not registrar:
            registrar = _vcard_name(e) or e.get("handle")
        if "registrant" in roles:
            registrant_blob += json.dumps(e).lower()
            for item in (e.get("vcardArray") or [None, []])[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "adr":
                    cc = (item[1] or {}).get("cc") if isinstance(item[1], dict) else None
                    country = country or (str(cc).upper()[:3] if cc else None)
    blob = registrant_blob or json.dumps(j.get("remarks") or []).lower()
    now = datetime.now(timezone.utc)
    ns = sorted({str(n.get("ldhName") or "").lower().rstrip(".") for n in (j.get("nameservers") or [])
                 if isinstance(n, dict) and n.get("ldhName")})[:8]
    return {
        "registrar": str(registrar) if registrar else None,
        "creation_date": created.isoformat() if created else None,
        "expiry_date": expiry.isoformat() if expiry else None,
        "updated_date": updated.isoformat() if updated else None,
        "age_days": (now - created).days if created else None,
        "days_to_expiry": (expiry - now).days if expiry else None,
        "registration_length_days": (expiry - created).days if (expiry and created) else None,
        "privacy_protected": any(w in blob for w in PRIVACY_WORDS),
        "country": country,
        "name_servers": ns,
        "org": None,
        "status": [str(s) for s in (j.get("status") or [])][:10],
        "found": bool(registrar or created),
        "source": "rdap",
    }


async def lookup_domain(domain: str, timeout: float = 5.0) -> dict:
    """WHOIS-shaped dict from RDAP, with ``source: "rdap"``; on failure ``{"error": ..., "source": "rdap"}``."""
    if not domain:
        return {"error": "no domain", "source": "rdap"}
    with _lock:
        c = _cache.get(domain)
    if c and time.time() - c[0] < CACHE_TTL:
        return dict(c[1])
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=min(4.0, timeout)), follow_redirects=True,
                                     headers={"User-Agent": UA, "Accept": "application/rdap+json, application/json"}) as cl:
            r = await cl.get(f"https://rdap.org/domain/{domain}")
        if r.status_code == 404:
            return {"error": "Not found in RDAP (unsupported TLD or unregistered)", "source": "rdap"}
        if r.status_code != 200:
            return {"error": f"RDAP HTTP {r.status_code}", "source": "rdap"}
        out = parse(r.json())
    except httpx.TimeoutException:
        return {"error": "RDAP timed out", "source": "rdap"}
    except Exception as e:
        return {"error": f"RDAP error: {type(e).__name__}: {e}"[:200], "source": "rdap"}
    with _lock:
        _cache[domain] = (time.time(), out)
        if len(_cache) > 4096:
            for k in list(_cache)[:1024]:
                _cache.pop(k, None)
    return dict(out)
