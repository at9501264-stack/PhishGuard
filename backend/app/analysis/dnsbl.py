"""DNS blocklists (G6/G12): Spamhaus DBL, SURBL, URIBL for domains; Spamhaus ZEN, SpamCop for IPs.

Return-code semantics (from the operators' documentation):

* Spamhaus (DBL/ZEN): ``127.255.255.252`` typo in zone, ``127.255.255.254`` query via a public/open resolver
  (or otherwise unattributable), ``127.255.255.255`` excessive queries, ``127.0.1.255`` IP queried against DBL.
  These are **refusals** -> ``listed: None`` with an error detail, never ``listed: True``.
* URIBL / SURBL: ``127.0.0.1`` means the query was refused (public resolver / quota) -> ``listed: None``.
* Some public resolvers silently answer NXDOMAIN for every Spamhaus query (e.g. Google 8.8.8.8). To avoid reporting
  a false "clean", each zone is verified once per hour against its official test point (dbltest.com,
  127.0.0.2, test.surbl.org, test.uribl.com); when the test point does not come back listed, NXDOMAIN answers from
  that zone are reported as ``listed: None`` ("not verifiable").

Results are cached for 1 hour. Nothing here raises.
"""
from __future__ import annotations

import asyncio
import ipaddress
import threading
import time
from typing import Any

ZONES: dict[str, dict] = {
    "Spamhaus DBL": {"zone": "dbl.spamhaus.org", "target": "domain", "test": "dbltest.com",
                     "homepage": "https://check.spamhaus.org"},
    "SURBL": {"zone": "multi.surbl.org", "target": "domain", "test": "test.surbl.org", "homepage": "https://surbl.org"},
    "URIBL": {"zone": "multi.uribl.com", "target": "domain", "test": "test.uribl.com", "homepage": "https://uribl.com"},
    "Spamhaus ZEN": {"zone": "zen.spamhaus.org", "target": "ip", "test": "127.0.0.2",
                     "homepage": "https://check.spamhaus.org"},
    "SpamCop": {"zone": "bl.spamcop.net", "target": "ip", "test": "127.0.0.2", "homepage": "https://www.spamcop.net"},
}

_DBL_CODES = {
    "127.0.1.2": ("spam", "spam domain", False), "127.0.1.4": ("phishing", "phishing domain", False),
    "127.0.1.5": ("malware", "malware domain", False), "127.0.1.6": ("malware", "botnet C&C domain", False),
    "127.0.1.102": ("spam", "abused legit spam", True), "127.0.1.103": ("suspicious", "abused spammed redirector", True),
    "127.0.1.104": ("phishing", "abused legit phish", True), "127.0.1.105": ("malware", "abused legit malware", True),
    "127.0.1.106": ("malware", "abused legit botnet C&C", True),
}
_SPAMHAUS_REFUSED = {
    "127.255.255.252": "typing error in DNSBL name", "127.255.255.254": "query refused – public/open resolver "
    "(Spamhaus blocks queries from public DNS resolvers; use your own resolver or Spamhaus DQS)",
    "127.255.255.255": "query refused – excessive number of queries", "127.0.1.255": "IP queries prohibited on DBL",
}
_ZEN_CODES = {
    "127.0.0.2": ("spam", "SBL (spam source)"), "127.0.0.3": ("spam", "SBL CSS (snowshoe spam)"),
    "127.0.0.4": ("malware", "XBL (exploited / botnet host)"), "127.0.0.5": ("malware", "XBL"),
    "127.0.0.6": ("malware", "XBL"), "127.0.0.7": ("malware", "XBL"), "127.0.0.9": ("malware", "SBL DROP (hijacked netblock)"),
    "127.0.0.10": ("policy", "PBL (end-user/dynamic range – policy listing)"),
    "127.0.0.11": ("policy", "PBL (end-user/dynamic range – policy listing)"),
}
_SURBL_BITS = [(8, "phishing", "PH (phishing)"), (16, "malware", "MW (malware)"), (128, "malware", "CR (cracked/compromised site)"),
               (64, "spam", "ABUSE (spam/abuse)"), (2, "spam", "legacy SC"), (4, "spam", "legacy WS"), (32, "spam", "legacy AB")]
_URIBL_BITS = [(2, "spam", "black"), (8, "suspicious", "red (new/active in spam)"), (4, "grey", "grey (bulk sender)")]

NAMESERVERS: list[str] | None = None   # override (tests/diagnostics); None = system resolver (/etc/resolv.conf)

_cache: dict[str, tuple[float, Any]] = {}
_lock = threading.Lock()
TTL = 3600.0
HEALTH_TTL_OK = 3600.0
HEALTH_TTL_BAD = 600.0


def _cget(key: str, ttl: float = TTL):
    with _lock:
        v = _cache.get(key)
        if v and time.time() - v[0] < ttl:
            return v[1]
    return None


def _cset(key: str, val):
    with _lock:
        _cache[key] = (time.time(), val)
        if len(_cache) > 8192:
            for k in list(_cache)[:2048]:
                _cache.pop(k, None)


# ------------------------------------------------------------------------------------------- raw query
async def _query(name: str, timeout: float) -> dict:
    """Return {"status": "listed"|"nxdomain"|"error", "codes": [...], "txt": str|None, "error"}."""
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
    res = dns.asyncresolver.Resolver()
    if NAMESERVERS:
        res.nameservers = list(NAMESERVERS)
    res.timeout = min(2.0, timeout)
    res.lifetime = timeout
    try:
        ans = await res.resolve(name, "A", lifetime=timeout)
        codes = sorted({r.to_text() for r in ans})
        txt = None
        try:
            t = await res.resolve(name, "TXT", lifetime=min(1.5, timeout))
            txt = " ".join(b"".join(r.strings).decode("utf-8", "ignore") for r in t)[:300]
        except Exception:
            txt = None
        return {"status": "listed", "codes": codes, "txt": txt, "error": None}
    except dns.resolver.NXDOMAIN:
        return {"status": "nxdomain", "codes": [], "txt": None, "error": None}
    except dns.resolver.NoAnswer:
        return {"status": "nxdomain", "codes": [], "txt": None, "error": None}
    except dns.exception.Timeout:
        return {"status": "error", "codes": [], "txt": None, "error": "DNS query timed out"}
    except dns.resolver.NoNameservers as e:
        return {"status": "error", "codes": [], "txt": None, "error": f"no nameserver answered (SERVFAIL/REFUSED): {e}"[:200]}
    except Exception as e:
        return {"status": "error", "codes": [], "txt": None, "error": f"{type(e).__name__}: {e}"[:200]}


# ------------------------------------------------------------------------------------------- interpretation
def interpret(name: str, codes: list[str]) -> dict:
    """Map A-record answers of zone ``name`` to {"listed","category","detail","abused_legit"}."""
    codes = list(codes or [])
    if not codes:
        return {"listed": False, "category": "clean", "detail": "Not listed", "abused_legit": False}
    if name.startswith("Spamhaus"):
        refused = [c for c in codes if c in _SPAMHAUS_REFUSED or c.startswith("127.255.255.")]
        if refused:
            why = _SPAMHAUS_REFUSED.get(refused[0], "query refused")
            return {"listed": None, "category": "error", "detail": f"Refused ({refused[0]}): {why}", "abused_legit": False,
                    "refused": True}
        if name == "Spamhaus DBL":
            hits = [(_DBL_CODES.get(c) or ("suspicious", f"listed ({c})", False)) for c in codes]
            cat = _worst([h[0] for h in hits])
            abused = all(h[2] for h in hits)
            return {"listed": True, "category": cat, "detail": "DBL: " + ", ".join(sorted({h[1] for h in hits})),
                    "abused_legit": abused}
        hits = [(_ZEN_CODES.get(c) or ("spam", f"listed ({c})")) for c in codes]
        real = [h for h in hits if h[0] != "policy"]
        if not real:
            return {"listed": False, "category": "clean", "detail": "Only in " + hits[0][1] + " – not a reputation hit",
                    "abused_legit": False, "policy_only": True}
        return {"listed": True, "category": _worst([h[0] for h in real]),
                "detail": "ZEN: " + ", ".join(sorted({h[1] for h in hits})), "abused_legit": False}
    if name in ("SURBL", "URIBL"):
        if "127.0.0.1" in codes:
            return {"listed": None, "category": "error", "abused_legit": False, "refused": True,
                    "detail": "Refused (127.0.0.1): query blocked – public resolver or query volume limit"}
        bits = 0
        for c in codes:
            try:
                bits |= int(c.rsplit(".", 1)[1])
            except Exception:
                pass
        table = _SURBL_BITS if name == "SURBL" else _URIBL_BITS
        hits = [(cat, label) for bit, cat, label in table if bits & bit]
        real = [h for h in hits if h[0] != "grey"]
        if not real:
            if hits:
                return {"listed": False, "category": "clean", "detail": "Only on URIBL grey list (bulk sender)",
                        "abused_legit": False}
            return {"listed": True, "category": "suspicious", "detail": f"Listed ({', '.join(codes)})", "abused_legit": False}
        return {"listed": True, "category": _worst([h[0] for h in real]),
                "detail": f"{name}: " + ", ".join(h[1] for h in hits), "abused_legit": False}
    # SpamCop and anything else: any 127.0.0.x answer is a listing
    return {"listed": True, "category": "spam", "detail": f"Listed ({', '.join(codes)})", "abused_legit": False}


_ORDER = ["phishing", "malware", "spam", "suspicious", "clean", "error"]


def _worst(cats: list[str]) -> str:
    for c in _ORDER:
        if c in cats:
            return c
    return "suspicious"


def _qname(name: str, value: str) -> str | None:
    cfg = ZONES[name]
    if cfg["target"] == "domain":
        v = (value or "").strip().lower().rstrip(".")
        return f"{v}.{cfg['zone']}" if v else None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version != 4:
        return None
    return ".".join(reversed(str(ip).split("."))) + "." + cfg["zone"]


# ------------------------------------------------------------------------------------------- health (test points)
async def zone_health(name: str, timeout: float = 3.0) -> dict:
    """Query the zone's official test point. Cached (1h when healthy, 10 min otherwise)."""
    key = f"health:{name}"
    c = _cget(key, HEALTH_TTL_OK)
    if c is not None and (c["ok"] or time.time() - c["checked_at"] < HEALTH_TTL_BAD):
        return c
    q = _qname(name, ZONES[name]["test"])
    r = await _query(q, timeout)
    if r["status"] == "listed":
        it = interpret(name, r["codes"])
        ok = it["listed"] is True
        detail = f"test point {ZONES[name]['test']} -> {', '.join(r['codes'])}" + ("" if ok else f" ({it['detail']})")
    elif r["status"] == "nxdomain":
        ok, detail = False, (f"test point {ZONES[name]['test']} returned NXDOMAIN – this resolver filters or blocks "
                             f"{ZONES[name]['zone']}; 'not listed' answers cannot be trusted")
    else:
        ok, detail = False, f"test point query failed: {r['error']}"
    out = {"zone": ZONES[name]["zone"], "ok": ok, "detail": detail, "codes": r["codes"], "checked_at": time.time()}
    _cset(key, out)
    return out


# ------------------------------------------------------------------------------------------- public API
async def check_one(name: str, value: str, timeout: float = 2.5) -> dict:
    """Engine dict for one zone: {"name","type":"dnsbl","listed","detail","category","zone","query","codes",...}."""
    cfg = ZONES[name]
    base = {"name": name, "type": "dnsbl", "zone": cfg["zone"], "target": cfg["target"], "query": value,
            "listed": None, "category": "error", "detail": "", "codes": [], "abused_legit": False}
    qn = _qname(name, value)
    if not qn:
        base["detail"] = "Not applicable (IPv6 or invalid value)" if cfg["target"] == "ip" else "Not applicable"
        base["not_applicable"] = True
        return base
    key = f"q:{qn}"
    cached = _cget(key)
    if cached is not None:
        return dict(cached)
    health_task = asyncio.ensure_future(zone_health(name, timeout=max(timeout, 2.5)))
    r = await _query(qn, timeout)
    try:
        health = await asyncio.wait_for(health_task, timeout + 1.0)
    except Exception:
        health = {"ok": False, "detail": "test point check timed out"}
    out = dict(base)
    out["codes"] = r["codes"]
    if r["txt"]:
        out["txt"] = r["txt"]
    if r["status"] == "error":
        out.update(listed=None, category="error", detail=f"Lookup failed: {r['error']}")
    else:
        it = interpret(name, r["codes"])
        out.update(listed=it["listed"], category=it["category"], detail=it["detail"],
                   abused_legit=bool(it.get("abused_legit")))
        if it.get("refused"):
            out["refused"] = True
        if it["listed"] is False and not health.get("ok"):
            out.update(listed=None, category="error",
                       detail=f"Not verifiable – {health.get('detail') or 'resolver failed DNSBL test point'}")
    out["resolver_ok"] = bool(health.get("ok"))
    if out["listed"] is not None or out.get("refused"):
        _cset(key, out)
    return out


async def check_domain(domain: str, timeout: float = 2.5) -> list[dict]:
    names = [n for n, c in ZONES.items() if c["target"] == "domain"]
    return list(await asyncio.gather(*[check_one(n, domain, timeout) for n in names]))


async def check_ip(ip: str, timeout: float = 2.5) -> list[dict]:
    names = [n for n, c in ZONES.items() if c["target"] == "ip"]
    return list(await asyncio.gather(*[check_one(n, ip, timeout) for n in names]))


async def check_all(domain: str | None, ip: str | None, timeout: float = 2.5) -> list[dict]:
    """All five zones (domain zones need ``domain``, IP zones need a public IPv4 ``ip``). Never raises."""
    try:
        tasks = []
        if domain:
            tasks.append(check_domain(domain, timeout))
        if ip:
            tasks.append(check_ip(ip, timeout))
        out: list[dict] = []
        for part in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(part, list):
                out.extend(part)
        return out
    except Exception:
        return []


async def resolver_report(timeout: float = 3.0) -> list[dict]:
    """Health of every zone with this machine's resolver (used by tests / diagnostics)."""
    rs = await asyncio.gather(*[zone_health(n, timeout) for n in ZONES], return_exceptions=True)
    out = []
    for n, r in zip(ZONES, rs):
        if isinstance(r, dict):
            out.append({"name": n, **{k: v for k, v in r.items() if k != "checked_at"}})
        else:
            out.append({"name": n, "zone": ZONES[n]["zone"], "ok": False, "detail": str(r)})
    return out
