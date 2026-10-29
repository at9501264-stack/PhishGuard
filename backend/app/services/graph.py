"""Relationship graph for GET /api/graph (VirusTotal-Graph style), built from the stored scans.

Node ids are "<type>:<value>" (deduplicated); edges are deduplicated by (source, target, type).
  node types: domain, url, ip, asn, ns, registrar, brand, redirect, country
  edge types: resolves_to, in_asn, uses_ns, registered_with, impersonates, redirects_to, located_in, scanned_as
depth 1 = each seed domain with its own infrastructure; depth 2 = plus other scanned domains sharing its
IP / ASN / name server / registrar / brand. No params = global graph of ~50 recent / high-risk domains.
Pivot values come from the scan JSON (or the v2 columns when present), so old and new scans both work.
"""
from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit

from app import db
from app.services.analytics import COUNTRY_NAMES, field

INDEX_LIMIT = 5000          # newest scans used for pivots and counts (demo-sized database)
GLOBAL_DOMAINS = 50
NEIGHBOURS_PER_PIVOT = 8
PIVOT_EDGES = {"ip": "resolves_to", "asn": "in_asn", "ns": "uses_ns", "registrar": "registered_with",
               "brand": "impersonates"}


def _scans(where: str = "", params: tuple = ()) -> list[dict]:
    """Scans (newest first) with their pivot values: ip, asn, as_name, registrar, ns (list), redirects (hosts)."""
    rows = db.query(
        "SELECT id, url, normalized_url, domain, registered_domain, risk_score, verdict, brand, country_code, country, "
        f"{field('ip')} ip, {field('asn')} asn, {field('registrar')} registrar, "
        "json_extract(data, '$.domain_info.geo.as_name') as_name, json_extract(data, '$.domain_info.dns.ns') ns, "
        "json_extract(data, '$.http.final_url') final_url, json_extract(data, '$.http.redirect_chain') chain "
        f"FROM scans {where} ORDER BY created_at DESC, id DESC LIMIT {INDEX_LIMIT}", params)
    for r in rows:
        r["ns"] = sorted({str(n).lower().rstrip(".") for n in (db.loads(r["ns"], []) or []) if n})
        hops = [h.get("url") if isinstance(h, dict) else h for h in (db.loads(r.pop("chain"), []) or [])]
        hosts: list[str] = []
        for u in [*hops, r.pop("final_url")]:
            host = (urlsplit(str(u)).hostname or "").lower() if u else ""
            if host and host != r["domain"] and host not in hosts:
                hosts.append(host)
        r["redirects"] = hosts
    return rows


def _newest_per_domain(rows: list[dict]) -> dict[str, dict]:
    newest: dict[str, dict] = {}
    for r in rows:  # rows are newest first
        newest.setdefault(r["domain"], r)
    return newest


def _pivots(s: dict) -> list[tuple[str, str]]:
    return [(k, s[k]) for k in ("ip", "asn", "registrar", "brand") if s[k]] + [("ns", n) for n in s["ns"]]


def _touches(s: dict) -> set[str]:
    """Node ids a scan contributes to (used for the per-node scan counts)."""
    keys = {f"domain:{s['domain']}", f"url:{s['normalized_url'] or s['url']}"}
    keys |= {f"{k}:{v}" for k, v in _pivots(s)}
    keys |= {f"redirect:{h}" for h in s["redirects"]}
    if s["country_code"]:
        keys.add(f"country:{s['country_code']}")
    return keys


class _Graph:
    def __init__(self, limit: int):
        self.limit = limit
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}
        self.truncated = False

    def add(self, ntype: str, value, label: str | None = None, risk=None, verdict=None) -> str | None:
        """Add or find a node; None when the value is empty or the node limit is reached.
        Redirect hosts share the domain id space, so a redirect target that was scanned is one node."""
        if value in (None, ""):
            return None
        nid = f"{'domain' if ntype == 'redirect' else ntype}:{value}"
        if nid not in self.nodes:
            if len(self.nodes) >= self.limit:
                self.truncated = True
                return None
            self.nodes[nid] = {"id": nid, "type": ntype, "label": label or str(value), "risk": risk,
                               "verdict": verdict, "count": 0}
        return nid

    def link(self, a: str | None, b: str | None, etype: str) -> None:
        if a and b and a != b:
            self.edges.setdefault((a, b, etype), {"source": a, "target": b, "type": etype})


def _add_infra(g: _Graph, s: dict, max_ns: int | None = None) -> None:
    dom = f"domain:{s['domain']}"
    if dom not in g.nodes:
        return
    ip = g.add("ip", s["ip"])
    g.link(dom, ip, "resolves_to")
    asn_label = f"{s['asn']} {s['as_name']}" if s["asn"] and s["as_name"] else s["asn"]
    g.link(ip or dom, g.add("asn", s["asn"], asn_label), "in_asn")
    cc = s["country_code"]
    g.link(ip or dom, g.add("country", cc, COUNTRY_NAMES.get(cc or "") or s["country"] or cc), "located_in")
    for ns in s["ns"][:max_ns]:
        g.link(dom, g.add("ns", ns), "uses_ns")
    g.link(dom, g.add("registrar", s["registrar"]), "registered_with")
    g.link(dom, g.add("brand", s["brand"]), "impersonates")
    for host in s["redirects"]:
        g.link(dom, g.add("redirect", host), "redirects_to")


def build_graph(domain: str | None = None, scan_id: int | None = None, depth: int = 1,
                limit: int = 150) -> dict | None:
    """Graph dict, or None when scan_id does not exist."""
    index = _scans()
    latest = _newest_per_domain(index)
    global_view, center = False, None
    if scan_id is not None:
        found = _scans("WHERE id = ?", (scan_id,))
        if not found:
            return None
        seeds = found
        latest[seeds[0]["domain"]] = seeds[0]  # show the requested scan's risk on its domain
        url_rows = seeds + [r for r in index if r["domain"] == seeds[0]["domain"] and r["id"] != scan_id][:9]
        center = f"domain:{seeds[0]['domain']}"
    elif domain and domain.strip():
        d = domain.strip().lower()
        d = (urlsplit(d).hostname or d) if "://" in d else d
        rows = [r for r in index if d in (r["domain"], r["registered_domain"])]
        seeds = list(_newest_per_domain(rows).values())[:10]
        url_rows = rows[:25]
        center = f"domain:{d}" if d in latest else (f"domain:{seeds[0]['domain']}" if seeds else None)
    else:
        global_view = True
        recent = list(latest.values())  # newest first
        risky = sorted(recent, key=lambda r: -(r["risk_score"] or 0))
        seeds = list({r["domain"]: r for r in recent[:25] + risky}.values())[:GLOBAL_DOMAINS]
        url_rows = []

    g = _Graph(limit)
    for s in seeds:  # every seed domain first, so the node limit never drops a seed
        g.add("domain", s["domain"])
    for s in seeds:
        _add_infra(g, s, max_ns=2 if global_view else None)
    for r in url_rows:
        u = r["normalized_url"] or r["url"]
        g.link(g.add("domain", r["domain"]), g.add("url", u, u[:100], r["risk_score"], r["verdict"]), "scanned_as")
    if depth >= 2:  # other scanned domains sharing a pivot with a seed
        seed_domains = {s["domain"] for s in seeds}
        others = [r for r in latest.values() if r["domain"] not in seed_domains]
        for s in seeds:
            for ptype, value in _pivots(s):
                pid = f"{ptype}:{value}"
                if pid not in g.nodes:
                    continue
                matches = [r for r in others if (value in r["ns"] if ptype == "ns" else r[ptype] == value)]
                for r in matches[:NEIGHBOURS_PER_PIVOT]:
                    g.link(g.add("domain", r["domain"]), pid, PIVOT_EDGES[ptype])

    counts: Counter = Counter()
    for r in index:
        counts.update(_touches(r))
    for n in g.nodes.values():
        kind, value = n["id"].split(":", 1)
        if kind == "domain":
            scan = latest.get(value)
            n["type"] = "domain" if scan else "redirect"
            if scan:
                n["risk"], n["verdict"] = scan["risk_score"], scan["verdict"]
            n["count"] = counts[n["id"]] if scan else counts[f"redirect:{value}"]
        else:
            n["count"] = counts[n["id"]]

    return {"nodes": list(g.nodes.values()), "edges": list(g.edges.values()), "center": center,
            "truncated": g.truncated}
