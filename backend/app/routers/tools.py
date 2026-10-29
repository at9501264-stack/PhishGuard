"""Utility endpoints: URL extraction from text, typosquat generation."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.services.events import log_event
from app.services.scanner import InvalidURL, normalize_url, split_host

router = APIRouter(prefix="/api", tags=["Tools"])


class ExtractRequest(BaseModel):
    text: str


@router.post("/extract", summary="Extract URLs from email/SMS text",
             description="Finds URLs in free text, including defanged forms like hxxp:// and example[.]com.")
async def extract(req: ExtractRequest):
    try:
        from app.analysis.text_extract import extract_urls
        urls = extract_urls(req.text or "")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"extraction failed: {e}")
    seen, out = set(), []
    for u in urls or []:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return {"urls": out}


@router.get("/typosquat", summary="Typosquat / lookalike domain finder",
            description="Generates dnstwist-style permutations of a domain and checks which ones resolve.")
async def typosquat(domain: str = Query(..., min_length=3), limit: int = Query(60, ge=1, le=300)):
    from app.analysis import typosquat as ts
    try:
        _, _, host = normalize_url(domain.strip())
    except InvalidURL as e:
        raise HTTPException(status_code=422, detail=str(e))
    reg = split_host(host)["registered_domain"]
    try:
        generated = ts.generate_permutations(reg) or []
    except Exception:
        generated = []
    try:
        results = await ts.check_permutations(reg, limit) or []
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"typosquat check failed: {e}")
    results = [{"domain": r.get("domain"), "technique": r.get("technique"), "resolves": bool(r.get("resolves")),
                "ip": r.get("ip"), **{k: v for k, v in r.items() if k not in ("domain", "technique", "resolves", "ip")}}
               for r in results]
    log_event("typosquat", f"Typosquat scan for {reg}: {sum(r['resolves'] for r in results)} resolving",
              {"domain": reg, "generated": len(generated), "checked": len(results)},
              entity_type="domain", entity_id=reg, domain=reg)
    return {"domain": reg, "total_generated": len(generated), "results": results}
