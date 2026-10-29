"""Relationship graph, similar scans and detection funnel (v2)."""
from __future__ import annotations

import asyncio
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query

from app.services import analytics, graph, similar as similar_service

router = APIRouter(prefix="/api", tags=["insights"])

RangeT = Literal["24h", "7d", "30d", "90d", "all"]


@router.get("/graph", summary="Relationship graph",
            description="Domain/URL/IP/ASN/NS/registrar/brand/redirect/country graph. `scan_id` or `domain` centres it; "
                        "no params = global graph of ~50 recent/high-risk domains. depth 2 adds domains sharing a pivot.")
async def get_graph(domain: Optional[str] = None, scan_id: Optional[int] = None,
                    depth: int = Query(1, ge=1, le=2), limit: int = Query(150, ge=10, le=500)):
    out = await asyncio.to_thread(graph.build_graph, domain, scan_id, depth, limit)
    if out is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return out


@router.get("/scans/{scan_id}/similar", summary="Similar scans",
            description="Newest scan of other domains sharing this scan's IP, ASN or registrar (<= 20 per list).")
async def get_similar(scan_id: int):
    out = await asyncio.to_thread(similar_service.similar, scan_id)
    if out is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return out


@router.get("/analytics/funnel", summary="Detection funnel",
            description="Scans reaching each stage: Scanned, Reachable, Login/password form, Brand impersonation, "
                        "Feed listed, Phishing verdict.")
async def get_funnel(range: RangeT = "30d"):
    return await asyncio.to_thread(analytics.funnel, range)
