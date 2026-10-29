"""Community reports & votes."""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app import db
from app.services import community
from app.services.scanner import InvalidURL

router = APIRouter(prefix="/api/reports", tags=["Community"])


class ReportRequest(BaseModel):
    url: str
    label: Literal["phishing", "legitimate"]
    brand: Optional[str] = None
    comment: Optional[str] = None
    reporter: Optional[str] = None


class VoteRequest(BaseModel):
    vote: Literal["phishing", "legitimate"]
    voter: Optional[str] = None


@router.post("", summary="Submit a community report",
             description="Creates a report (the reporter's label counts as the first vote) and triggers a background "
                         "scan; `scan_id` is filled in once the scan finishes.")
async def create_report(req: ReportRequest):
    try:
        return community.create_report(req.url, req.label, req.brand, req.comment, req.reporter)
    except InvalidURL as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("", summary="List community reports")
async def list_reports(status: Optional[Literal["pending", "verified", "rejected"]] = None, q: Optional[str] = None,
                       page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)):
    c, p = [], []
    if status:
        c.append("status = ?")
        p.append(status)
    if q:
        c.append("(url LIKE ? OR domain LIKE ? OR brand LIKE ?)")
        p += [f"%{q}%"] * 3
    w = (" WHERE " + " AND ".join(c)) if c else ""
    total = db.scalar(f"SELECT COUNT(*) FROM reports{w}", p, 0)
    rows = db.query(f"SELECT * FROM reports{w} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                    [*p, page_size, (page - 1) * page_size])
    return {"items": [community.report_out(r) for r in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/{report_id}", summary="Get a report")
async def get_report(report_id: int):
    r = community.get_report(report_id)
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return r


@router.post("/{report_id}/vote", summary="Vote on a report",
             description="Verified when phishing_votes - legitimate_votes >= 3, rejected when <= -3. "
                         "A named voter can change their vote; anonymous votes always add.")
async def vote(report_id: int, req: VoteRequest):
    r = community.vote(report_id, req.vote, req.voter)
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return r
