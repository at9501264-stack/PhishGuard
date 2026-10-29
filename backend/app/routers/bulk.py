"""Bulk scanning endpoints."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app import db
from app.services import bulk as bulk_service

router = APIRouter(prefix="/api/bulk", tags=["Bulk"])


class BulkRequest(BaseModel):
    urls: list[str] = Field(..., description="Up to 500 URLs", max_length=500)
    name: Optional[str] = None


@router.post("", summary="Create bulk scan job", description="Queues up to 500 URLs; scanned in the background "
             "with concurrency 5 (source=bulk). Poll `GET /api/bulk/{id}` for progress.")
async def create_bulk(req: BulkRequest):
    urls = bulk_service.dedupe(req.urls)
    if not urls:
        raise HTTPException(status_code=422, detail="No URLs provided")
    if len(urls) > bulk_service.MAX_URLS:
        raise HTTPException(status_code=422, detail=f"At most {bulk_service.MAX_URLS} URLs per job")
    return {"job_id": bulk_service.create_job(urls, req.name)}


@router.post("/upload", summary="Upload CSV/TXT for bulk scan",
             description="CSV: uses a column named `url` if present, otherwise the first column. TXT: one URL per line.")
async def upload_bulk(file: UploadFile = File(...), name: Optional[str] = Form(None)):
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 5 MB)")
    urls = bulk_service.parse_upload(content, file.filename)
    if not urls:
        raise HTTPException(status_code=422, detail="No URLs found in file")
    return {"job_id": bulk_service.create_job(urls[:bulk_service.MAX_URLS], name or file.filename),
            "total": min(len(urls), bulk_service.MAX_URLS), "truncated": len(urls) > bulk_service.MAX_URLS}


@router.get("", summary="List bulk jobs")
async def list_jobs():
    return [bulk_service.job_out(r) for r in db.query("SELECT * FROM bulk_jobs ORDER BY id DESC LIMIT 200")]


@router.get("/{job_id}", summary="Bulk job detail + results")
async def get_job(job_id: int):
    j = bulk_service.job_detail(job_id)
    if not j:
        raise HTTPException(status_code=404, detail="Job not found")
    return j
