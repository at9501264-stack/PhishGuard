"""Vercel Python Function entrypoint (file-based /api function).

vercel.json rewrites /api/*, /docs, /redoc and /openapi.json here; the ASGI app still sees the ORIGINAL
request path (e.g. /api/scans), so the FastAPI routes of backend/app/main.py match unchanged.
All cloud-specific setup lives in deploy/cloud_app.py (see docs/DEPLOY_NOTES.md).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from deploy.cloud_app import app  # noqa: E402,F401  (ASGI app picked up by the Vercel Python runtime)
