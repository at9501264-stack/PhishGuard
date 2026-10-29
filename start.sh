#!/usr/bin/env bash
# Start PhishGuard locally: FastAPI backend on :8000 and the React dashboard on :5173.
# First run installs everything (Python venv + npm packages). Ctrl+C stops both.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x backend/.venv/bin/uvicorn ]; then
  echo "Setting up the Python environment (first run only)..."
  if command -v uv >/dev/null 2>&1; then
    uv venv backend/.venv --python 3.12
    uv pip install --python backend/.venv/bin/python -r backend/requirements.txt
  else
    python3 -m venv backend/.venv
    backend/.venv/bin/pip install -r backend/requirements.txt
  fi
fi

if [ ! -f backend/ml/artifacts/metrics.json ]; then
  echo "No trained model found - training it now (needs the dataset, see README)..."
  (cd backend && .venv/bin/python -m ml.train)
fi

if [ ! -d frontend/node_modules ]; then
  echo "Installing frontend packages (first run only)..."
  (cd frontend && npm install)
fi

trap 'kill 0' EXIT
(cd backend && .venv/bin/uvicorn app.main:app --port 8000) &
(cd frontend && npm run dev -- --port 5173) &
echo ""
echo "PhishGuard is starting:"
echo "  Dashboard : http://localhost:5173"
echo "  API docs  : http://localhost:8000/docs"
wait
