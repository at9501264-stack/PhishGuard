#!/usr/bin/env python3
"""Pre-deploy checks for the Vercel demo deployment (run from anywhere, any Python >= 3.10):

    backend/.venv/bin/python deploy/preflight.py                 # checks only
    backend/.venv/bin/python deploy/preflight.py --stage DIR     # + materialise the function bundle in DIR
    backend/.venv/bin/python deploy/preflight.py --smoke         # + stage to a temp dir and smoke-test it locally

Checks
1. upload size: files `vercel deploy` would upload after .vercelignore (Hobby CLI limit 100 MB);
2. function bundle: upload minus vercel.json functions.excludeFiles minus the Python builder's predefined
   excludes (+ dependency size measured on the last staged install, if any) against the 500 MB limit;
3. Python requirements: every third-party import in backend/app, backend/ml/{predictor,features}.py and
   deploy/cloud_app.py must be listed in requirements.txt; forbidden packages (playwright, uvloop, httptools)
   must not be; listed-but-unused packages are reported;
4. snapshot freshness: deploy/seed.db and deploy/feeds/*.gz vs backend/data (rebuild with build_cloud_seed.py);
5. --smoke: runs deploy.cloud_app from the staged copy with uvicorn on a free port (never 8000/8100/5173) and
   calls /api/health, /api/_diag, /api/scans, POST /api/scan (deep) - an offline rehearsal of the cloud function.
Exit code 1 if a hard check fails.
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MB = 1024 * 1024
UPLOAD_LIMIT_MB = 100
FUNCTION_LIMIT_MB = 500
FORBIDDEN = {"playwright", "uvloop", "httptools", "uvicorn"}
PREDEFINED_PY_EXCLUDES = [".git/**", ".vercel/**", "**/node_modules/**", "**/.venv/**", "**/venv/**",
                          "**/__pycache__/**", "**/public/**"]
CLI_ALWAYS_IGNORED = [".git", ".vercel", ".hg", ".svn", ".DS_Store", "node_modules"]
# import name -> distribution name (only where they differ)
IMPORT_TO_DIST = {"sklearn": "scikit-learn", "bs4": "beautifulsoup4", "dns": "dnspython", "whois": "python-whois",
                  "multipart": "python-multipart", "PIL": "pillow", "yaml": "pyyaml", "dateutil": "python-dateutil"}
RUNTIME_SOURCES = ["backend/app/**/*.py", "backend/ml/predictor.py", "backend/ml/features.py", "deploy/cloud_app.py",
                   "api/*.py"]


# ------------------------------------------------------------------------------------- glob helpers
def _expand_braces(p: str) -> list[str]:
    m = re.search(r"\{([^{}]*)\}", p)
    if not m:
        return [p]
    out = []
    for alt in m.group(1).split(","):
        out += _expand_braces(p[:m.start()] + alt + p[m.end():])
    return out


def _glob_re(p: str) -> re.Pattern:
    i, out = 0, ""
    while i < len(p):
        if p.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif p.startswith("**", i):
            out += ".*"
            i += 2
        elif p[i] == "*":
            out += "[^/]*"
            i += 1
        elif p[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(p[i])
            i += 1
    return re.compile("^" + out + "$")


def _ignore_rules(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text().splitlines() if ln.strip() and not ln.strip().startswith("#")]


def _ignored(rel: str, rules: list[str]) -> bool:
    """Small gitignore matcher (no negations) - enough for this repo's .vercelignore."""
    parts = rel.split("/")
    prefixes = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
    for r in rules:
        pat = r.rstrip("/")
        if pat.startswith("/") or "/" in pat:
            pat = pat.lstrip("/")
            rx = _glob_re(pat)
            if any(rx.match(p) for p in prefixes):
                return True
        elif any(fnmatch.fnmatchcase(part, pat) for part in parts):
            return True
    return False


def upload_files() -> list[tuple[str, int]]:
    rules = CLI_ALWAYS_IGNORED + _ignore_rules(ROOT / ".vercelignore")
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel_dir = Path(dirpath).relative_to(ROOT).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in dirnames if not _ignored(f"{rel_dir}/{d}".lstrip("/"), rules)]
        for f in filenames:
            rel = f"{rel_dir}/{f}".lstrip("/")
            if not _ignored(rel, rules):
                out.append((rel, (Path(dirpath) / f).stat().st_size))
    return out


def function_files(upload: list[tuple[str, int]]) -> list[tuple[str, int]]:
    cfg = json.loads((ROOT / "vercel.json").read_text())
    fn = (cfg.get("functions") or {}).get("api/index.py") or {}
    pats = []
    for p in PREDEFINED_PY_EXCLUDES + [fn.get("excludeFiles") or ""]:
        pats += [x for x in _expand_braces(p) if x]
    rxs = [_glob_re(p) for p in pats]
    out_dir = cfg.get("outputDirectory") or ""
    return [(r, s) for r, s in upload if not any(rx.match(r) for rx in rxs)
            and not (out_dir and r.startswith(out_dir.rstrip("/") + "/"))]


# ----------------------------------------------------------------------------------- requirements
def _req_names() -> dict[str, str]:
    names = {}
    for ln in (ROOT / "requirements.txt").read_text().splitlines():
        ln = ln.split("#", 1)[0].strip()
        if ln:
            n = re.split(r"[<>=!~\[; ]", ln, 1)[0].strip().lower().replace("_", "-")
            names[n] = ln
    return names


def _third_party_imports() -> dict[str, set[str]]:
    stdlib = set(sys.stdlib_module_names)
    local = {"app", "ml", "deploy", "api", "__future__"}
    found: dict[str, set[str]] = {}
    files: set[Path] = set()
    for pattern in RUNTIME_SOURCES:
        files |= set(ROOT.glob(pattern))
    for f in sorted(files):
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError as e:
            print(f"  ! syntax error in {f.relative_to(ROOT)}: {e}")
            continue
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module]
            for m in mods:
                top = m.split(".")[0]
                if top not in stdlib and top not in local:
                    found.setdefault(top, set()).add(str(f.relative_to(ROOT)))
    return found


def check_requirements() -> bool:
    ok = True
    req = _req_names()
    imports = _third_party_imports()
    dists = {IMPORT_TO_DIST.get(m, m).lower().replace("_", "-"): m for m in imports}
    try:
        from importlib.metadata import packages_distributions
        pd = packages_distributions()
        for m in imports:
            for d in pd.get(m, []):
                dists.setdefault(d.lower().replace("_", "-"), m)
    except Exception:
        pass
    missing = sorted(m for m in imports if IMPORT_TO_DIST.get(m, m).lower().replace("_", "-") not in req
                     and not any(d in req for d, mm in dists.items() if mm == m))
    forbidden = sorted(n for n in req if n in FORBIDDEN)
    imported_dists = {d for d in dists}
    # needed although not imported by name: scikit-learn/scipy are unpickled by joblib, python-multipart is
    # FastAPI's form/upload parser, pandas is imported lazily for DataFrame-fitted artifacts
    transitive_ok = {"scikit-learn", "scipy", "httpcore", "pydantic", "python-multipart", "joblib", "pandas"}
    unused = sorted(n for n in req if n not in imported_dists and n not in transitive_ok)
    print(f"- runtime third-party imports: {', '.join(sorted(imports))}")
    if missing:
        ok = False
        for m in missing:
            print(f"  ! MISSING in requirements.txt: {m} (imported by {', '.join(sorted(imports[m]))[:160]})")
    if forbidden:
        ok = False
        print(f"  ! FORBIDDEN in requirements.txt: {', '.join(forbidden)}")
    if unused:
        print(f"  ~ listed but not imported by runtime code: {', '.join(unused)}")
    if ok:
        print("  requirements.txt covers every runtime import")
    return ok


# ------------------------------------------------------------------------------------- freshness
def check_snapshot() -> bool:
    ok = True
    seed = ROOT / "deploy" / "seed.db"
    src = ROOT / "backend" / "data" / "phishguard.db"
    if not seed.exists():
        print("  ! deploy/seed.db missing -> run deploy/build_cloud_seed.py")
        return False
    age_h = (time.time() - seed.stat().st_mtime) / 3600
    print(f"- deploy/seed.db: {seed.stat().st_size / MB:.1f} MB, built {age_h:.1f} h ago")
    if src.exists():
        newest_src = max(p.stat().st_mtime for p in src.parent.glob("phishguard.db*"))
        if newest_src > seed.stat().st_mtime + 60:
            print("  ~ backend/data/phishguard.db changed after the snapshot -> re-run deploy/build_cloud_seed.py")
    packed = ROOT / "deploy" / "feeds"
    raw = ROOT / "backend" / "data" / "feeds"
    if not packed.is_dir() or not list(packed.glob("*.gz")):
        print("  ! deploy/feeds/*.gz missing -> run deploy/build_cloud_seed.py (raw feeds are not uploaded)")
        ok = False
    elif raw.is_dir():
        newest_raw = max((p.stat().st_mtime for p in raw.iterdir() if p.is_file()), default=0)
        oldest_packed = min(p.stat().st_mtime for p in packed.iterdir())
        print(f"- deploy/feeds: {sum(p.stat().st_size for p in packed.iterdir()) / MB:.1f} MB packed")
        if newest_raw > oldest_packed + 60:
            print("  ~ backend/data/feeds changed after packing -> re-run deploy/build_cloud_seed.py")
    return ok


# ------------------------------------------------------------------------------------------ stage
def stage(dst: Path, files: list[tuple[str, int]]) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    for rel, _ in files:
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dst / rel)


def _free_port() -> int:
    for port in range(8765, 8800):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise SystemExit("no free port in 8765-8799")


def _req(url: str, data: dict | None = None, timeout: float = 120) -> tuple[int, dict, float]:
    t = time.perf_counter()
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"} if body else {})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}"), time.perf_counter() - t
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read()[:300].decode("utf-8", "ignore")}, time.perf_counter() - t


def smoke(staged: Path) -> bool:
    py = ROOT / "backend" / ".venv" / "bin" / "python"
    port = _free_port()
    tmp_root = Path(tempfile.mkdtemp(prefix="pg-cloud-tmp-"))
    env = {**os.environ, "PHISHGUARD_TMP_ROOT": str(tmp_root)}
    for k in [k for k in env if k.startswith("PHISHGUARD_") and k != "PHISHGUARD_TMP_ROOT"]:
        env.pop(k)
    cmd = [str(py), "-m", "uvicorn", "api.index:app", "--host", "127.0.0.1", "--port", str(port)]
    print(f"- smoke: {' '.join(cmd[2:])} (cwd={staged}, TMP={tmp_root})")
    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, cwd=staged, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{port}"
    ok = True
    try:
        for _ in range(120):
            try:
                st, body, _ = _req(base + "/api/health", timeout=5)
                if st == 200:
                    break
            except Exception:
                pass
            if proc.poll() is not None:
                break
            time.sleep(0.25)
        print(f"  first /api/health after {time.perf_counter() - t0:.1f}s")
        checks = [("GET /api/health", lambda: _req(base + "/api/health")),
                  ("GET /api/_diag", lambda: _req(base + "/api/_diag?net=0")),
                  ("GET /api/scans", lambda: _req(base + "/api/scans?page_size=5")),
                  ("POST /api/scan deep", lambda: _req(base + "/api/scan", {
                      "url": "http://paypal-login-verify.secure-account.xyz/update", "deep": True}))]
        for name, fn in checks:
            st, body, dt = fn()
            good = st == 200
            extra = ""
            if name.endswith("/api/scans") and good:
                good = (body.get("total") or 0) > 0
                extra = f"total={body.get('total')}"
            elif name.startswith("POST") and good:
                extra = f"verdict={body.get('verdict')} risk={body.get('risk_score')} duration_ms={body.get('duration_ms')}"
            elif name.endswith("_diag") and good:
                extra = (f"app_import={body.get('app_import')} bootstrap_ms={body['cold_start'].get('bootstrap_ms')} "
                         f"feeds={body['feeds'].get('entries_index')} tranco={(body.get('tranco') or {}).get('status')}")
            elif name.endswith("health") and good:
                extra = f"cloud={body.get('cloud')} model_loaded={body.get('model_loaded')} feeds={body.get('feeds_entries')}"
            ok &= good
            print(f"  {'ok ' if good else 'FAIL'} {name}: HTTP {st} in {dt:.2f}s {extra}")
    finally:
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        if not ok:
            print("  --- server log (tail) ---\n" + "\n".join(out.splitlines()[-40:]))
        shutil.rmtree(tmp_root, ignore_errors=True)
    return ok


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", type=Path, help="copy the function bundle (minus deps) into this directory")
    ap.add_argument("--smoke", action="store_true", help="stage to a temp dir and smoke-test with uvicorn")
    ap.add_argument("--top", type=int, default=8, help="show the N largest uploaded files")
    a = ap.parse_args()
    hard_ok = True

    up = upload_files()
    up_mb = sum(s for _, s in up) / MB
    print(f"- upload: {len(up)} files, {up_mb:.1f} MB (Hobby CLI limit {UPLOAD_LIMIT_MB} MB)")
    for rel, s in sorted(up, key=lambda x: -x[1])[:a.top]:
        print(f"    {s / MB:7.1f} MB  {rel}")
    if up_mb > UPLOAD_LIMIT_MB:
        hard_ok = False
        print("  ! upload exceeds the Hobby limit")
    elif up_mb > UPLOAD_LIMIT_MB * 0.9:
        print("  ~ upload is within 10% of the Hobby limit")

    fn = function_files(up)
    fn_mb = sum(s for _, s in fn) / MB
    print(f"- function files (excl. Python deps): {len(fn)} files, {fn_mb:.1f} MB; "
          f"+ ~300 MB Linux wheels (numpy/scipy/sklearn/pandas) -> ~{fn_mb + 300:.0f} MB of {FUNCTION_LIMIT_MB} MB")
    for must in ("api/index.py", "deploy/cloud_app.py", "deploy/seed.db", "backend/app/main.py",
                 "backend/ml/predictor.py", "backend/ml/artifacts/metrics.json", "backend/data/tranco/tranco_index.npz"):
        if not any(r == must for r, _ in fn):
            hard_ok = False
            print(f"  ! required file missing from the function bundle: {must}")

    hard_ok &= check_requirements()
    hard_ok &= check_snapshot()

    if a.stage or a.smoke:
        dst = a.stage or Path(tempfile.mkdtemp(prefix="pg-stage-")) / "phishguard"
        stage(dst, fn)
        print(f"- staged function bundle in {dst}")
        if a.smoke:
            hard_ok &= smoke(dst)
            if not a.stage:
                shutil.rmtree(dst.parent, ignore_errors=True)
    print("PREFLIGHT", "OK" if hard_ok else "FAILED")
    sys.exit(0 if hard_ok else 1)


if __name__ == "__main__":
    main()
