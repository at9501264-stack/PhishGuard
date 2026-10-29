#!/usr/bin/env python3
"""Assemble README.md from docs/readme_parts/*.md.

Run from the repository root (the backend venv is only needed for the API-table fallback):

    backend/.venv/bin/python scripts/build_readme.py

Every part file starts with its own '## Heading'. The parts are joined in filename order and these markers are filled:

    <!-- SCREENSHOTS -->            gallery from docs/media/screenshots.json (fallback: manifest.json, then the PNGs)
    <!-- ARCHITECTURE_DIAGRAMS -->  docs/architecture/diagrams.md (H1 + intro removed, headings demoted, PNG links)
    <!-- TECH_STACK -->             docs/architecture/tech-stack.md (fallback: frontend/package.json + requirements)
    <!-- API_TABLE -->              docs/architecture/api-endpoints.md (fallback: routes of the FastAPI app)
    <!-- TOC -->                    table of contents from every '## ' heading (GitHub anchor slugs)

Internal '#anchor' links are then checked against GitHub's own heading ids, which keep invisible emoji variation
selectors (U+FE0F: '## 🏗️ Architecture' -> '#️-architecture', not '#-architecture') and number duplicate headings
across the whole page ('machine-learning', 'machine-learning-1'). Links written without the variation selector, or
pointing at a duplicate heading while a heading of that name exists in the link's own section, are rewritten.

Python 3 standard library only.
"""
from __future__ import annotations

import json
import os
import posixpath
import re
import struct
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARTS_DIR = ROOT / "docs" / "readme_parts"
MEDIA_DIR = ROOT / "docs" / "media"
ARCH_DIR = ROOT / "docs" / "architecture"
OUT = ROOT / "README.md"

SKIP_MEDIA = {"demo-poster.png"}
FENCE_RE = re.compile(r"^\s*(```|~~~)")


# --------------------------------------------------------------------------------------------- helpers
def rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return p.as_posix()


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def iter_lines_with_fence(text: str):
    """Yield (line, in_code) where in_code is True for lines inside (or delimiting) a fenced code block."""
    in_code = False
    fence = ""
    for line in text.split("\n"):
        m = FENCE_RE.match(line)
        if m:
            if not in_code:
                in_code, fence = True, m.group(1)
                yield line, True
                continue
            if m.group(1) == fence:
                in_code = False
                yield line, True
                continue
        yield line, in_code


def is_relative_target(t: str) -> bool:
    t = t.strip()
    return bool(t) and not t.startswith(("#", "/", "http://", "https://", "mailto:", "data:", "tel:"))


def rebase_links(text: str, src_dir: str) -> str:
    """Rewrite relative links/src/href of an included file (located in src_dir, repo-relative) to be README-relative."""

    def fix(target: str) -> str:
        if not is_relative_target(target):
            return target
        path, sep, frag = target.partition("#")
        new = posixpath.normpath(posixpath.join(src_dir, path)) if path else ""
        return new + (sep + frag if sep else "")

    out = []
    for line, in_code in iter_lines_with_fence(text):
        if not in_code:
            line = re.sub(r"\]\(([^)\s]+)((?:\s+\"[^\"]*\")?)\)", lambda m: f"]({fix(m.group(1))}{m.group(2)})", line)
            line = re.sub(r"\b(src|href)=\"([^\"]+)\"", lambda m: f'{m.group(1)}="{fix(m.group(2))}"', line)
        out.append(line)
    return "\n".join(out)


def demote(text: str, levels: int = 1) -> str:
    out = []
    for line, in_code in iter_lines_with_fence(text):
        if not in_code and re.match(r"^#{1,5} ", line):
            line = "#" * levels + line
        out.append(line)
    return "\n".join(out)


def strip_h1_and_intro(text: str, keep_intro: bool) -> str:
    """Remove the H1. With keep_intro=False everything before the first '## ' heading is dropped too
    (intro paragraph, contents table/list); otherwise only a leading contents list/table is dropped."""
    lines = text.split("\n")
    out, seen_h2 = [], False
    for line, in_code in iter_lines_with_fence("\n".join(lines)):
        if not in_code and line.startswith("# "):
            continue
        if not in_code and line.startswith("## "):
            seen_h2 = True
        if not keep_intro and not seen_h2:
            continue
        out.append(line)
    body = "\n".join(out)
    if keep_intro:  # drop a contents list / table that only links to local anchors
        body = re.sub(r"(?m)^(?:\s*[-*]\s+\[[^\]]+\]\(#[^)]+\)\s*\n)+", "", body)
    return body.strip("\n")


def _github_keeps(ch: str) -> bool:
    """GitHub removes every character outside [\\p{Word}\\- ] (Ruby/Onigmo: letters, marks, decimal digits,
    connector punctuation, join controls). Marks include the emoji variation selector U+FE0F, so it stays."""
    if ch in "- ‌‍":
        return True
    cat = unicodedata.category(ch)
    return cat[0] in ("L", "M") or cat in ("Nd", "Nl", "Pc")


def slugify(heading: str) -> str:
    """Anchor id GitHub gives a heading (before duplicate numbering)."""
    s = heading.strip().lower()
    s = re.sub(r"<[^>]+>", "", s)  # html tags
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)  # markdown links -> text
    s = re.sub(r"[`*]", "", s)
    s = s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
    return "".join(ch for ch in s if _github_keeps(ch)).replace(" ", "-")


def loose_slug(slug: str) -> str:
    """The same slug without combining marks: what a hand-written '#-architecture' link usually looks like."""
    return "".join(ch for ch in slug if not unicodedata.category(ch).startswith("M"))


HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def heading_index(text: str) -> list[dict]:
    """Every markdown heading outside code fences, in order, with GitHub's de-duplicated anchor id and the index of
    the H1/H2 section it belongs to."""
    counts: dict[str, int] = {}
    out: list[dict] = []
    section = -1
    for n, (line, in_code) in enumerate(iter_lines_with_fence(text)):
        if in_code:
            continue
        m = HEADING_RE.match(line)
        if not m:
            continue
        level, title = len(m.group(1)), m.group(2)
        if level <= 2:
            section += 1
        base = slugify(title)
        slug = base if base not in counts else f"{base}-{counts[base]}"
        counts[base] = counts.get(base, 0) + 1
        out.append({"line": n, "level": level, "title": title, "base": base, "slug": slug,
                    "loose": loose_slug(base), "section": section})
    return out


LINK_ANCHOR_RE = re.compile(r"(\]\(#)([^)\s]+)(\))|(href=\"#)([^\"]+)(\")")


def fix_anchors(text: str) -> tuple[str, list[str]]:
    """Point every internal link at the anchor id GitHub really generates (see the module docstring)."""
    heads = heading_index(text)
    exact = {h["slug"] for h in heads}
    exact.update(re.findall(r"\b(?:id|name)=\"([^\"]+)\"", text))
    starts = [h["line"] for h in heads if h["level"] <= 2]
    changes: list[str] = []

    def section_of(line_no: int) -> int:
        return sum(1 for s in starts if s <= line_no) - 1

    def target(anchor: str, sec: int) -> str:
        same = [h for h in heads if h["section"] == sec and anchor in (h["slug"], h["base"], h["loose"])]
        if same:
            return same[0]["slug"]
        if anchor in exact:
            return anchor
        loose = [h for h in heads if h["loose"] == anchor or loose_slug(h["slug"]) == anchor]
        return loose[0]["slug"] if loose else anchor

    out = []
    for n, (line, in_code) in enumerate(iter_lines_with_fence(text)):
        if not in_code and "#" in line:
            sec = section_of(n)

            def repl(m: re.Match) -> str:
                pre, anchor, post = (m.group(1), m.group(2), m.group(3)) if m.group(1) else \
                    (m.group(4), m.group(5), m.group(6))
                new = target(anchor, sec)
                if new != anchor:
                    changes.append(f"#{anchor} -> #{new}")
                return f"{pre}{new}{post}"

            line = LINK_ANCHOR_RE.sub(repl, line)
        out.append(line)
    return "\n".join(out), changes


# --------------------------------------------------------------------------------------------- screenshots
def title_from_filename(name: str) -> str:
    stem = Path(name).stem.replace("_", "-")
    words = [w for w in stem.split("-") if w]
    return " ".join(w.upper() if w in {"api", "ml", "ssl", "http", "url"} else w.capitalize() for w in words)


def load_screenshots() -> tuple[list[dict], str]:
    sj = MEDIA_DIR / "screenshots.json"
    if sj.exists():
        data = json.loads(read(sj))
        if isinstance(data, dict):
            data = data.get("screenshots") or data.get("files") or data.get("items") or []
        items = []
        for d in data:
            f = d.get("file") or d.get("path") or ""
            f = Path(f).name if f.startswith("docs/media/") else f
            items.append({"file": f, "title": d.get("title") or title_from_filename(f),
                          "section": d.get("section") or d.get("group") or "Screenshots",
                          "explanation": d.get("explanation") or d.get("caption") or d.get("description") or ""})
        return items, rel(sj)
    mj = MEDIA_DIR / "manifest.json"
    if mj.exists():
        data = json.loads(read(mj))
        items = []
        for d in data.get("files", []):
            f = d.get("file", "")
            if not f.lower().endswith((".png", ".jpg", ".jpeg", ".webp")) or d.get("kind", "screenshot") != "screenshot":
                continue
            cap = d.get("caption", "")
            title, _, expl = cap.partition(": ")
            if not expl:
                title, expl = title_from_filename(f), cap
            items.append({"file": f, "title": title.strip(), "section": d.get("group") or "Screenshots",
                          "explanation": expl.strip()[:1].upper() + expl.strip()[1:]})
        return items, rel(mj)
    items = [{"file": p.name, "title": title_from_filename(p.name), "section": "Screenshots", "explanation": ""}
             for p in sorted(MEDIA_DIR.glob("*.png"))]
    return items, "docs/media/*.png"


def build_gallery() -> str:
    items, source = load_screenshots()
    items = [i for i in items if i["file"] and i["file"] not in SKIP_MEDIA]
    counts: dict[str, int] = {}
    for it in items:
        counts[it["title"]] = counts.get(it["title"], 0) + 1
    for it in items:  # same title twice (e.g. phishing vs legitimate report tab): add the file-derived name
        if counts[it["title"]] > 1:
            it["title"] = f"{it['title']} ({title_from_filename(it['file'])})"
    sections: dict[str, list[dict]] = {}
    for it in items:
        sections.setdefault(it["section"], []).append(it)
    out = [f"<!-- gallery generated by scripts/build_readme.py from {source} -->", "",
           f"**{len(items)} screenshots** in {len(sections)} groups: "
           + " · ".join(f"{name} ({len(its)})" for name, its in sections.items()), ""]
    n = 0
    for section, its in sections.items():
        out += [f"### {section}", ""]
        for it in its:
            n += 1
            alt = it["title"].replace('"', "&quot;")
            out.append(f"**{n}. {it['title']}**")
            out.append("")
            expl = it["explanation"].strip()
            if expl:
                if expl[-1] not in ".!?)\"'":
                    expl += "."
                out += [expl, ""]
            size = png_size(MEDIA_DIR / it["file"])
            # phone screenshots (narrow and tall, e.g. 780x1688) stay phone-sized; desktop captures use the full width
            width = "360" if size and size[0] < 1000 and size[1] > size[0] else "100%"
            out += [f'<img src="docs/media/{it["file"]}" alt="{alt}" width="{width}">', ""]
    return "\n".join(out).rstrip() + "\n"


def png_size(p: Path) -> tuple[int, int] | None:
    """(width, height) from a PNG header, or None."""
    try:
        with open(p, "rb") as f:
            head = f.read(24)
    except OSError:
        return None
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", head[16:24])


# --------------------------------------------------------------------------------------------- diagrams
def build_diagrams() -> str:
    src = ARCH_DIR / "diagrams.md"
    if not src.exists():
        return "_Architecture diagrams: see docs/architecture/ (diagrams.md not found)._\n"
    body = strip_h1_and_intro(read(src), keep_intro=False)
    body = rebase_links(body, "docs/architecture")
    body = demote(body, 1)
    # add a PNG fallback link after each mermaid block (named by the preceding <!-- diagram: name --> marker,
    # else by the slug of the current heading)
    out: list[str] = []
    marker = None
    heading_slug = ""
    in_mermaid = False
    for line, in_code in iter_lines_with_fence(body):
        m = re.match(r"^\s*<!--\s*diagram:\s*([\w.-]+)\s*-->", line)
        if m and not in_code:
            marker = m.group(1)
        if not in_code and line.startswith("#"):
            heading_slug = slugify(line.lstrip("#"))
        if FENCE_RE.match(line) and line.strip().startswith("```mermaid"):
            in_mermaid = True
            out.append(line)
            continue
        out.append(line)
        if in_mermaid and FENCE_RE.match(line) and line.strip() in ("```", "~~~"):
            in_mermaid = False
            name = marker
            if not name:
                cands = [p.stem for p in (ARCH_DIR / "img").glob("*.png")] if (ARCH_DIR / "img").exists() else []
                name = next((c for c in cands if c in heading_slug), None)
            png = ARCH_DIR / "img" / f"{name}.png" if name else None
            if png and png.exists():
                out += ["", f"<sub>🖼️ Static image (for viewers without Mermaid): "
                            f"[`{rel(png)}`]({rel(png)})</sub>"]
            marker = None
    return "\n".join(out).strip("\n") + "\n"


# --------------------------------------------------------------------------------------------- tech stack
FE_ROLES = {
    "react": "UI library", "react-dom": "DOM renderer", "react-router-dom": "Client-side routing (19 routes)",
    "@tanstack/react-query": "Server-state cache, polling", "recharts": "Charts (Overview, Analytics, Model Lab)",
    "d3-force": "Force-directed relationship graph", "@types/d3-force": "Types for d3-force",
    "lucide-react": "Icons", "jsqr": "In-browser QR-code decoding", "vite": "Dev server + production bundler",
    "@vitejs/plugin-react": "React support for Vite", "tailwindcss": "Utility-first CSS",
    "@tailwindcss/vite": "Tailwind plugin for Vite", "typescript": "Static typing", "oxlint": "Linter",
    "@types/react": "Types", "@types/react-dom": "Types", "@types/node": "Types",
}
BE_ROLES = {
    "fastapi": "REST API framework, OpenAPI / Swagger UI", "uvicorn": "ASGI server (local)",
    "pydantic": "Request / response validation", "python-multipart": "CSV/TXT upload for bulk scans",
    "httpx": "Async HTTP client (probes, feeds, GeoIP, RDAP)", "httpcore": "httpx transport",
    "dnspython": "DNS records, DNS blocklists, typosquat resolution", "python-whois": "WHOIS lookups",
    "tldextract": "Registered-domain / suffix parsing", "beautifulsoup4": "HTML parsing (forms, links, scripts)",
    "scikit-learn": "LR, Decision Tree, Random Forest, SVM", "scipy": "scikit-learn dependency",
    "pandas": "Dataset building", "numpy": "Feature vectors", "joblib": "Model persistence (`.joblib` files)",
    "mmh3": "Hashed Tranco top-1M index", "langdetect": "Page language detection",
}


LAYERS = [
    "| Machine learning | Python 3.12, scikit-learn (Logistic Regression, Decision Tree, Random Forest, SVM), pandas, NumPy, joblib, tldextract |",
    "| Backend API | FastAPI, Uvicorn, Pydantic 2, httpx (async), SQLite in WAL mode (stdlib `sqlite3`) |",
    "| Network intelligence | dnspython, python-whois with RDAP fallback, Beautiful Soup 4, ip-api.com / ipwho.is (GeoIP), "
    "DNS blocklists, Tranco top-1M (mmh3-hashed index), langdetect |",
    "| Threat intelligence | Local feeds: OpenPhish, PhishTank, URLhaus, Phishing.Database, Phishing Army; optional Google Safe Browsing / VirusTotal keys |",
    "| Frontend | React 19, TypeScript 6, Vite 8, Tailwind CSS 4, Recharts 3, TanStack Query 5, React Router 7, d3-force, lucide-react, jsQR |",
    "| Browser extension | Chrome Manifest V3, plain JavaScript (no build step) |",
    "| Hosting | Vercel: static frontend + one Python function (`api/index.py`) in demo mode, daily Vercel Cron |",
    "| Docs and tooling | oxlint, Mermaid (diagrams), Playwright + Chromium and FFmpeg (screenshots, demo video) |",
]


def build_tech_stack() -> str:
    src = ARCH_DIR / "tech-stack.md"
    if src.exists():
        body = strip_h1_and_intro(read(src), keep_intro=True).replace("This page lists", "This section lists", 1)
        return demote(rebase_links(body, "docs/architecture"), 1).strip("\n") + "\n"
    out = ["### Overview", "", "| Layer | Technology |", "|---|---|", *LAYERS, ""]
    pkg = ROOT / "frontend" / "package.json"
    if pkg.exists():
        p = json.loads(read(pkg))
        out += ["### Frontend (`frontend/package.json`)", "", "| Package | Version | Used for |", "|---|---|---|"]
        for kind in ("dependencies", "devDependencies"):
            for name, ver in p.get(kind, {}).items():
                installed = ROOT / "frontend" / "node_modules" / name / "package.json"
                try:  # prefer the exact installed version over the semver range
                    ver = json.loads(read(installed)).get("version") or ver
                except Exception:
                    pass
                role = FE_ROLES.get(name, "dev tooling" if kind == "devDependencies" else "")
                out.append(f"| `{name}` | {ver} | {role}{' (dev)' if kind == 'devDependencies' else ''} |")
        out.append("")
    pins: dict[str, str] = {}
    for req in (ROOT / "requirements.txt", ROOT / "backend" / "requirements.txt"):
        if req.exists():
            for line in read(req).splitlines():
                line = line.split("#")[0].strip()
                m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]+\])?\s*([=<>!~].*)?$", line)
                if m:
                    pins.setdefault(m.group(1).lower(), (m.group(3) or "").strip())
    if pins:
        out += ["### Backend (`requirements.txt`, `backend/requirements.txt`)", "",
                "| Package | Version | Used for |", "|---|---|---|"]
        for name, ver in pins.items():
            if not ver.startswith("=="):  # unpinned: show the version installed in the running interpreter, if any
                try:
                    from importlib.metadata import version as _v
                    ver = f"{_v(name)} (installed; requires {ver})" if ver else _v(name)
                except Exception:
                    pass
            out.append(f"| `{name}` | {ver.replace('==', '') or '-'} | {BE_ROLES.get(name, '')} |")
    return "\n".join(out).strip() + "\n"


# --------------------------------------------------------------------------------------------- API table
def build_api_table() -> str:
    src = ARCH_DIR / "api-endpoints.md"
    if src.exists():
        body = strip_h1_and_intro(read(src), keep_intro=True)
        body = demote(rebase_links(body, "docs/architecture"), 1)
        # the README's own 70-api.md part follows with a fuller "Example: scan a URL", so drop the page's short one
        body = re.sub(r"(?ms)^### Example\s*\n.*?(?=^#{1,3} |\Z)", "", body)
        return body.strip("\n") + "\n"
    try:
        os.environ.setdefault("PHISHGUARD_NO_SEED", "1")
        os.environ.setdefault("PHISHGUARD_NO_SCHEDULER", "1")
        sys.path.insert(0, str(ROOT / "backend"))
        import logging
        logging.disable(logging.CRITICAL)
        from app.main import app  # type: ignore
        schema = app.openapi()  # works across FastAPI versions (newer ones wrap included routers)
    except Exception as exc:  # pragma: no cover - fallback of the fallback
        return f"_Endpoint table unavailable ({exc.__class__.__name__}); open `/docs` on a running server._\n"
    tag_order = [t["name"] for t in schema.get("tags", [])]
    groups: dict[str, list[tuple[str, str, str, str]]] = {t: [] for t in tag_order}
    for path, ops in schema.get("paths", {}).items():
        for method, op in ops.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            tag = (op.get("tags") or ["Other"])[0]
            params = [f"`{p_['name']}`" for p_ in op.get("parameters", []) if p_.get("in") == "query"]
            body = op.get("requestBody", {}).get("content", {})
            if "multipart/form-data" in body:
                params.insert(0, "file upload")
            elif body:
                params.insert(0, "JSON body")
            groups.setdefault(tag, []).append((method.upper(), path, op.get("summary") or op.get("operationId", ""),
                                               ", ".join(params) or "-"))
    groups = {("Insights" if k == "insights" else k): v for k, v in groups.items() if v}
    total = sum(len(v) for v in groups.values())
    out = [f"All **{total} endpoints** (generated from the FastAPI app):", "",
           "| Area | Method | Path | Purpose | Input (body / query parameters) |", "|---|---|---|---|---|"]
    for tag, rows in groups.items():
        for i, (method, path, summary, params) in enumerate(rows):
            out.append(f"| {'**' + tag + '**' if i == 0 else ''} | `{method}` | `{path}` | {summary} | {params} |")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------------------------- TOC
def build_toc(text: str) -> str:
    items = [f"- [{h['title']}](#{h['slug']})" for h in heading_index(text) if h["level"] == 2]
    return "**📑 Contents**\n\n" + "\n".join(items) + "\n"


# --------------------------------------------------------------------------------------------- checks
def missing_local_refs(text: str) -> list[str]:
    refs = set()
    for line, in_code in iter_lines_with_fence(text):
        if in_code:
            continue
        refs.update(re.findall(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", line))
        refs.update(re.findall(r"\b(?:src|href)=\"([^\"]+)\"", line))
    missing = []
    for r in sorted(refs):
        if not is_relative_target(r):
            continue
        path = r.split("#")[0].split("?")[0]
        if path and not exists_exact_case(path):
            missing.append(path)
    return sorted(set(missing))


def exists_exact_case(path: str) -> bool:
    """Like Path.exists(), but case-sensitive on macOS/Windows too (GitHub serves files case-sensitively)."""
    cur = ROOT
    for part in [p for p in posixpath.normpath(path).split("/") if p not in ("", ".")]:
        if part == "..":
            cur = cur.parent
            continue
        try:
            if part not in os.listdir(cur):
                return False
        except (NotADirectoryError, FileNotFoundError):
            return False
        cur = cur / part
    return True


def broken_anchors(text: str) -> list[str]:
    """Internal '#anchor' links that match no heading (GitHub ids, de-duplicated across all levels) or id/name."""
    slugs = {h["slug"] for h in heading_index(text)}
    slugs.update(re.findall(r"\b(?:id|name)=\"([^\"]+)\"", text))
    bad = set()
    for line, in_code in iter_lines_with_fence(text):
        if in_code:
            continue
        for a in re.findall(r"\]\(#([^)\s]+)\)", line) + re.findall(r"href=\"#([^\"]+)\"", line):
            if a not in slugs:
                bad.add(a)
    return sorted(bad)


# --------------------------------------------------------------------------------------------- main
def main() -> int:
    out_path = OUT
    if "--out" in sys.argv:  # write somewhere else (dry run), e.g. --out /tmp/README.preview.md
        out_path = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
    parts = sorted(PARTS_DIR.glob("*.md"))
    if not parts:
        print(f"no parts in {rel(PARTS_DIR)}", file=sys.stderr)
        return 1
    text = "\n\n".join(read(p).strip("\n") for p in parts) + "\n"

    fillers = {
        "<!-- SCREENSHOTS -->": build_gallery,
        "<!-- ARCHITECTURE_DIAGRAMS -->": build_diagrams,
        "<!-- TECH_STACK -->": build_tech_stack,
        "<!-- API_TABLE -->": build_api_table,
    }
    for marker, fn in fillers.items():
        if marker in text:
            text = text.replace(marker, fn().strip("\n"))
    text = re.sub(r"(?m)^[ \t]*<!--\s*diagram:\s*[\w.-]+\s*-->[ \t]*\n", "", text)  # builder-internal markers
    text = re.sub(r"\n{3,}", "\n\n", text)
    text, anchor_changes = fix_anchors(text)
    if "<!-- TOC -->" in text:
        text = text.replace("<!-- TOC -->", build_toc(text).strip("\n"))
    text = ("<!-- Generated by scripts/build_readme.py from docs/readme_parts/*.md. "
            "Edit those files and run the script again instead of editing README.md. -->\n" + text)
    out_path.write_text(text, encoding="utf-8")

    words = len(re.findall(r"\S+", text))
    n_img = len(re.findall(r"<img\s", text)) + len(re.findall(r"!\[[^\]]*\]\(", text))
    n_mermaid = len(re.findall(r"(?m)^\s*```mermaid", text))
    n_h2 = sum(1 for line, c in iter_lines_with_fence(text) if not c and line.startswith("## "))
    print(f"{out_path.name} written from {len(parts)} parts: {', '.join(p.name for p in parts)}")
    print(f"words: {words}")
    print(f"images: {n_img}")
    print(f"mermaid blocks: {n_mermaid}")
    print(f"H2 sections: {n_h2}")
    missing = missing_local_refs(text)
    if missing:
        print(f"missing local files ({len(missing)}):")
        for m in missing:
            print(f"  - {m}")
    else:
        print("missing local files: none")
    if anchor_changes:
        print(f"#anchors rewritten to GitHub ids ({len(anchor_changes)}): "
              + ", ".join(sorted(set(c.replace("️", "<FE0F>") for c in anchor_changes))))
    bad = broken_anchors(text)
    print(f"broken #anchors ({len(bad)}): {', '.join(bad)}" if bad else "broken #anchors: none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
