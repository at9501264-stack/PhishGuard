"""Collect REAL legitimate deep-link URLs from public sitemaps of Tranco-ranked domains.

Run from backend/:  .venv/bin/python -m ml.collect_legit

Writes ml/data/raw/sitemaps/legit_deeplinks.csv (url, domain, rank, group). The training script reads
this snapshot (it never crawls), so training stays reproducible offline.

groups
  train : random domains from Tranco ranks 1-30,000   -> extra real legitimate training URLs
  eval  : random domains from Tranco ranks 30,001-60,000 -> held-out "modern" evaluation set

Politeness: one robots.txt request per domain, at most 3 sitemap documents per domain, response bodies
capped at 400 kB, identified User-Agent.
"""
from __future__ import annotations

import asyncio
import csv
import zlib
import html
import random
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import tldextract

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"
OUT_DIR = RAW / "sitemaps"
OUT = OUT_DIR / "legit_deeplinks.csv"
SEED = 7
N_DOMAINS = {"train": 4000, "eval": 7000}
PER_DOMAIN = 6
MAX_BYTES = 400_000
UA = "PhishGuard-academic-research/1.0 (B.Tech project; sitemap sampler)"

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_LOC = re.compile(r"<loc>\s*(?:<!\[CDATA\[)?\s*([^<\s\]]+)", re.I)
_SKIP_EXT = re.compile(r"\.(xml|gz|jpe?g|png|gif|webp|svg|ico|mp4|mp3|webm|css|js|woff2?|ttf|zip|rss)$", re.I)


async def _get(client: httpx.AsyncClient, url: str) -> str | None:
    try:
        async with client.stream("GET", url) as r:
            if r.status_code != 200:
                return None
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf += chunk
                if len(buf) > MAX_BYTES:
                    break
        data = bytes(buf)
        if data[:2] == b"\x1f\x8b":
            try:  # tolerate truncated gzip streams
                data = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, MAX_BYTES * 8)
            except Exception:
                return None
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _locs(text: str) -> list[str]:
    return [html.unescape(m) for m in _LOC.findall(text or "")]


async def _domain(client: httpx.AsyncClient, domain: str, rng: random.Random) -> list[str]:
    sitemaps: list[str] = []
    robots = await _get(client, f"https://{domain}/robots.txt")
    if robots:
        sitemaps = [ln.split(":", 1)[1].strip() for ln in robots.splitlines()
                    if ln.lower().startswith("sitemap:")][:5]
    if not sitemaps:
        sitemaps = [f"https://{domain}/sitemap.xml"]
    fetched = 0
    urls: list[str] = []
    queue = list(sitemaps)
    while queue and fetched < 3:
        sm = queue.pop(0)
        text = await _get(client, sm)
        fetched += 1
        if not text:
            continue
        locs = _locs(text)
        if "<sitemapindex" in text[:5000].lower():
            rng.shuffle(locs)
            queue = locs[:2] + queue
            continue
        urls.extend(locs)
        if len(urls) > 200:
            break
    good = []
    for u in urls:
        try:
            p = urlsplit(u)
        except ValueError:
            continue
        if p.scheme not in ("http", "https") or not p.hostname:
            continue
        ex = _EXTRACT(p.hostname)
        if f"{ex.domain}.{ex.suffix}" != domain:
            continue
        if len(p.path.strip("/")) < 2 or _SKIP_EXT.search(p.path) or len(u) > 300:
            continue
        good.append(u.strip())
    good = list(dict.fromkeys(good))
    rng.shuffle(good)
    return good[:PER_DOMAIN]


async def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = [ln.split(",", 1) for ln in (RAW / "top-1m.csv").read_text().splitlines()[:60000]]
    ranked = [(int(r), d.strip().lower()) for r, d in rows]
    # "--round N" (N >= 2): extra TRAIN-group domains not sampled in earlier rounds -> separate CSV
    rnd = int(sys.argv[sys.argv.index("--round") + 1]) if "--round" in sys.argv else 1
    global OUT
    if rnd == 1:
        rng = random.Random(SEED)
        groups = {
            "train": rng.sample([x for x in ranked if x[0] <= 30000], N_DOMAINS["train"]),
            "eval": rng.sample([x for x in ranked if x[0] > 30000], N_DOMAINS["eval"]),
        }
    else:
        rng0 = random.Random(SEED)  # replay round-1 sampling to exclude those domains
        done_before = {d for _, d in rng0.sample([x for x in ranked if x[0] <= 30000], N_DOMAINS["train"])}
        rng = random.Random(SEED + rnd)
        for k in range(2, rnd):
            done_before |= {d for _, d in random.Random(SEED + k).sample(
                [x for x in ranked if x[0] <= 30000 and x[1] not in done_before], 6000)}
        groups = {"train": rng.sample([x for x in ranked if x[0] <= 30000 and x[1] not in done_before], 6000)}
        OUT = OUT_DIR / f"legit_deeplinks_r{rnd}.csv"
    limits = httpx.Limits(max_connections=220, max_keepalive_connections=40)
    timeout = httpx.Timeout(7.0, connect=5.0)
    sem = asyncio.Semaphore(200)
    results: list[tuple[str, str, int, str]] = []
    done = 0

    async with httpx.AsyncClient(headers={"User-Agent": UA}, follow_redirects=True, limits=limits,
                                 timeout=timeout, verify=True) as client:
        async def one(group: str, rank: int, domain: str) -> None:
            nonlocal done
            async with sem:
                try:
                    urls = await asyncio.wait_for(_domain(client, domain, random.Random(f"{SEED}-{domain}")), 20)
                except Exception:
                    urls = []
            results.extend((u, domain, rank, group) for u in urls)
            done += 1
            if done % 500 == 0:
                print(f"{done} domains, {len(results)} urls", flush=True)

        jobs = [(g, r, d) for g, lst in groups.items() for r, d in lst]
        random.Random(SEED).shuffle(jobs)  # interleave groups
        await asyncio.gather(*(one(g, r, d) for g, r, d in jobs))

    with OUT.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "domain", "rank", "group"])
        w.writerows(results)
    by = {g: sum(1 for x in results if x[3] == g) for g in groups}
    print(f"wrote {len(results)} urls to {OUT}: {by}", flush=True)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
