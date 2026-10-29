"""Demo data seed (~67 scans over the last 30 days + reports, votes, 3 watch items, alerts).

Every scan goes through the normal pipeline (perform_scan), so v2 fields (trust_score, tier, threat_type, factors,
summary, engines, ...) are computed exactly like a live scan. DEEP_SAMPLE well-known sites get full network scans
(IP/ASN/registrar pivots, graph edges, DOM snapshot); everything else is lexical + ML only. Phishing URLs are never
fetched. Disabled on an empty DB with PHISHGUARD_NO_SEED=1.
"""
from __future__ import annotations

import asyncio
import logging
import random
from datetime import datetime, timedelta, timezone

from app import db
from app.services import community, feeds_service
from app.services.events import create_alert, log_event
from app.services.scanner import InvalidURL, normalize_url, perform_scan

log = logging.getLogger("phishguard.seed")

LEGIT_URLS = [
    "https://www.google.com", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "https://www.facebook.com",
    "https://www.wikipedia.org", "https://en.wikipedia.org/wiki/Phishing", "https://www.amazon.com/gp/bestsellers",
    "https://www.amazon.in", "https://www.apple.com/iphone/", "https://support.apple.com/en-us/HT201222",
    "https://www.microsoft.com/en-us/microsoft-365", "https://login.microsoftonline.com",
    "https://github.com/fastapi/fastapi", "https://stackoverflow.com/questions/tagged/python",
    "https://www.linkedin.com/feed/", "https://twitter.com/home", "https://www.instagram.com",
    "https://www.netflix.com/browse", "https://www.paypal.com/in/home", "https://www.reddit.com/r/netsec/",
    "https://www.bbc.com/news", "https://www.nytimes.com", "https://docs.python.org/3/library/sqlite3.html",
    "https://www.dropbox.com/login", "https://mail.google.com/mail/u/0/", "https://drive.google.com/drive/my-drive",
    "https://www.adobe.com/acrobat.html", "https://www.zoom.us/join", "https://slack.com/intl/en-in/",
    "https://www.sbi.co.in", "https://www.hdfcbank.com/personal/pay/cards", "https://www.icicibank.com",
    "https://www.flipkart.com/mobiles", "https://www.irctc.co.in/nget/train-search", "https://www.chase.com",
    "https://www.bankofamerica.com/online-banking/", "https://www.wellsfargo.com", "https://www.cloudflare.com",
    "https://www.mozilla.org/en-US/firefox/", "https://openai.com", "https://www.anthropic.com",
    "https://news.ycombinator.com", "https://www.spotify.com/in-en/premium/",
]

FALLBACK_PHISHING = [
    "http://paypal-account-verify.secure-login-update.com/webapps/signin",
    "http://appleid.apple.com.verify-account-locked.xyz/login",
    "https://secure-chase-online.com.auth-session.top/verify/identity",
    "http://microsoft-office365-login.web-app-auth.info/owa/",
    "http://192.168.43.7/netflix/billing/update.php",
    "https://amaz0n-prime-renewal.shop/account/payment",
    "http://www.faceb00k-security-check.club/recover",
    "https://login-wellsfargo.secure-verify-online.net/signon",
    "http://sbi-netbanking-kyc-update.online/sbi/login.html",
    "https://dropbox-shared-doc.firebaseapp.com/view?file=invoice.pdf",
    "http://bit-ly-redirect.icu/?u=paypal.com.webscr.cmd-login",
    "https://hdfc-bank-reward-points.top/redeem/otp",
    "http://xn--pple-43d.com/id/signin",
    "https://instagram-copyright-appeal.help/form",
    "http://outlook-mail-quota-exceeded.weebly.com/",
    "https://docs-google.com-drive-share.ml/file/d/0B7/view",
    "http://irctc-refund-claim.in.net/refund/status",
    "https://steamcommunity-gift.ru/tradeoffer/new",
    "http://binance-wallet-verify.app-secure.cc/login",
    "https://metamask-io-restore.web.app/wallet",
    "http://usps-redelivery-tracking-update.com/track?id=9400111",
    "https://dhl-parcel-customs-fee.info/pay",
    "http://netflix-account-hold.billing-update-center.com/",
    "https://linkedin-job-offer-verify.xyz/apply",
    "http://adobe-pdf-online-viewer.000webhostapp.com/doc.php",
]

# full network scans (shared ASNs make a readable graph: Google, Meta, Microsoft, Wikimedia, Amazon ...)
DEEP_SAMPLE = {
    "https://www.google.com", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "https://mail.google.com/mail/u/0/",
    "https://drive.google.com/drive/my-drive", "https://www.facebook.com", "https://www.instagram.com",
    "https://www.microsoft.com/en-us/microsoft-365", "https://login.microsoftonline.com", "https://www.wikipedia.org",
    "https://en.wikipedia.org/wiki/Phishing", "https://www.amazon.com/gp/bestsellers", "https://github.com/fastapi/fastapi",
}
LEXICAL_ONLY = {"enable_network_checks": False, "enable_screenshots": False}

SOURCE_WEIGHTS = [("web", 50), ("api", 14), ("bulk", 14), ("text", 8), ("qr", 5), ("extension", 9)]
HOUR_WEIGHTS = [1, 1, 1, 1, 1, 2, 3, 5, 8, 10, 11, 11, 10, 10, 11, 11, 10, 9, 8, 7, 6, 4, 3, 2]

_state = {"running": False, "last": None}


def status() -> dict:
    return {"running": _state["running"], "last": _state["last"],
            "demo_scans": db.scalar("SELECT COUNT(*) FROM scans WHERE tags LIKE '%\"demo\"%'", (), 0)}


def _random_time(rng: random.Random, now: datetime, max_days: int = 30) -> datetime:
    # slightly favour recent days so the trend looks alive
    day = int(min(max_days - 1, abs(rng.triangular(0, max_days, 0))))
    hour = rng.choices(range(24), weights=HOUR_WEIGHTS)[0]
    t = (now - timedelta(days=day)).replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59),
                                            microsecond=0)
    if t > now:
        t -= timedelta(days=1)
    return t


async def _phishing_urls(n: int = 25) -> list[str]:
    urls: list[str] = []
    try:
        if feeds_service.total_entries() == 0:
            await feeds_service.wait_for_refresh(90)
        entries = await asyncio.to_thread(feeds_service.feeds_mod().search_entries, "", n * 2)
        for e in entries or []:
            u = (e or {}).get("url")
            if u and u not in urls:
                urls.append(u)
            if len(urls) >= n:
                break
    except Exception as e:
        log.warning("feed search for seed failed: %s", e)
    if len(urls) < 8:
        urls += [u for u in FALLBACK_PHISHING if u not in urls]
    return urls[:n]


async def run_seed(force: bool = False, deep: bool = False) -> dict:
    if _state["running"]:
        return {"status": "already_running"}
    if not force and db.scalar("SELECT COUNT(*) FROM scans WHERE tags LIKE '%\"demo\"%'", (), 0) > 0:
        return {"status": "skipped", "reason": "demo data already present"}
    _state["running"] = True
    try:
        rng = random.Random()
        now = datetime.now(timezone.utc)
        phishing = await _phishing_urls(25)
        targets = [(u, "legit") for u in LEGIT_URLS] + [(u, "phish") for u in phishing]
        rng.shuffle(targets)
        sem = asyncio.Semaphore(6)
        created: list[tuple[int, str]] = []

        async def one(url: str, kind: str) -> None:
            async with sem:
                src = rng.choices([s for s, _ in SOURCE_WEIGHTS], weights=[w for _, w in SOURCE_WEIGHTS])[0]
                full = kind == "legit" and (deep or url in DEEP_SAMPLE)
                try:
                    res = await perform_scan(url, source=src, deep=full, tags=["demo"], log_events=False,
                                             make_alerts=False, settings_override=None if full else LEXICAL_ONLY)
                    created.append((res["id"], kind))
                except InvalidURL:
                    pass
                except Exception:
                    log.exception("seed scan failed for %s", url)

        await asyncio.gather(*(one(u, k) for u, k in targets))

        # rewrite timestamps & write matching activity events
        times: dict[int, str] = {}
        for sid, _ in created:
            t = db.to_iso(_random_time(rng, now))
            times[sid] = t
            s = db.query_one("SELECT domain, verdict, risk_score, source, url, tested_depth FROM scans WHERE id = ?",
                             (sid,))
            if s["tested_depth"] == "full":
                db.execute("UPDATE scans SET created_at = ? WHERE id = ?", (t, sid))
            else:  # lexical-only scans are ~instant; give them realistic full-scan latencies for the demo
                db.execute("UPDATE scans SET created_at = ?, duration_ms = ? WHERE id = ?",
                           (t, rng.randint(350, 4200) if rng.random() < 0.85 else rng.randint(4200, 9800), sid))
            log_event("scan", f"Scanned {s['domain']}: {s['verdict']} ({s['risk_score']})",
                      {"scan_id": sid, "url": s["url"], "verdict": s["verdict"], "risk_score": s["risk_score"],
                       "source": s["source"], "demo": True}, created_at=t,
                      entity_type="scan", entity_id=sid, scan_id=sid, domain=s["domain"])

        rows = db.query("SELECT id, url, domain, verdict, risk_score, brand, created_at FROM scans "
                        "WHERE tags LIKE '%\"demo\"%' ORDER BY risk_score DESC")
        risky = [r for r in rows if r["verdict"] != "legitimate"] or rows[:6]
        safe = [r for r in rows if r["verdict"] == "legitimate"]

        # community reports with votes
        voters = ["analyst_ayushi", "soc_team", "blue_fox", "netwatch", "j.doe", "secops42", "phishhunter"]
        plan = [(+5, "phishing"), (+4, "phishing"), (+1, "phishing"), (0, "phishing"), (+3, "phishing")]
        for (extra, label), r in zip(plan, risky[:5]):
            created_at = db.to_iso(db.parse_iso(r["created_at"]) + timedelta(minutes=rng.randint(5, 600)))
            if db.parse_iso(created_at) > now:
                created_at = db.now_iso()
            rep = community.create_report(r["url"], label, brand=r["brand"], comment="Received via email/SMS lure",
                                          reporter=rng.choice(voters), scan=False, created_at=created_at, log_it=False)
            db.update("reports", rep["id"], {"scan_id": r["id"]})
            for v in rng.sample(voters, k=min(len(voters), abs(extra))):
                community.vote(rep["id"], "phishing" if extra > 0 else "legitimate", voter=v, log_it=False,
                               created_at=created_at)
            if rng.random() < 0.5:
                community.vote(rep["id"], "legitimate", voter="skeptic_" + str(rng.randint(1, 99)), log_it=False)
            log_event("report", f"Community report: {rep['domain']} as {label}", {"report_id": rep["id"], "demo": True},
                      created_at=created_at, entity_type="report", entity_id=rep["id"], scan_id=r["id"],
                      domain=rep["domain"])
        if safe:
            r = safe[0]
            rep = community.create_report(r["url"], "phishing", comment="Looked suspicious to me", reporter="newuser",
                                          scan=False, log_it=False)
            db.update("reports", rep["id"], {"scan_id": r["id"]})
            for v in voters[:4]:
                community.vote(rep["id"], "legitimate", voter=v, log_it=False)

        # watchlist
        watch = [("paypal.com", "PayPal brand protection", 60, 1),
                 ("https://github.com", "GitHub", 120, 0)]
        if risky:
            watch.append((risky[0]["url"], "Suspected phishing kit", 30, 0))
        for target, label, interval, typo in watch:
            if not db.scalar("SELECT COUNT(*) FROM watchlist WHERE target = ?", (target,), 0):
                wid = db.insert("watchlist", {"target": target, "label": label, "interval_minutes": interval,
                                              "monitor_typosquats": typo, "created_at": db.now_iso(),
                                              "known_typosquats": "[]"})
                try:
                    host = normalize_url(target)[2]
                except InvalidURL:
                    host = None
                log_event("watch_add", f"Watching {target}", {"watch_id": wid, "demo": True},
                          entity_type="watch", entity_id=wid, domain=host)

        # alerts
        for r in risky[:2]:
            t = times.get(r["id"]) or db.now_iso()
            create_alert("high_risk_scan", "critical", f"High-risk phishing detected: {r['domain']}",
                         f"Risk {r['risk_score']}/100" + (f", impersonating {r['brand']}" if r["brand"] else ""),
                         scan_id=r["id"], created_at=t, domain=r["domain"])
        sus = [r for r in rows if r["verdict"] == "suspicious"]
        if sus:
            create_alert("suspicious_scan", "warning", f"Suspicious URL needs review: {sus[0]['domain']}",
                         f"Risk {sus[0]['risk_score']}/100", scan_id=sus[0]["id"], created_at=times.get(sus[0]["id"]),
                         domain=sus[0]["domain"])
        create_alert("system", "info", "Demo data loaded", f"{len(created)} demo scans seeded across 30 days", read=True)

        result = {"status": "ok", "scans": len(created), "phishing_urls": len(phishing)}
        log_event("seed", f"Demo seed completed: {len(created)} scans", result)
        _state["last"] = {**result, "at": db.now_iso()}
        return result
    finally:
        _state["running"] = False


_tasks: set[asyncio.Task] = set()


def seed_in_background(force: bool = False, deep: bool = False) -> asyncio.Task:
    t = asyncio.get_running_loop().create_task(run_seed(force, deep))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return t
