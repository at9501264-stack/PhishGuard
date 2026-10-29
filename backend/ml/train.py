"""Build the dataset, train & compare 4 classifiers (2 feature variants), save artifacts.

Run from backend/:  .venv/bin/python -m ml.train
(optional, needs network, run first:  .venv/bin/python -m ml.collect_legit  -> real legit deep links)

Data (all read from snapshots under ml/data/raw/, never from live feeds)
---------------------------------------------------------------------
Phishing
  * PhiUSIIL Phishing URL Dataset (UCI #967; label 0 = phishing, verified from the data)
  * PhishTank verified-online feed, Phishing.Database ACTIVE domains, OpenPhish
    (snapshot of backend/data/feeds/ in raw/feeds_snapshot_20261024/)
  Deduplicated across sources (scheme-insensitive); at most 3 URLs per "campaign key"
  (PSL-private-aware registered domain, or the tenant host on free-hosting platforms).
Legitimate
  * real deep links sampled from public sitemaps of Tranco top-30k domains (collect_legit.py)
  * real popular hosts with human-facing sub-domains from the Tranco list incl. sub-domains
  * PhiUSIIL legitimate homepages + Tranco top-30k domains, augmented (see below)

Bias mitigation
  * PhiUSIIL legit URLs are all bare "https://www.<domain>" homepages -> legit hosts are augmented
    (www toggled, ~40% get a realistic synthetic deep-link path, a few get a query string) and mixed
    with real deep links / real sub-domain hosts.
  * Phishing.Database lists hosts only. Their scheme is imputed with PhishTank's https rate and a share
    of them (PhishTank's own path rate) get the path+query of a random *training* PhishTank URL, so
    "bare host" does not become a phishing artefact. Eval Phishing.Database hosts are left bare.
  * Scheme: two variants are trained - (a) with `uses_https`, (b) without any scheme-derived feature -
    and the more robust one on the held-out modern set is kept.

Held-out "modern" evaluation set (never used for training or model selection inside a variant)
  * 1,000 PhishTank + 1,000 Phishing.Database URLs whose campaign keys are excluded from training
  * 2,000 legitimate deep links from Tranco ranks 30,001-60,000 (real sitemap URLs; any shortfall is
    filled with synthetic deep links from templates NOT used in training). All domains of that rank
    range are excluded from the legit training data.
"""
from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.kernel_approximation import Nystroem
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

from ml.features import (FEATURE_LABELS, FEATURE_NAMES, OFFICIAL_DOMAINS, SCHEME_FEATURES, SHORTENERS,
                         extract_features, normalize_url, on_free_hosting)

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
RAW = DATA / "raw"
SNAP = RAW / "feeds_snapshot_20261024"
SITEMAPS = RAW / "sitemaps" / "legit_deeplinks.csv"
TRANCO = RAW / "top-1m.csv"
TRANCO_SUB = RAW / "tranco_sub" / "top-1m.csv"
ART = ROOT / "artifacts"
SEED = 42

N_PHIUSIIL = 45_000
N_PHISHTANK = 16_000
N_PHISHDB = 12_000
N_EVAL_PT, N_EVAL_PD, N_EVAL_LEGIT = 1_000, 1_000, 2_000
CAP_PER_KEY = 3
SVM_SUBSAMPLE = 40_000
EVAL_RANKS = (30_001, 60_000)

MODEL_FILES = {
    "Logistic Regression": "logistic_regression.joblib",
    "Decision Tree": "decision_tree.joblib",
    "Random Forest": "random_forest.joblib",
    "Support Vector Machine": "svm.joblib",
}

_EX = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_EX_PRIV = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

# ----------------------------------------------------------------------------- synthetic legit paths
WORDS = ("about news blog article home product products item shop store cart help support docs "
         "documentation guide tutorial learn course courses video videos watch music movie movies "
         "series sports football cricket weather travel hotels flights jobs careers team contact "
         "privacy terms policy faq pricing plans features download downloads release releases "
         "notes changelog community forum forums topic thread question questions answers search "
         "results category categories tag tags author profile user users settings preferences "
         "dashboard library reference api developer developers sdk examples sample samples "
         "project projects issues pull pulls wiki events event calendar photos gallery images "
         "recipes food health science technology tech business finance markets money world india "
         "local politics opinion review reviews best top new latest popular trending deals sale "
         "offers gift cards electronics mobiles laptops fashion women men kids books kindle "
         "education research papers publications report annual investor investors press media "
         "local city state country map maps directions open source python javascript linux "
         "install getting started overview introduction chapter section part page index archive "
         "2019 2020 2021 2022 2023 2024 2025 how to why what best-practices the of and for in on"
         ).split()
SUBS = ("docs blog shop store support help m en accounts mail news developer developers app my "
        "login auth api status community forum learn careers investor static cdn images").split()
LANGS = ("en en-us en-gb en-in fr de es hi ja pt-br it").split()
HUMAN_SUBS = set(("docs doc blog blogs shop store support help m mobile en fr de es it pt ja news "
                  "developer developers dev app apps my login auth account accounts signin secure id "
                  "portal mail webmail community forum forums learn careers jobs status investor investors "
                  "about info web online pay checkout cart wiki music maps drive photos play translate "
                  "calendar meet admin console dashboard cloud business ads partners events academy "
                  "education research labs open shopping smile go get try members member customer "
                  "service services billing myaccount profile live tv video videos games search").split())

# held-out templates / vocabulary used ONLY to fill the modern eval set if real deep links run short
EVAL_WORDS = ("garden kitchen bicycle festival museum harbor violin lantern meadow orchard canyon "
              "pottery tailor cobalt saffron glacier compass novel poetry theatre ballet ceramic quilt "
              "harvest summit vintage marble walnut cedar falcon prairie lagoon atlas emerald copper").split()


def _slug(rng, lo=2, hi=6, words=WORDS):
    return "-".join(rng.choice(words) for _ in range(rng.randint(lo, hi)))


def _rand_id(rng, n, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"):
    return "".join(rng.choice(alphabet) for _ in range(n))


def _fake_path(rng: random.Random) -> str:
    w = lambda: rng.choice(WORDS)  # noqa: E731
    # ~15% of deep links carry a query string
    if rng.random() < 0.15:
        t = rng.choice((6, 7, 11, 12, 13, 18, 21))
    else:
        t = rng.choice((0, 1, 2, 3, 4, 5, 8, 9, 10, 14, 15, 16, 17, 19, 20, 22, 23, 24, 25, 26, 27))
    if t == 0:
        return f"/{w()}/{_slug(rng)}"
    if t == 1:
        return f"/{rng.randint(2015, 2025)}/{rng.randint(1, 12):02d}/{rng.randint(1, 28):02d}/{_slug(rng)}"
    if t == 2:
        return f"/products/{_slug(rng, 1, 4)}-{rng.randint(100, 99999)}"
    if t == 3:
        return f"/dp/b0{_rand_id(rng, 8)}"
    if t == 4:
        return f"/{_rand_id(rng, rng.randint(4, 10), 'abcdefghijklmnopqrstuvwxyz')}/{w()}-{w()}/issues/{rng.randint(1, 9999)}"
    if t == 5:
        return f"/{rng.randint(1, 3)}/{w()}/{w()}.html"
    if t == 6:
        return f"/search?q={'+'.join(w() for _ in range(rng.randint(1, 4)))}"
    if t == 7:
        return f"/watch?v={_rand_id(rng, 11, 'abcdefghijklmnopqrstuvwxyz0123456789-_')}"
    if t == 8:
        return f"/wiki/{w()}_{w()}"
    if t == 9:
        return f"/{rng.choice(LANGS)}/{w()}/{_slug(rng, 1, 3)}"
    if t == 10:
        return rng.choice(["/login", "/signin", "/account", "/account/login", "/accounts/login",
                           "/user/login", "/auth/login", "/my-account", "/account/settings",
                           "/signup", "/register", "/checkout", "/cart", "/support/contact",
                           "/help/security", "/secure/checkout", "/update-profile", "/billing"])
    if t == 11:
        return f"/{w()}?id={rng.randint(1, 999999)}"
    if t == 12:
        return f"/{w()}/{w()}?page={rng.randint(1, 50)}&sort={rng.choice(['new', 'top', 'price', 'asc'])}"
    if t == 13:
        return f"/index.php?title={w()}_{w()}"
    if t == 14:
        return f"/{w()}/{rng.randint(10000, 9999999)}/{_slug(rng, 2, 5)}"
    if t == 15:
        return f"/p/{_rand_id(rng, rng.randint(8, 12))}"
    if t == 16:
        return f"/{w()}/{w()}/{w()}"
    if t == 17:
        return f"/{w()}"
    if t == 18:
        return (f"/{w()}/{_slug(rng, 1, 3)}?utm_source={rng.choice(['twitter', 'newsletter', 'google', 'facebook'])}"
                f"&utm_medium={rng.choice(['social', 'email', 'cpc'])}")
    if t == 19:
        return f"/r/{w()}/comments/{_rand_id(rng, 6)}/{w()}_{w()}_{w()}"
    if t == 20:
        return f"/{w()}/{w()}.pdf"
    if t == 21:
        return f"/{w()}/{w()}.php?id={rng.randint(1, 5000)}"
    if t == 22:
        return f"/questions/{rng.randint(1000, 79999999)}/{_slug(rng, 3, 8)}"
    if t == 23:
        return f"/{w()}/{w()}/{rng.randint(1, 500)}"
    if t == 24:
        return f"/@{w()}{rng.randint(1, 999)}/{_slug(rng, 3, 7)}-{_rand_id(rng, 12, '0123456789abcdef')}"
    if t == 25:
        return f"/status/{rng.randint(10**17, 10**19)}"
    if t == 26:
        return f"/{w()}/{w()}/#{w()}"
    return f"/{w()}-{w()}/{w()}/{_slug(rng, 1, 3)}.html"


def _eval_path(rng: random.Random) -> str:
    """Held-out deep-link templates (different structure & vocabulary from training)."""
    w = lambda: rng.choice(EVAL_WORDS)  # noqa: E731
    t = rng.randint(0, 7)
    if t == 0:
        return f"/collections/{w()}/products/{_slug(rng, 2, 4, EVAL_WORDS)}"
    if t == 1:
        return f"/stories/{_slug(rng, 3, 7, EVAL_WORDS)}-{rng.randint(1000000, 99999999)}"
    if t == 2:
        return f"/events/{rng.randint(2024, 2026)}/{w()}-{w()}"
    if t == 3:
        return f"/forum/viewtopic.php?t={rng.randint(100, 999999)}"
    if t == 4:
        return f"/catalog/{w()}/item/{rng.randint(10000, 999999)}?color={w()}"
    if t == 5:
        return f"/media/press-releases/{_slug(rng, 3, 6, EVAL_WORDS)}"
    if t == 6:
        return f"/members/{w()}{rng.randint(1, 99)}/gallery"
    return f"/guides/{w()}/{w()}-for-beginners"


def _augment_legit(host: str, rng: random.Random, p_path=0.40, p_sub=0.10) -> str:
    host = host.lower().strip()
    if host.startswith("www."):
        host = host[4:]
    if host.count(".") == 1 or _EX(host).subdomain == "":
        r = rng.random()
        if r < p_sub:
            host = f"{rng.choice(SUBS)}.{host}"
        elif r < p_sub + 0.45:
            host = f"www.{host}"
    scheme = "http" if rng.random() < 0.08 else "https"
    path = _fake_path(rng) if rng.random() < p_path else ("/" if rng.random() < 0.3 else "")
    return f"{scheme}://{host}{path}"


# ----------------------------------------------------------------------------- helpers
def _host(u: str) -> str:
    try:
        h = urlsplit(u).hostname or ""
    except ValueError:
        h = ""
    return h[4:] if h.startswith("www.") else h


def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h.strip("[]"))
        return True
    except ValueError:
        return False


def _pld(h: str) -> str:
    e = _EX(h)
    return f"{e.domain}.{e.suffix}" if e.suffix else e.domain


def campaign_key(u: str) -> str:
    """Dedupe key: tenant host on free-hosting platforms, else PSL-private-aware registered domain."""
    h = _host(u)
    if not h:
        return u
    if _is_ip(h) or on_free_hosting(h):
        return h
    e = _EX_PRIV(h)
    return f"{e.domain}.{e.suffix}" if e.suffix else h


def _scheme_less(u: str) -> str:
    return u.split("://", 1)[1] if "://" in u else u


def _read_lines(p: Path) -> list[str]:
    return [ln.strip() for ln in p.read_text(errors="ignore").splitlines() if ln.strip()]


def _atomic_dump(obj, path: Path) -> None:
    tmp = path.with_name(f".{path.name}.tmp{os.getpid()}")
    joblib.dump(obj, tmp, compress=3)
    os.replace(tmp, path)


def _atomic_text(text: str, path: Path) -> None:
    tmp = path.with_name(f".{path.name}.tmp{os.getpid()}")
    tmp.write_text(text)
    os.replace(tmp, path)


# ----------------------------------------------------------------------------- dataset
def build_dataset():
    rng = random.Random(SEED)
    tranco = pd.read_csv(TRANCO, header=None, names=["rank", "domain"])
    tranco["domain"] = tranco.domain.str.lower()
    top100k = set(tranco.domain[:100_000])
    eval_domains = set(tranco.domain[EVAL_RANKS[0] - 1:EVAL_RANKS[1]])

    # ---------------- phishing
    pt = pd.read_csv(SNAP / "phishtank.csv", usecols=["url", "verified"])
    pt = pt[pt.verified.astype(str).str.lower() == "yes"]
    pt_urls = [normalize_url(u) for u in pt.url.astype(str)]
    p_https = float(np.mean([u.startswith("https://") for u in pt_urls]))
    op_urls = [normalize_url(u) for u in _read_lines(SNAP / "openphish.txt") if u.startswith("http")]
    pd_urls = []
    for ln in _read_lines(SNAP / "phishing_database.txt"):
        if ln.startswith("#"):
            continue
        if re.match(r"^[a-z]+://", ln.lower()):
            pd_urls.append(normalize_url(ln))
        else:
            h = ln.lower().strip(".")
            hb = h[4:] if h.startswith("www.") else h
            if hb in top100k or hb in OFFICIAL_DOMAINS or _pld(hb) in OFFICIAL_DOMAINS:
                continue  # apex of a popular / brand-owned site: almost certainly a feed false positive
            scheme = "https" if rng.random() < p_https else "http"
            pd_urls.append(f"{scheme}://{h}")
    phi = pd.read_csv(RAW / "PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"])
    phi_urls = [normalize_url(u) for u in phi.loc[phi.label == 0, "URL"].astype(str)]

    rows, seen = [], set()
    for src, urls in (("phishtank", pt_urls), ("openphish", op_urls), ("phishing_database", pd_urls),
                      ("phiusiil", phi_urls)):
        for u in urls:
            k = _scheme_less(u)
            if k in seen or not _host(u):
                continue
            seen.add(k)
            rows.append({"url": u, "source": src, "key": campaign_key(u)})
    ph = pd.DataFrame(rows)
    phish_hosts = set(ph.url.map(_host))
    phish_keys_all = set(ph.key)

    # held-out modern phishing: whole campaign keys removed from training
    def pick_keys(src, n, exclude):
        keys = sorted(set(ph.key[ph.source == src]) - exclude)
        rng.shuffle(keys)
        return keys[:n]
    k_pt = pick_keys("phishtank", N_EVAL_PT, set())
    k_pd = pick_keys("phishing_database", N_EVAL_PD, set(k_pt))
    eval_keys = set(k_pt) | set(k_pd)
    ev_rows = []
    for src, keys in (("phishtank", k_pt), ("phishing_database", k_pd)):
        sub = ph[(ph.source == src) & ph.key.isin(set(keys))]
        ev_rows.append(sub.sample(frac=1, random_state=SEED).drop_duplicates("key"))
    ev_ph = pd.concat(ev_rows)
    pool = ph[~ph.key.isin(eval_keys)]

    # cap per campaign key, then sample per source
    pool = pool.sample(frac=1, random_state=SEED).groupby("key", group_keys=False).head(CAP_PER_KEY)
    parts = []
    for src, n in (("phishtank", N_PHISHTANK), ("openphish", 10**9), ("phishing_database", N_PHISHDB),
                   ("phiusiil", N_PHIUSIIL)):
        s = pool[pool.source == src]
        parts.append(s.sample(min(n, len(s)), random_state=SEED))
    tr_ph = pd.concat(parts)

    # Phishing.Database hosts -> borrow a real PhishTank path for PhishTank's share of URLs with a path
    pt_tr = tr_ph[tr_ph.source == "phishtank"].url
    pt_paths = [u.split("://", 1)[1].partition("/")[2] for u in pt_tr]
    pt_paths = ["/" + p for p in pt_paths if p]
    p_path = len(pt_paths) / max(len(pt_tr), 1)

    def transplant(u):
        if "/" in _scheme_less(u) or rng.random() >= p_path:
            return u
        return u + rng.choice(pt_paths)
    m = tr_ph.source == "phishing_database"
    tr_ph.loc[m, "url"] = tr_ph.loc[m, "url"].map(transplant)
    tr_ph["label"] = 1
    ev_ph = ev_ph.assign(label=1)

    # ---------------- legitimate
    def legit_ok(h: str) -> bool:
        hb = h[4:] if h.startswith("www.") else h
        return (hb not in phish_hosts and not on_free_hosting(hb) and _pld(hb) not in SHORTENERS
                and hb not in SHORTENERS)

    sm_files = sorted(SITEMAPS.parent.glob("legit_deeplinks*.csv")) if SITEMAPS.parent.exists() else []
    sm = (pd.concat([pd.read_csv(f) for f in sm_files]) if sm_files
          else pd.DataFrame(columns=["url", "domain", "rank", "group"]))
    sm["url"] = sm.url.astype(str).map(normalize_url)
    ok = np.array([legit_ok(_host(u)) for u in sm.url], dtype=bool) & ~sm.domain.isin(phish_keys_all).to_numpy(bool)
    sm = sm.loc[ok]
    sm = sm.drop_duplicates("url").sample(frac=1, random_state=SEED)

    ev_sm = sm[(sm.group == "eval") & sm.domain.isin(eval_domains)].groupby("domain").head(2)
    ev_sm = ev_sm.head(N_EVAL_LEGIT)
    ev_legit = [{"url": u, "source": "sitemap_eval", "key": d} for u, d in zip(ev_sm.url, ev_sm.domain)]
    if len(ev_legit) < N_EVAL_LEGIT:
        used = set(ev_sm.domain)
        cand = [d for d in tranco.domain[EVAL_RANKS[0] - 1:EVAL_RANKS[1]] if d not in used and legit_ok(d)
                and d not in phish_keys_all]
        rng.shuffle(cand)
        for d in cand[:N_EVAL_LEGIT - len(ev_legit)]:
            host = d if rng.random() < 0.5 else f"www.{d}"
            ev_legit.append({"url": normalize_url(f"https://{host}{_eval_path(rng)}"),
                             "source": "synthetic_eval", "key": d})
    ev_lg = pd.DataFrame(ev_legit).assign(label=0)

    n_target = len(tr_ph)
    legit_parts = []
    # (1) real sitemap deep links from Tranco top-30k
    tr_sm = sm[(sm.group == "train") & ~sm.domain.isin(eval_domains)].groupby("domain").head(6)
    legit_parts.append(pd.DataFrame({"url": tr_sm.url, "source": "sitemap_train", "key": tr_sm.domain}))
    # (2) real popular hosts with human-facing sub-domains (Tranco incl. sub-domains)
    sub = pd.read_csv(TRANCO_SUB, header=None, names=["rank", "host"], nrows=400_000) if TRANCO_SUB.exists() \
        else pd.DataFrame(columns=["rank", "host"])
    sub_hosts = []
    for h in sub.host.astype(str).str.lower():
        e = _EX(h)
        if not e.suffix or e.subdomain in ("", "www") or "." in e.subdomain:
            continue
        if e.subdomain not in HUMAN_SUBS:
            continue
        d = f"{e.domain}.{e.suffix}"
        if d in eval_domains or not legit_ok(h):
            continue
        sub_hosts.append((h, d))
    rng.shuffle(sub_hosts)
    sub_hosts = sub_hosts[:8000]
    legit_parts.append(pd.DataFrame({
        "url": [normalize_url(_augment_legit(h, rng, p_path=0.45, p_sub=0.0)) for h, _ in sub_hosts],
        "source": "tranco_subdomain", "key": [d for _, d in sub_hosts]}))
    # (3) PhiUSIIL legit domains + Tranco top-30k, augmented
    phi_dom = (phi.loc[phi.label == 1, "URL"].str.lower().str.replace(r"^https?://", "", regex=True)
               .str.replace(r"^www\.", "", regex=True).str.rstrip("/").drop_duplicates())
    phi_dom = [d for d in phi_dom if d not in eval_domains and legit_ok(d)]
    tr_dom = [d for d in tranco.domain[:30_000] if d not in eval_domains and legit_ok(d)]
    have = sum(len(p) for p in legit_parts)
    remaining = max(n_target - have, 0)
    n_tr = min(len(tr_dom), int(remaining * 0.35))
    n_phi = min(len(phi_dom), remaining - n_tr)
    rng.shuffle(phi_dom)
    rng.shuffle(tr_dom)
    for src, doms in (("phiusiil_aug", phi_dom[:n_phi]), ("tranco_aug", tr_dom[:n_tr])):
        legit_parts.append(pd.DataFrame({"url": [normalize_url(_augment_legit(d, rng)) for d in doms],
                                         "source": src, "key": doms}))
    tr_lg = pd.concat(legit_parts).drop_duplicates("url").assign(label=0)

    train_df = pd.concat([tr_ph[["url", "label", "source", "key"]], tr_lg[["url", "label", "source", "key"]]])
    train_df = train_df.sample(frac=1, random_state=SEED).reset_index(drop=True)
    eval_df = pd.concat([ev_ph[["url", "label", "source", "key"]], ev_lg[["url", "label", "source", "key"]]])
    eval_df = eval_df.reset_index(drop=True)
    comp = train_df.groupby(["label", "source"]).size()
    info = {"p_https_phishtank": round(p_https, 4), "p_path_phishtank": round(p_path, 4),
            "train_sources": {f"{'phishing' if lab else 'legitimate'}:{src}": int(n)
                              for (lab, src), n in comp.items()},
            "eval_sources": {k: int(v) for k, v in eval_df.groupby("source").size().items()}}
    return train_df, eval_df, info


# ----------------------------------------------------------------------------- models
def make_models() -> dict:
    return {
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, C=1.0)),
        "Decision Tree": DecisionTreeClassifier(max_depth=20, min_samples_leaf=5, random_state=SEED),
        "Random Forest": RandomForestClassifier(n_estimators=150, min_samples_leaf=2, n_jobs=-1,
                                                random_state=SEED),
        "Support Vector Machine": CalibratedClassifierCV(
            make_pipeline(StandardScaler(), Nystroem(gamma=0.03, n_components=500, random_state=SEED),
                          LinearSVC(C=1.0, dual=False, max_iter=5000)),
            method="sigmoid", cv=3),
    }


def _down(a, b, n=100):
    a, b = np.asarray(a), np.asarray(b)
    if len(a) > n:
        idx = np.unique(np.linspace(0, len(a) - 1, n).round().astype(int))
        a, b = a[idx], b[idx]
    return [round(float(x), 4) for x in a], [round(float(x), 4) for x in b]


def _svm_rows(y, rng_seed=SEED):
    """Stratified subsample indices for the (slower) SVM."""
    r = np.random.RandomState(rng_seed)
    idx = np.arange(len(y))
    if len(y) <= SVM_SUBSAMPLE:
        return idx
    keep = []
    for c in (0, 1):
        ci = idx[y == c]
        keep.append(r.choice(ci, int(SVM_SUBSAMPLE * len(ci) / len(y)), replace=False))
    return np.sort(np.concatenate(keep))


def balance_strata(X, y, idx, seed=SEED):
    """Downsample so phishing:legit is 1:1 inside every URL-shape stratum (path depth x has-query).

    The two classes were collected differently (feeds vs. popularity lists / sitemaps), so URL shape
    alone (bare host vs. deep link) would otherwise be learnt as a phishing signal."""
    depth = np.minimum(X[idx, FEATURE_NAMES.index("path_depth")], 4).astype(int)
    hasq = (X[idx, FEATURE_NAMES.index("num_question")] > 0).astype(int)
    strata = depth * 2 + hasq
    r = np.random.RandomState(seed)
    keep, table = [], {}
    for s in np.unique(strata):
        m = strata == s
        a, b = idx[m & (y[idx] == 0)], idx[m & (y[idx] == 1)]
        n = min(len(a), len(b))
        table[f"depth{min(s // 2, 4)}{'+' if s // 2 == 4 else ''}{'_query' if s % 2 else ''}"] = \
            {"legitimate": int(len(a)), "phishing": int(len(b)), "kept_per_class": int(n)}
        if n:
            keep += [r.choice(a, n, replace=False), r.choice(b, n, replace=False)]
    return np.sort(np.concatenate(keep)), table


def _modern_metrics(y, proba, https_mask, src):
    pred = (proba >= 0.5).astype(int)
    ph = y == 1
    out = {"size": int(len(y)),
           "accuracy": round(accuracy_score(y, pred), 4),
           "precision": round(precision_score(y, pred, zero_division=0), 4),
           "recall": round(recall_score(y, pred), 4),
           "f1": round(f1_score(y, pred), 4),
           "https_phish_recall": round(float(pred[ph & https_mask].mean()), 4),
           "roc_auc": round(roc_auc_score(y, proba), 4),
           "fpr": round(float(pred[~ph].mean()), 4)}
    for s in ("phishtank", "phishing_database"):
        mm = ph & (src == s)
        out[f"recall_{s}"] = round(float(pred[mm].mean()), 4) if mm.any() else None
    return out


def fit_variant(feats, X_tr, y_tr, X_te, y_te, X_ev, y_ev, ev_https, ev_src):
    cols = [FEATURE_NAMES.index(f) for f in feats]
    A_tr, A_te, A_ev = X_tr[:, cols], X_te[:, cols], X_ev[:, cols]
    out = {}
    for name, model in make_models().items():
        rows = _svm_rows(y_tr) if name == "Support Vector Machine" else slice(None)
        t0 = time.time()
        model.fit(A_tr[rows], y_tr[rows])
        train_time = time.time() - t0
        t0 = time.time()
        p_te = model.predict_proba(A_te)[:, 1]
        pred_ms = (time.time() - t0) * 1000 / len(A_te)
        p_ev = model.predict_proba(A_ev)[:, 1]
        out[name] = {"model": model, "p_te": p_te, "train_time": train_time, "pred_ms": pred_ms,
                     "modern": _modern_metrics(y_ev, p_ev, ev_https, ev_src),
                     "test_f1": f1_score(y_te, (p_te >= 0.5).astype(int))}
        print(f"  {name:24s} test F1 {out[name]['test_f1']:.4f} | modern {out[name]['modern']}", flush=True)
    return out


def main() -> None:
    t_all = time.time()
    ART.mkdir(parents=True, exist_ok=True)
    print("building dataset ...", flush=True)
    train_df, eval_df, info = build_dataset()
    train_df.to_csv(DATA / "dataset.csv", index=False)
    eval_df.to_csv(DATA / "modern_eval.csv", index=False)
    print(json.dumps(info, indent=1), flush=True)
    print("train", train_df.label.value_counts().to_dict(), "eval", eval_df.label.value_counts().to_dict(),
          flush=True)

    t0 = time.time()
    X = np.array([[f[k] for k in FEATURE_NAMES] for f in map(extract_features, train_df.url)], dtype=float)
    X_ev = np.array([[f[k] for k in FEATURE_NAMES] for f in map(extract_features, eval_df.url)], dtype=float)
    print(f"features: {time.time() - t0:.1f}s", flush=True)
    y = train_df.label.to_numpy()
    y_ev = eval_df.label.to_numpy()
    ev_https = eval_df.url.str.startswith("https://").to_numpy()
    ev_src = eval_df.source.to_numpy()
    groups = train_df.key.astype(str).to_numpy()

    # group-aware stratified 80/20 split: no campaign / domain appears in both train and test
    sgk = StratifiedGroupKFold(5, shuffle=True, random_state=SEED)
    tr_idx, te_idx = next(sgk.split(X, y, groups))
    strata_table = None
    if "--balance-strata" in sys.argv:  # evaluated: did not improve the modern set, off by default
        tr_idx, strata_table = balance_strata(X, y, tr_idx)
        print("strata:", json.dumps(strata_table), flush=True)
    X_tr, X_te, y_tr, y_te = X[tr_idx], X[te_idx], y[tr_idx], y[te_idx]

    variants = {"with_scheme": list(FEATURE_NAMES),
                "without_scheme": [f for f in FEATURE_NAMES if f not in SCHEME_FEATURES]}
    fitted = {}
    for vname, feats in variants.items():
        print(f"variant {vname} ({len(feats)} features)", flush=True)
        fitted[vname] = fit_variant(feats, X_tr, y_tr, X_te, y_te, X_ev, y_ev, ev_https, ev_src)

    def best_of(v):
        return max(fitted[v], key=lambda n: fitted[v][n]["test_f1"])
    ba, bb = best_of("with_scheme"), best_of("without_scheme")
    fa, fb = fitted["with_scheme"][ba]["modern"], fitted["without_scheme"][bb]["modern"]
    # keep the scheme-free variant unless it is clearly worse on the modern set
    chosen = "without_scheme" if fb["f1"] >= fa["f1"] - 0.005 else "with_scheme"
    feats = variants[chosen]
    res = fitted[chosen]
    print(f"chosen variant: {chosen}", flush=True)

    cols = [FEATURE_NAMES.index(f) for f in feats]
    A_tr = X_tr[:, cols]
    cv_folds = list(StratifiedGroupKFold(5, shuffle=True, random_state=SEED).split(A_tr, y_tr, groups[tr_idx]))
    results = []
    for name in MODEL_FILES:
        r = res[name]
        cv = []
        for a, b in cv_folds:
            m = make_models()[name]
            if name == "Support Vector Machine":
                a = a[_svm_rows(y_tr[a])]
            m.fit(A_tr[a], y_tr[a])
            cv.append(f1_score(y_tr[b], m.predict(A_tr[b])))
        cv = np.array(cv)
        proba = r["p_te"]
        pred = (proba >= 0.5).astype(int)
        fpr, tpr, _ = roc_curve(y_te, proba)
        prec, rec, _ = precision_recall_curve(y_te, proba)
        fpr_d, tpr_d = _down(fpr, tpr)
        prec_d, rec_d = _down(prec, rec)
        results.append({
            "name": name,
            "accuracy": round(accuracy_score(y_te, pred), 4),
            "precision": round(precision_score(y_te, pred), 4),
            "recall": round(recall_score(y_te, pred), 4),
            "f1": round(f1_score(y_te, pred), 4),
            "roc_auc": round(roc_auc_score(y_te, proba), 4),
            "train_time_s": round(r["train_time"], 3),
            "predict_time_ms": round(r["pred_ms"], 5),
            "cv_f1_mean": round(float(cv.mean()), 4), "cv_f1_std": round(float(cv.std()), 4),
            "confusion_matrix": confusion_matrix(y_te, pred).tolist(),
            "roc_curve": {"fpr": fpr_d, "tpr": tpr_d},
            "pr_curve": {"precision": prec_d, "recall": rec_d},
            "file": MODEL_FILES[name],
        })
        print({k: v for k, v in results[-1].items() if not isinstance(v, (dict, list))}, flush=True)

    best = max(results, key=lambda r: r["f1"])["name"]
    rf = res["Random Forest"]["model"]
    fi = sorted(({"feature": f, "label": FEATURE_LABELS[f], "importance": round(float(i), 5)}
                 for f, i in zip(feats, rf.feature_importances_)), key=lambda d: -d["importance"])
    Xf = X[:, cols]
    stats = [{"feature": f, "label": FEATURE_LABELS[f],
              "mean_phishing": round(float(Xf[y == 1, j].mean()), 4),
              "mean_legitimate": round(float(Xf[y == 0, j].mean()), 4)} for j, f in enumerate(feats)]
    legit_median = {f: float(np.median(A_tr[y_tr == 0, j])) for j, f in enumerate(feats)}
    scheme_rates = {
        "train_phishing_https": round(float(train_df.url[train_df.label == 1].str.startswith("https://").mean()), 4),
        "train_legitimate_https": round(float(train_df.url[train_df.label == 0].str.startswith("https://").mean()), 4),
        "eval_phishing_https": round(float(ev_https[y_ev == 1].mean()), 4),
        "eval_legitimate_https": round(float(ev_https[y_ev == 0].mean()), 4),
    }
    for s in ("phiusiil", "phishtank", "phishing_database", "openphish"):
        mm = (train_df.label == 1) & (train_df.source == s)
        if mm.any():
            scheme_rates[f"train_{s}_https"] = round(float(train_df.url[mm].str.startswith("https://").mean()), 4)

    now = datetime.now(timezone.utc)
    version = now.strftime("%Y.%m.%d-%H%M")
    n_ph, n_lg = int((y == 1).sum()), int((y == 0).sum())
    metrics = {
        "version": version,
        "trained_at": now.isoformat(timespec="seconds"),
        "dataset": {
            "name": "PhiUSIIL + PhishTank + Phishing.Database + OpenPhish vs Tranco/sitemaps/PhiUSIIL legit",
            "source": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset ; "
                      "http://data.phishtank.com/data/online-valid.csv ; "
                      "https://github.com/mitchellkrogza/Phishing.Database ; https://openphish.com/feed.txt ; "
                      "https://tranco-list.eu (+ public sitemaps of Tranco domains)",
            "total": int(len(y)), "phishing": n_ph, "legitimate": n_lg,
            "train_size": int(len(tr_idx)), "test_size": int(len(te_idx)),
            "composition": info["train_sources"],
            "scheme_rates": scheme_rates,
            "split": "StratifiedGroupKFold 80/20 by campaign key / domain (no group in both train and test)",
            "train_strata": strata_table,
            "notes": (
                "Phishing deduplicated across sources and capped at 3 URLs per campaign key "
                "(PSL-private-aware registered domain, or tenant host on free-hosting platforms). "
                "PhiUSIIL legitimate URLs are bare https://www homepages, so legitimate hosts were "
                "augmented (www toggled, ~40 percent synthetic deep-link paths) and mixed with real sitemap "
                "deep links and real sub-domain hosts from the Tranco list. Phishing.Database lists hosts "
                f"only: scheme imputed with PhishTank's https rate ({info['p_https_phishtank']:.2f}) and "
                f"{100 * info['p_path_phishtank']:.0f} percent of training hosts given the path of a random "
                "training PhishTank URL. All URLs normalised identically (lower-case, trailing slash "
                "stripped)."),
        },
        "best_model": best,
        "models": results,
        "feature_importance": fi,
        "feature_stats": stats,
        "features": feats,
        "feature_names": feats,
        "legit_median": legit_median,
        "feature_variant": chosen,
        "modern_eval": {n: res[n]["modern"] for n in MODEL_FILES},
        "modern_eval_info": {
            "size": int(len(y_ev)), "phishing": int((y_ev == 1).sum()), "legitimate": int((y_ev == 0).sum()),
            "sources": info["eval_sources"],
            "description": ("Held out: 1,000 PhishTank + 1,000 Phishing.Database URLs whose campaign keys "
                            "never appear in training, and legitimate deep links on Tranco ranks "
                            "30,001-60,000 domains (excluded from all legit training data)."),
        },
        "variant_comparison": {
            v: {"features": len(variants[v]), "best_model": best_of(v),
                "test_f1": {n: round(float(fitted[v][n]["test_f1"]), 4) for n in MODEL_FILES},
                "modern_eval": {n: fitted[v][n]["modern"] for n in MODEL_FILES}}
            for v in variants},
        "total_training_time_s": None,
    }
    metrics["total_training_time_s"] = round(time.time() - t_all, 1)

    if "--no-save" in sys.argv:
        print("--no-save: artifacts left untouched", flush=True)
        return
    # artifacts: models first, metrics.json last; every file replaced atomically
    for name, fn in MODEL_FILES.items():
        _atomic_dump(res[name]["model"], ART / fn)
    _atomic_text(json.dumps(metrics, indent=1), ART / "metrics.json")
    print(f"best model: {best}; variant {chosen}; total {time.time() - t_all:.1f}s", flush=True)


if __name__ == "__main__":
    sys.exit(main())
