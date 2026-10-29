"""Phishing URL prediction with 4 trained models + per-feature explanations."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import joblib
import numpy as np

from ml.features import FEATURE_LABELS, FEATURE_NAMES, extract_features

ART = Path(__file__).resolve().parent / "artifacts"
_LOCK = threading.Lock()
_STATE: dict | None = None
MODEL_ORDER = ("Logistic Regression", "Decision Tree", "Random Forest", "Support Vector Machine")


def _load_once() -> dict:
    metrics = json.loads((ART / "metrics.json").read_text())
    names = list(metrics.get("features") or metrics.get("feature_names") or FEATURE_NAMES)
    files = {m["name"]: m.get("file") for m in metrics.get("models", [])}
    models = {}
    for name in MODEL_ORDER:
        fn = files.get(name)
        if not fn or not (ART / fn).exists():
            continue
        m = joblib.load(ART / fn)
        n_in = getattr(m, "n_features_in_", len(names))
        if n_in != len(names):  # artifacts are being replaced right now -> caller retries
            raise RuntimeError(f"{name}: expects {n_in} features, metrics.json lists {len(names)}")
        if hasattr(m, "n_jobs"):
            m.n_jobs = 1  # single-row latency is better without thread fan-out
        models[name] = m
    if not models:
        raise RuntimeError("no trained models found in ml/artifacts")
    median = metrics.get("legit_median", {})
    best = metrics.get("best_model")
    return {"metrics": metrics, "models": models, "names": names,
            "baseline": np.array([median.get(f, 0.0) for f in names], dtype=float),
            "best": best if best in models else next(iter(models))}


def _load() -> dict:
    global _STATE
    if _STATE is not None:
        return _STATE
    with _LOCK:
        if _STATE is None:
            for attempt in range(5):
                try:
                    _STATE = _load_once()
                    break
                except (RuntimeError, ValueError, EOFError, OSError):
                    if attempt == 4:
                        raise
                    time.sleep(0.4)
        return _STATE


def _as_input(model, X: np.ndarray, names: list[str]):
    """Feed the model the same input type it was fitted with (avoids sklearn feature-name warnings)."""
    cols = getattr(model, "feature_names_in_", None)
    if cols is None:
        return X
    import pandas as pd  # only for artifacts fitted on DataFrames
    return pd.DataFrame(X, columns=names)[list(cols)]


def _proba(model, X: np.ndarray, names: list[str]) -> np.ndarray:
    return model.predict_proba(_as_input(model, X, names))[:, 1]


def predict(url: str) -> dict:
    st = _load()
    feats = extract_features(url)
    names = st["names"]
    x = np.array([[feats.get(f, 0.0) for f in names]], dtype=float)
    models = st["models"]
    best_name = st["best"]
    best = models[best_name]

    per_model = [{"name": n, "probability": round(float(_proba(m, x, names)[0]), 4)} for n, m in models.items()]

    # Perturbation explanation over the model's own inputs: set each feature (that differs) to the
    # legitimate-class training median and measure the change in the best model's probability.
    base = st["baseline"]
    diff_idx = [i for i in range(len(names)) if x[0, i] != base[i]]
    rows = np.repeat(x, len(diff_idx) + 1, axis=0)
    for r, i in enumerate(diff_idx, start=1):
        rows[r, i] = base[i]
    probs = _proba(best, rows, names)
    p = float(probs[0])
    expl = []
    for r, i in enumerate(diff_idx, start=1):
        impact = p - float(probs[r])
        if abs(impact) < 1e-4:
            continue
        f = names[i]
        v = feats.get(f, 0.0)
        expl.append({"feature": f, "label": FEATURE_LABELS.get(f, f),
                     "value": int(v) if float(v).is_integer() else round(v, 4),
                     "impact": round(impact, 4), "direction": "risk" if impact > 0 else "safe"})
    expl.sort(key=lambda e: -abs(e["impact"]))

    return {"model_name": best_name, "model_version": st["metrics"].get("version", "unknown"),
            "probability_phishing": round(p, 4), "per_model": per_model,
            "explanations": expl[:10], "features": feats}


def model_info() -> dict:
    m = dict(_load()["metrics"])
    m.pop("legit_median", None)
    return m
