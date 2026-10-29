"""Application settings persisted in the `settings` table."""
from __future__ import annotations

from typing import Any

from app import db

DEFAULTS: dict[str, Any] = {
    "suspicious_threshold": 35,
    "phishing_threshold": 65,
    "enable_network_checks": True,
    "enable_screenshots": False,
    "timeout_s": 8.0,
    "virustotal_api_key": None,
    "google_safe_browsing_api_key": None,
    "retention_days": 365,
    # v2 (engine: DNSBL lookups, RDAP fallback when the `whois` binary is missing)
    "enable_dnsbl": True,
    "enable_rdap": True,
}
SECRET_KEYS = ("virustotal_api_key", "google_safe_browsing_api_key")
BOOL_KEYS = ("enable_network_checks", "enable_screenshots", "enable_dnsbl", "enable_rdap")


def get_settings() -> dict:
    """Real (unmasked) settings, defaults filled in."""
    out = dict(DEFAULTS)
    for row in db.query("SELECT key, value FROM settings"):
        if row["key"] in DEFAULTS:
            out[row["key"]] = db.loads(row["value"], DEFAULTS[row["key"]])
    return out


def mask(value: str | None) -> str | None:
    if not value:
        return None
    return "****" + value[-4:] if len(value) > 4 else "****"


def masked_settings() -> dict:
    s = get_settings()
    for k in SECRET_KEYS:
        s[k] = mask(s.get(k))
    return s


def _coerce(key: str, value: Any) -> Any:
    if key in ("suspicious_threshold", "phishing_threshold"):
        v = float(value)
        if not 0 <= v <= 100:
            raise ValueError(f"{key} must be between 0 and 100")
        return int(v) if v == int(v) else v
    if key in BOOL_KEYS:
        if isinstance(value, str):
            return value.lower() in ("1", "true", "yes", "on")
        return bool(value)
    if key == "timeout_s":
        v = float(value)
        if not 0.5 <= v <= 60:
            raise ValueError("timeout_s must be between 0.5 and 60")
        return v
    if key == "retention_days":
        v = int(value)
        if v < 0:
            raise ValueError("retention_days must be >= 0 (0 = keep forever)")
        return v
    return value


def update_settings(patch: dict) -> tuple[dict, list[str]]:
    """Apply a partial update. Masked secret values ("****...") are ignored. Returns (masked, changed)."""
    current = get_settings()
    changed: list[str] = []
    new_values: dict[str, Any] = {}
    for key, value in patch.items():
        if key not in DEFAULTS:
            continue
        if key in SECRET_KEYS:
            if value is None:
                continue
            value = str(value).strip()
            if value.startswith("****"):
                continue  # masked echo from the UI: keep real key
            value = value or None
        else:
            if value is None:
                continue
            value = _coerce(key, value)
        if current.get(key) != value:
            new_values[key] = value
            changed.append(key)
    merged = {**current, **new_values}
    if float(merged["suspicious_threshold"]) >= float(merged["phishing_threshold"]):
        raise ValueError("suspicious_threshold must be lower than phishing_threshold")
    for key, value in new_values.items():
        db.execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (key, db.dumps(value)))
    return masked_settings(), changed


def get_meta(key: str, default: Any = None) -> Any:
    row = db.query_one("SELECT value FROM settings WHERE key = ?", (f"_meta:{key}",))
    return db.loads(row["value"], default) if row else default


def set_meta(key: str, value: Any) -> None:
    db.execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (f"_meta:{key}", db.dumps(value)))
