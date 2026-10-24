"""Editable configuration for PhishGuard.

Weights and thresholds are initial product choices, NOT a validated or
calibrated probability model. Calibrate against a labeled dataset (Phase 4)
before making any accuracy claim.
"""
from __future__ import annotations

import os

MAX_INPUT_LENGTH = 4096          # characters accepted for a submitted URL
MAX_BODY_BYTES = 16 * 1024       # request body cap enforced in main.py

# Rate limit per client IP (in-memory; resets on restart)
RATE_LIMIT_MAX = int(os.getenv("PHISHGUARD_RATE_LIMIT_MAX", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("PHISHGUARD_RATE_LIMIT_WINDOW", "60"))

CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("PHISHGUARD_CORS_ORIGINS", "http://localhost:5173").split(",")
    if o.strip()
]

# Points added per indicator. Within one `group` only the highest weight counts.
RULE_WEIGHTS: dict[str, int] = {
    "userinfo_deceptive": 40,
    "userinfo_present": 15,
    "ip_host": 30,
    "ip_obfuscated": 40,
    "brand_official_domain_embedded": 45,
    "brand_idn_homograph": 55,
    "brand_homoglyph": 40,
    "brand_typosquat": 40,
    "brand_in_unofficial_domain": 40,
    "idn_mixed_script": 40,
    "punycode": 10,
    "url_shortener": 15,
    "no_https": 8,
    "excessive_subdomains": 12,
    "long_url_moderate": 5,
    "long_url_extreme": 10,
    "many_hyphens": 8,
    "unusual_port": 12,
    "file_double_extension": 40,
    "file_executable": 30,
    "file_archive": 8,
    "suspicious_keywords_one": 5,
    "suspicious_keywords_many": 10,
    "suspicious_encoding": 15,
    "encoded_host": 30,
    "reputation_match": 80,
}

# Reputation providers (keys come ONLY from the environment, never from the frontend)
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
PROVIDER_TIMEOUT_SECONDS = float(os.getenv("PHISHGUARD_PROVIDER_TIMEOUT", "4"))

LONG_URL_MODERATE = 100
LONG_URL_EXTREME = 250
EXCESSIVE_SUBDOMAINS = 4
MANY_HYPHENS = 3

CATEGORY_LABELS = ("Lower observed risk", "Caution", "High concern", "Very high concern")
DEFAULT_THRESHOLDS = (25, 50, 75)   # lower bound of Caution / High / Very high


def parse_thresholds(value: str | None, default=DEFAULT_THRESHOLDS) -> tuple[int, int, int]:
    """Parse 'a,b,c' (ascending, within 1..100); fall back to defaults if invalid."""
    if not value:
        return default
    try:
        parts = tuple(int(p.strip()) for p in value.split(","))
    except ValueError:
        return default
    if len(parts) != 3 or not (0 < parts[0] < parts[1] < parts[2] <= 100):
        return default
    return parts  # type: ignore[return-value]


THRESHOLDS = parse_thresholds(os.getenv("PHISHGUARD_THRESHOLDS"))
