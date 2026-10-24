"""Orchestrates one scan: parse -> features -> rules -> score -> explain."""
from __future__ import annotations

import uuid
from dataclasses import asdict
from datetime import datetime, timezone

from .config import THRESHOLDS
from .explanation import build_explanation
from .config import RULE_WEIGHTS
from .reputation import get_providers, run_providers
from .feature_extractor import extract_features
from .risk_scorer import SCORE_METHOD, calculate_score
from .rules_engine import ACTION_VERIFY, Finding, evaluate
from .url_parser import parse_url

SKIPPED_CHECKS = [
    {"check": "Redirect chain", "status": "not_checked",
     "reason": "PhishGuard never fetches submitted URLs (protects against SSRF), so redirects are not followed."},
    {"check": "TLS certificate and domain age", "status": "not_checked",
     "reason": "Requires contacting the destination or WHOIS/RDAP services; not performed."},
    {"check": "Page content", "status": "not_checked",
     "reason": "The page is never loaded or rendered."},
]


def _reputation_findings(results) -> list[Finding]:
    out = []
    for r in results:
        if r.status == "match":
            weight = RULE_WEIGHTS["reputation_match"]
            kinds = ", ".join(r.threat_types or []) or "unspecified threat"
            out.append(Finding(
                "reputation_match", "reputation", f"Reported by {r.provider}", "high", weight,
                f"{r.provider} lists this URL (threat type: {kinds}).",
                "A reputation service has flagged this address. Unlike PhishGuard's heuristics, this is an external report.",
                ACTION_VERIFY))
    return out


def run_scan(raw_url: str, providers=None) -> dict:
    parsed = parse_url(raw_url)
    features = extract_features(parsed)
    findings, observations = evaluate(parsed, features)
    reputation = run_providers(get_providers() if providers is None else providers, parsed.lookup_url)
    findings = sorted(findings + _reputation_findings(reputation), key=lambda f: f.weight, reverse=True)
    result = calculate_score(findings)
    explanation = build_explanation(findings, result, reputation)
    return {
        "scan_id": uuid.uuid4().hex,
        "scanned_at": datetime.now(timezone.utc),
        "hostname": parsed.hostname,
        "risk_score": result.score,
        "risk_category": result.category,
        "thresholds": list(THRESHOLDS),
        "score_method": SCORE_METHOD,
        "findings": [asdict(f) for f in findings],
        "positive_observations": [asdict(o) for o in observations],
        "score_breakdown": result.breakdown,
        "url_breakdown": parsed.to_breakdown(),
        "reputation": [r.to_dict() for r in reputation],
        "skipped_checks": [dict(s) for s in SKIPPED_CHECKS],
        "explanation": explanation,
        "recommended_next_steps": explanation["next_steps"],
    }
