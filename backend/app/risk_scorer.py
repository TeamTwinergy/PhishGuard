"""Transparent risk calculation.

score = min(100, sum of the HIGHEST-weight finding in each indicator group)

Related indicators share a group (e.g. all brand-impersonation variants), so the
same underlying signal is never counted twice. The result is an ordinal warning
level, NOT a probability that the URL is malicious.
"""
from __future__ import annotations

from dataclasses import dataclass

from .config import CATEGORY_LABELS, THRESHOLDS
from .rules_engine import Finding

SCORE_METHOD = (
    "Score = sum of the highest-weight finding in each indicator group, capped at 100. "
    "Weights and category thresholds are configurable starting points, not calibrated probabilities."
)


@dataclass
class ScoreResult:
    score: int
    category: str
    breakdown: list[dict]
    uncapped_total: int


def categorize(score: int, thresholds=THRESHOLDS) -> str:
    caution, high, very_high = thresholds
    if score >= very_high:
        return CATEGORY_LABELS[3]
    if score >= high:
        return CATEGORY_LABELS[2]
    if score >= caution:
        return CATEGORY_LABELS[1]
    return CATEGORY_LABELS[0]


def calculate_score(findings: list[Finding], thresholds=THRESHOLDS) -> ScoreResult:
    best: dict[str, Finding] = {}
    for f in findings:
        if f.group not in best or f.weight > best[f.group].weight:
            best[f.group] = f
    breakdown = []
    for f in findings:
        counted = best[f.group] is f
        breakdown.append({
            "rule_id": f.rule_id,
            "group": f.group,
            "weight": f.weight,
            "counted": counted,
            "note": "Counted toward the score." if counted
            else f"Not counted: a stronger indicator in the '{f.group}' group already applies.",
        })
    total = sum(f.weight for f in best.values())
    score = min(100, total)
    return ScoreResult(score, categorize(score, thresholds), breakdown, total)
