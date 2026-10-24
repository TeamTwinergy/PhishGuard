"""Deterministic, evidence-only explanations (no AI key needed).

Only restates what the scanner actually found or did not check.
"""
from __future__ import annotations

from .risk_scorer import ScoreResult
from .rules_engine import Finding

LIMITATIONS = [
    "This is a static analysis of the URL text. PhishGuard did not visit the site, so it cannot see the page content, redirects, certificate details or domain age.",
    "A low score means few warning signs were found in the address itself. It is not a guarantee that the site is safe.",
]


def _next_steps(category: str) -> list[str]:
    never = "Never enter passwords, one-time codes or payment details on a page you reached through a suspicious link."
    if category in ("High concern", "Very high concern"):
        return [
            "Do not open the link.",
            "Go to the service by typing its official address or using its official app.",
            "If you already entered a password, change it from a trusted device and turn on two-factor authentication.",
            "Report the message to your email provider or IT/help desk.",
            never,
        ]
    if category == "Caution":
        return [
            "Be careful: confirm with the sender through a different channel before opening the link.",
            "Prefer reaching the service by typing its official address.",
            never,
        ]
    return [
        "If you did not expect this link, still avoid entering credentials unless you reached the site yourself.",
        never,
    ]


def _reputation_note(reputation) -> str:
    queried = [r.provider for r in (reputation or []) if r.status in ("match", "no_match")]
    if queried:
        return (f"Reputation lookups ran against: {', '.join(queried)}. A 'no match' only means the URL was not in "
                "those lists at that moment; new phishing sites often are not listed yet.")
    return "No reputation provider returned a result in this scan, so the absence of a reputation warning means nothing."


def build_explanation(findings: list[Finding], result: ScoreResult, reputation=None) -> dict:
    counted = [b for b in result.breakdown if b["counted"]]
    if findings:
        top = findings[0]
        summary = (
            f"Risk score {result.score}/100 ({result.category}). {len(counted)} indicator group(s) counted toward the score. "
            f"Strongest signal: {top.title}. These are signals found in the URL, not proof of phishing."
        )
    else:
        summary = (
            f"Risk score {result.score}/100 ({result.category}). No warning indicators were triggered by PhishGuard's URL rules. "
            "That is not a guarantee the site is safe."
        )
    return {
        "source": "deterministic",
        "summary": summary,
        "evidence": [f"{f.title}: {f.evidence}" for f in findings],
        "limitations": LIMITATIONS[:1] + [_reputation_note(reputation)] + LIMITATIONS[1:],
        "next_steps": _next_steps(result.category),
    }
