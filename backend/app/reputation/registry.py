from __future__ import annotations

from .base import ProviderResult, ReputationProvider
from .safe_browsing import SafeBrowsingProvider


def get_providers() -> list[ReputationProvider]:
    return [SafeBrowsingProvider()]


def run_providers(providers: list[ReputationProvider], url: str) -> list[ProviderResult]:
    results = []
    for p in providers:
        try:
            results.append(p.check(url))
        except Exception:
            results.append(ProviderResult(getattr(p, "name", "provider"), "error", "The provider check failed unexpectedly."))
    return results
