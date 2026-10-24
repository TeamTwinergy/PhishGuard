"""Provider interface. Add a new reputation source by subclassing ReputationProvider."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# match        -> provider reported the URL
# no_match     -> provider was queried and returned nothing (NOT proof of safety)
# not_checked  -> provider was not queried (e.g. no credentials)
# error / timeout / rate_limited -> query attempted but no usable answer
STATUSES = ("match", "no_match", "not_checked", "error", "timeout", "rate_limited")


@dataclass
class ProviderResult:
    provider: str
    status: str
    detail: Optional[str] = None
    threat_types: Optional[list] = None

    def to_dict(self) -> dict:
        return {"provider": self.provider, "status": self.status, "detail": self.detail,
                "threat_types": self.threat_types}


class ReputationProvider:
    name = "provider"

    def is_configured(self) -> bool:
        raise NotImplementedError

    def check(self, url: str) -> ProviderResult:
        raise NotImplementedError
