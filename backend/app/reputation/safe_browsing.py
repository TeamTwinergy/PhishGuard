"""Google Safe Browsing v4 `threatMatches:find` adapter.

The URL is sent to Google (never fetched by PhishGuard). Review Google's Safe Browsing
terms: the Lookup API is intended for non-commercial use. The API key travels in a
header, not the URL, so HTTP client logs never contain it.
"""
from __future__ import annotations

from typing import Callable, Optional

from ..config import PROVIDER_TIMEOUT_SECONDS, SAFE_BROWSING_API_KEY
from .base import ProviderResult, ReputationProvider

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]

# (url, headers, json_body, timeout) -> (status_code, parsed_json_or_None)
HttpPost = Callable[[str, dict, dict, float], tuple]


def _default_post(url: str, headers: dict, body: dict, timeout: float):
    import httpx  # imported lazily so the rest of the app imports without it

    try:
        r = httpx.post(url, headers=headers, json=body, timeout=timeout)
    except httpx.TimeoutException as exc:
        raise TimeoutError("provider timed out") from exc
    except httpx.HTTPError as exc:
        raise ConnectionError("provider unreachable") from exc
    try:
        data = r.json()
    except ValueError:
        data = None
    return r.status_code, data


class SafeBrowsingProvider(ReputationProvider):
    name = "Google Safe Browsing"

    def __init__(self, api_key: Optional[str] = None, http_post: HttpPost = _default_post,
                 timeout: float = PROVIDER_TIMEOUT_SECONDS):
        self._key = SAFE_BROWSING_API_KEY if api_key is None else api_key
        self._post = http_post
        self._timeout = timeout

    def is_configured(self) -> bool:
        return bool(self._key)

    def check(self, url: str) -> ProviderResult:
        if not self.is_configured():
            return ProviderResult(self.name, "not_checked",
                                  "No API key configured on the server; no request was sent.")
        body = {
            "client": {"clientId": "phishguard", "clientVersion": "0.2.0"},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            status, data = self._post(ENDPOINT, {"X-Goog-Api-Key": self._key}, body, self._timeout)
        except TimeoutError:
            return ProviderResult(self.name, "timeout", "The provider did not answer in time.")
        except Exception:  # never leak exception text (could include URLs or keys)
            return ProviderResult(self.name, "error", "The provider could not be reached.")
        if status == 429:
            return ProviderResult(self.name, "rate_limited", "The provider's rate limit was reached.")
        if status != 200 or not isinstance(data, dict):
            return ProviderResult(self.name, "error", f"The provider returned an unexpected response (HTTP {status}).")
        matches = data.get("matches") or []
        if matches:
            types = sorted({m.get("threatType", "UNKNOWN") for m in matches if isinstance(m, dict)})
            return ProviderResult(self.name, "match", "Reported in Google's Safe Browsing lists.", types)
        return ProviderResult(self.name, "no_match",
                              "Not in Google's lists at query time. This does not prove the URL is safe.")
