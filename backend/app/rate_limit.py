"""Simple in-memory sliding-window limiter (per client IP).

Behind a proxy (e.g. Render) the client IP is the proxy's unless uvicorn runs with
--proxy-headers and a trusted --forwarded-allow-ips. Resets on restart.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import Request

from .config import RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECONDS
from .errors import ApiError


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window_seconds:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECONDS)


def enforce_rate_limit(request: Request) -> None:
    key = request.client.host if request.client else "unknown"
    if not limiter.allow(key):
        raise ApiError(429, "rate_limited", "Too many scans in a short time. Please wait a minute and try again.",
                       headers={"Retry-After": str(limiter.window_seconds)})
