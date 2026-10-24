"""API tests. Require fastapi + httpx (pip install -r requirements.txt)."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.rate_limit import limiter

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_limiter(monkeypatch):
    monkeypatch.setattr("app.reputation.safe_browsing.SAFE_BROWSING_API_KEY", "")
    limiter.reset()
    yield
    limiter.reset()


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_scan_response_shape():
    r = client.post("/api/scan", json={"url": "https://www.example.com/"})
    assert r.status_code == 200
    d = r.json()
    for key in ["scan_id", "scanned_at", "hostname", "risk_score", "risk_category", "findings",
                "reputation", "skipped_checks", "explanation", "recommended_next_steps", "url_breakdown"]:
        assert key in d
    assert all(x["status"] == "not_checked" for x in d["reputation"])


def test_providers_endpoint_never_exposes_keys():
    r = client.get("/api/providers")
    assert r.status_code == 200
    assert r.json() == [{"name": "Google Safe Browsing", "configured": False}]


def test_unsupported_scheme_uses_error_format():
    r = client.post("/api/scan", json={"url": "javascript:alert(1)"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "unsupported_scheme"


def test_invalid_bodies():
    for body in [{}, {"url": ""}, {"url": 5}, {"url": "a" * 5000}]:
        r = client.post("/api/scan", json=body)
        assert r.status_code == 422 and r.json()["error"]["code"] in {"invalid_request", "empty_url", "url_too_long"}


def test_secrets_not_echoed():
    r = client.post("/api/scan", json={"url": "https://a.test/p?token=SECRET123&q=1#access_token=SECRET456"})
    assert r.status_code == 200
    assert "SECRET123" not in r.text and "SECRET456" not in r.text


def test_rate_limit():
    limiter.max_requests = 3
    try:
        codes = [client.post("/api/scan", json={"url": "https://a.test/"}).status_code for _ in range(5)]
    finally:
        limiter.max_requests = 30
    assert codes[:3] == [200, 200, 200] and codes[3] == 429


def test_oversized_body_rejected():
    r = client.post("/api/scan", content=b"x" * 20000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413
