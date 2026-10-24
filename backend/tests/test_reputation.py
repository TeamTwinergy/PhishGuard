from app.reputation.base import ProviderResult
from app.reputation.safe_browsing import SafeBrowsingProvider
from app.scan_service import run_scan


def provider(post, key="k"):
    return SafeBrowsingProvider(api_key=key, http_post=post)


def test_missing_key_is_not_checked_and_sends_nothing():
    def boom(*a):
        raise AssertionError("no request should be sent without a key")
    r = provider(boom, key="").check("https://a.test/")
    assert r.status == "not_checked"


def test_no_match_and_match():
    assert provider(lambda *a: (200, {})).check("https://a.test/").status == "no_match"
    hit = provider(lambda *a: (200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})).check("https://a.test/")
    assert hit.status == "match" and hit.threat_types == ["SOCIAL_ENGINEERING"]


def test_failure_modes_are_distinguished():
    def timeout(*a):
        raise TimeoutError()
    def down(*a):
        raise ConnectionError("secret-key-xyz in message")
    assert provider(timeout).check("https://a.test/").status == "timeout"
    err = provider(down).check("https://a.test/")
    assert err.status == "error" and "secret-key-xyz" not in (err.detail or "")
    assert provider(lambda *a: (429, None)).check("https://a.test/").status == "rate_limited"
    assert provider(lambda *a: (403, {"error": {}})).check("https://a.test/").status == "error"


def test_key_sent_in_header_not_url():
    seen = {}
    def spy(url, headers, body, timeout):
        seen.update(url=url, headers=headers, body=body)
        return 200, {}
    provider(spy, key="KEY123").check("https://a.test/x")
    assert "KEY123" not in seen["url"] and seen["headers"]["X-Goog-Api-Key"] == "KEY123"


class FakeProvider:
    name = "Fake"
    def __init__(self, result): self.result = result
    def is_configured(self): return True
    def check(self, url):
        self.url = url
        return self.result


def test_reputation_match_raises_score_and_is_a_finding():
    fake = FakeProvider(ProviderResult("Fake", "match", "listed", ["MALWARE"]))
    d = run_scan("https://www.example.com/", providers=[fake])
    assert d["risk_score"] >= 75 and d["findings"][0]["rule_id"] == "reputation_match"
    assert d["reputation"][0]["status"] == "match"


def test_no_match_does_not_lower_score_or_claim_safety():
    d = run_scan("http://203.0.113.7/login", providers=[FakeProvider(ProviderResult("Fake", "no_match"))])
    base = run_scan("http://203.0.113.7/login", providers=[])
    assert d["risk_score"] == base["risk_score"]
    assert any("only means" in l for l in d["explanation"]["limitations"])


def test_provider_exception_becomes_error_result():
    class Broken(FakeProvider):
        def check(self, url): raise RuntimeError("x")
    d = run_scan("https://a.test/", providers=[Broken(None)])
    assert d["reputation"][0]["status"] == "error"


def test_lookup_url_excludes_userinfo_and_fragment():
    fake = FakeProvider(ProviderResult("Fake", "no_match"))
    run_scan("https://user:pw@a.test/p?q=1#frag", providers=[fake])
    assert fake.url == "https://a.test/p?q=1"
