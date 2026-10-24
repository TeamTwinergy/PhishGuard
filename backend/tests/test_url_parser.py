import pytest

from app.url_parser import InvalidURLError, parse_url


def code_of(url):
    with pytest.raises(InvalidURLError) as e:
        parse_url(url)
    return e.value.code


def test_basic_https_url():
    p = parse_url("https://www.example.com/a/b?x=1#top")
    assert (p.scheme, p.hostname, p.path) == ("https", "www.example.com", "/a/b")
    assert p.registered_domain == "example.com" and p.subdomains == ["www"]
    assert p.fragment == "top" and not p.scheme_assumed


def test_scheme_assumed_when_missing():
    p = parse_url("example.com/login")
    assert p.scheme == "https" and p.scheme_assumed and p.normalization_notes
    q = parse_url("example.com:8080/x")
    assert q.hostname == "example.com" and q.port == 8080


def test_unsupported_schemes_rejected():
    for u in ["javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd",
              "ftp://files.example.test/x", "mailto:a@b.test"]:
        assert code_of(u) == "unsupported_scheme", u


def test_empty_whitespace_and_control_chars():
    assert code_of("") == "empty_url"
    assert code_of("   ") == "empty_url"
    assert code_of("https://a.test/\x00") == "control_characters"
    assert code_of("https://a.test/a b") == "whitespace_in_url"


def test_too_long_rejected():
    assert code_of("https://a.test/" + "a" * 5000) == "url_too_long"


def test_userinfo_trick_uses_host_after_at():
    p = parse_url("https://paypal.com@evil.test/login")
    assert p.hostname == "evil.test" and p.has_userinfo and p.username == "paypal.com"


def test_password_never_in_redacted_url():
    p = parse_url("https://user:hunter2@a.test/")
    assert "hunter2" not in p.redacted_url and "user" not in p.redacted_url.split("@")[0].replace("[userinfo hidden]", "")


def test_ip_forms():
    assert parse_url("http://203.0.113.7/").is_ip
    v6 = parse_url("http://[2001:db8::1]:8080/")
    assert v6.is_ip and v6.port == 8080
    o = parse_url("http://2130706433/")
    assert o.is_ip and o.ip_obfuscated and o.ip_address == "127.0.0.1"
    assert parse_url("http://0x7f.0.0.1/").ip_address == "127.0.0.1"
    assert parse_url("http://127.1/").ip_obfuscated


def test_ports():
    assert code_of("https://a.test:99999/") == "invalid_port"
    assert code_of("https://a.test:abc/") == "invalid_port"
    assert parse_url("https://a.test:/").port is None


def test_idn_and_punycode():
    p = parse_url("https://b\u00fccher.example/")
    assert p.hostname == "xn--bcher-kva.example" and p.hostname_unicode == "b\u00fccher.example"
    q = parse_url("https://xn--bcher-kva.example/")
    assert q.hostname_unicode == "b\u00fccher.example"


def test_backslash_normalized():
    # Browsers read '\\' as '/', so the real host is evil.test, not paypal.com.
    p = parse_url("https://evil.test\\@paypal.com/")
    assert p.hostname == "evil.test"
    assert any("Backslash" in n for n in p.normalization_notes)


def test_query_redaction():
    p = parse_url("https://a.test/p?token=abc123&q=hello&session=zzz&email=me@x.com")
    vals = {q.name: q.value for q in p.query_params}
    assert vals["token"] == vals["session"] == vals["email"] == "[redacted]"
    assert vals["q"] == "hello"
    assert "abc123" not in p.redacted_url and "me@x.com" not in p.redacted_url


def test_fragment_redaction():
    assert parse_url("https://a.test/#access_token=abc").fragment == "[redacted]"
    assert parse_url("https://a.test/#section-2").fragment == "section-2"


def test_registered_domain_heuristic():
    p = parse_url("https://a.b.example.co.uk/")
    assert p.registered_domain == "example.co.uk" and p.subdomains == ["a", "b"]


def test_case_and_trailing_dot():
    assert parse_url("HTTPS://WWW.Example.COM./").hostname == "www.example.com"


def test_invalid_hosts():
    assert code_of("https://exa<mple.test/") == "invalid_host_characters"
    assert code_of("https://a..test/") == "malformed_host"
    assert code_of("https:///nohost") == "missing_host"
    assert code_of("https://" + "a" * 64 + ".test/") == "label_too_long"
