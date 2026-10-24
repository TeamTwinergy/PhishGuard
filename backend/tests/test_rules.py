from tests.helpers import analyze, rule_ids


def test_clean_url_has_no_findings():
    assert analyze("https://www.example.com/docs/start")[2] == []


def test_http_only_is_a_weak_signal():
    ids = rule_ids("http://www.example.com/")
    assert ids == {"no_https"}


def test_userinfo_trick():
    assert "userinfo_deceptive" in rule_ids("https://paypal.com@evil.test/")
    assert "userinfo_present" in rule_ids("https://bob@files.test/")


def test_ip_hosts():
    assert "ip_host" in rule_ids("http://203.0.113.7/")
    assert "ip_obfuscated" in rule_ids("http://2130706433/")


def test_brand_variants():
    cases = {
        "https://paypa1-secure-login.example.net/": "brand_homoglyph",
        "https://paypal.com.account-verify.example.net/": "brand_official_domain_embedded",
        "https://paypal-login.example.org/": "brand_in_unofficial_domain",
        "https://gooogle.example/": "brand_typosquat",
        "https://rnicrosoft.example/": "brand_homoglyph",
    }
    for url, expected in cases.items():
        assert expected in rule_ids(url), url


def test_brand_false_positive_guards():
    for url in ["https://www.paypal.com/signin", "https://accounts.google.com/",
                "https://pineapple.example/", "https://apply.example/", "https://www.amazon.in/",
                "https://docs.github.com/"]:
        ids = rule_ids(url)
        assert not {i for i in ids if i.startswith("brand_")}, (url, ids)


def test_idn_homograph_of_brand():
    ids = rule_ids("https://\u0430pple.example/")   # Cyrillic a + 'pple'
    assert "brand_idn_homograph" in ids and "idn_mixed_script" in ids


def test_punycode_alone_is_weak():
    ids = rule_ids("https://b\u00fccher.example/")
    assert ids == {"punycode"}


def test_shortener():
    assert "url_shortener" in rule_ids("https://bit.ly/abc")


def test_file_rules():
    assert "file_double_extension" in rule_ids("https://files.example/invoice.pdf.exe")
    assert "file_executable" in rule_ids("https://files.example/setup.exe")
    assert "file_archive" in rule_ids("https://files.example/a.zip")
    assert not {i for i in rule_ids("https://files.example/report.pdf") if i.startswith("file_")}


def test_ports():
    assert "unusual_port" in rule_ids("https://example.test:8081/")
    for u in ["https://example.test:8443/", "https://example.test:443/"]:
        assert "unusual_port" not in rule_ids(u)


def test_subdomain_depth():
    assert "excessive_subdomains" in rule_ids("https://a.b.c.d.example.com/")
    assert "excessive_subdomains" not in rule_ids("https://a.b.example.com/")


def test_keywords_tiers():
    assert "suspicious_keywords_one" in rule_ids("https://example.test/login")
    assert "suspicious_keywords_many" in rule_ids("https://example.test/secure/login/verify")


def test_encoding_rules():
    assert "suspicious_encoding" in rule_ids("https://example.test/%70%61%79%70%61%6c")
    assert "suspicious_encoding" in rule_ids("https://example.test/a%252e")
    # Legitimate percent-encoded Bengali must not be flagged.
    bn = "https://bn.wikipedia.org/wiki/%E0%A6%95%E0%A6%B2%E0%A6%95%E0%A6%BE%E0%A6%A4%E0%A6%BE"
    assert "suspicious_encoding" not in rule_ids(bn)


def test_https_observation_does_not_claim_trust():
    obs = {o.id: o for o in analyze("https://www.example.com/")[3]}
    assert "does not show" in obs["https"].detail
