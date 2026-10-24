from app.config import parse_thresholds
from app.explanation import build_explanation
from app.risk_scorer import calculate_score, categorize
from app.rules_engine import Finding
from tests.helpers import analyze


def fnd(rule, group, weight):
    return Finding(rule, group, rule, "low", weight, "e", "w", "a")


def test_duplicate_groups_counted_once():
    r = calculate_score([fnd("a", "g", 40), fnd("b", "g", 35), fnd("c", "h", 10)])
    assert r.score == 50
    assert [b["counted"] for b in r.breakdown] == [True, False, True]


def test_score_capped_at_100():
    r = calculate_score([fnd(str(i), f"g{i}", 40) for i in range(5)])
    assert r.score == 100 and r.uncapped_total == 200


def test_threshold_boundaries():
    expect = {0: "Lower observed risk", 24: "Lower observed risk", 25: "Caution", 49: "Caution",
              50: "High concern", 74: "High concern", 75: "Very high concern", 100: "Very high concern"}
    for score, label in expect.items():
        assert categorize(score) == label, score


def test_threshold_parsing_falls_back_on_bad_input():
    assert parse_thresholds("10,20,30") == (10, 20, 30)
    for bad in ["50,25,75", "a,b,c", "1,2", "0,50,75", "25,50,101", None, ""]:
        assert parse_thresholds(bad) == (25, 50, 75), bad


def score_of(url):
    _, _, findings, _ = analyze(url)
    return calculate_score(findings)


def test_clean_url_scores_zero():
    assert score_of("https://www.example.com/").score == 0


def test_classic_at_trick_with_ip_is_very_high():
    r = score_of("http://paypal.com@203.0.113.7/login")
    assert r.category == "Very high concern"


def test_lookalike_login_is_at_least_high():
    assert score_of("https://paypal.com.account-verify.example.net/").score >= 50


def test_no_findings_explanation_avoids_safety_claim():
    _, _, findings, _ = analyze("https://www.example.com/")
    text = build_explanation(findings, calculate_score(findings))
    assert "not a guarantee" in text["summary"]
    assert any("No reputation provider" in l for l in text["limitations"])
