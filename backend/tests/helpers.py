from app.feature_extractor import extract_features
from app.rules_engine import evaluate
from app.url_parser import parse_url


def analyze(url):
    p = parse_url(url)
    f = extract_features(p)
    findings, observations = evaluate(p, f)
    return p, f, findings, observations


def rule_ids(url):
    return {x.rule_id for x in analyze(url)[2]}
