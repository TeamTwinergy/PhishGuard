"""Evaluate the heuristic scanner on eval/dataset.csv (no network, no providers).

    python eval/run_eval.py [--threshold 25]

A URL counts as FLAGGED when score >= threshold. Positive class = suspicious.
IMPORTANT: this dataset is small, hand-written by the developers and aligned with the
rules, so the numbers are a regression check, NOT evidence of real-world accuracy.
"""
import argparse
import csv
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.feature_extractor import extract_features  # noqa: E402
from app.risk_scorer import calculate_score  # noqa: E402
from app.rules_engine import evaluate  # noqa: E402
from app.url_parser import parse_url  # noqa: E402


def score(url: str) -> int:
    p = parse_url(url)
    findings, _ = evaluate(p, extract_features(p))
    return calculate_score(findings).score


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, default=25)
    ap.add_argument("--data", default=str(pathlib.Path(__file__).with_name("dataset.csv")))
    args = ap.parse_args()

    tp = fp = tn = fn = 0
    wrong = []
    with open(args.data, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            s = score(row["url"])
            flagged = s >= args.threshold
            positive = row["label"] == "suspicious"
            if positive and flagged: tp += 1
            elif positive: fn += 1; wrong.append(("MISSED", s, row["url"], row["note"]))
            elif flagged: fp += 1; wrong.append(("FALSE ALARM", s, row["url"], row["note"]))
            else: tn += 1
    div = lambda a, b: (a / b) if b else float("nan")
    print(f"threshold={args.threshold}  n={tp+fp+tn+fn}  suspicious={tp+fn}  benign={tn+fp}")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"precision={div(tp, tp+fp):.2f} recall={div(tp, tp+fn):.2f} "
          f"false_positive_rate={div(fp, fp+tn):.2f} false_negative_rate={div(fn, fn+tp):.2f}")
    for kind, s, url, note in wrong:
        print(f"  {kind}: score={s} {url}  ({note})")


if __name__ == "__main__":
    main()
