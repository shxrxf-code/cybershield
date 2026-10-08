#!/usr/bin/env python
"""Risk engine calibration harness.

Runs the labelled calibration set through the risk engine and prints where each
case lands, so tuning changes can be evaluated before they are committed. Also
reports separation metrics between the benign and malicious halves of the set.

Usage::

    python -m scripts.calibrate_risk            # from the backend directory
    python scripts/calibrate_risk.py --verbose
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection_engine.file.analyzer import analyse_file  # noqa: E402
from app.detection_engine.phishing.heuristics import analyse_text_content  # noqa: E402
from app.detection_engine.url.analyzer import analyse_url_structure  # noqa: E402
from app.detection_engine.url.parser import parse_url  # noqa: E402
from app.schemas.common import ObjectType, Verdict  # noqa: E402
from app.schemas.signal import SignalBundle  # noqa: E402
from app.services.risk_engine import assess_risk  # noqa: E402
from tests.calibration_set import ALL_CASES, VERDICT_ORDER, satisfies  # noqa: E402


def evaluate_case(case) -> tuple[int, float, float, Verdict, list[str]]:
    """Score one calibration case and return (rank, score, confidence, verdict, codes)."""
    payload = case.payload
    bundle = SignalBundle()

    if case.object_type == "URL":
        url = str(payload["url"])
        bundle.extend(analyse_url_structure(parse_url(url)))
        object_type = ObjectType.URL
    elif case.object_type == "TEXT":
        text = str(payload["text"])
        bundle.extend(analyse_text_content(text))
        object_type = ObjectType.TEXT
    else:
        data = payload.get("data", b"")
        result = analyse_file(data, filename=payload.get("filename"))
        bundle.extend(result.signals)
        object_type = ObjectType.FILE

    assessment = assess_risk(bundle, object_type=object_type)
    return (
        VERDICT_ORDER.index(assessment.verdict),
        assessment.score,
        assessment.confidence,
        assessment.verdict,
        bundle.codes(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true", help="list signal codes per case")
    args = parser.parse_args()

    print(f"{'case':<26} {'score':>6} {'conf':>6}  {'verdict':<11} result")
    print("-" * 78)

    failures: list[str] = []
    benign_scores: list[float] = []
    malicious_scores: list[float] = []
    confusions = {"false_positive": 0, "false_negative": 0}

    for case in ALL_CASES:
        rank, score, confidence, verdict, codes = evaluate_case(case)
        ok, reason = satisfies(case, verdict)

        is_benign = case.maximum_verdict in (Verdict.SAFE, Verdict.LOW_RISK)
        if is_benign:
            benign_scores.append(score)
            if verdict in (Verdict.HIGH_RISK, Verdict.MALICIOUS):
                confusions["false_positive"] += 1
        else:
            malicious_scores.append(score)
            if verdict is Verdict.SAFE:
                confusions["false_negative"] += 1

        status = "PASS" if ok else "FAIL"
        print(f"{case.name:<26} {score:>6.1f} {confidence:>6.2f}  {verdict.value:<11} {status}")
        if not ok:
            print(f"{'':<26} {reason}")
            failures.append(f"{case.name}: {reason}")
        if args.verbose:
            print(f"{'':<28}signals: {', '.join(codes) or '(none)'}")

    # ---- separation metrics ------------------------------------------
    benign_mean = sum(benign_scores) / len(benign_scores) if benign_scores else 0.0
    malicious_mean = sum(malicious_scores) / len(malicious_scores) if malicious_scores else 0.0
    benign_max = max(benign_scores, default=0.0)
    malicious_min = min(malicious_scores, default=100.0)

    print("-" * 78)
    print(f"cases:            {len(ALL_CASES)}")
    print(f"pass:             {len(ALL_CASES) - len(failures)}")
    print(f"fail:             {len(failures)}")
    print(f"benign mean:      {benign_mean:.1f}  (max {benign_max:.1f})")
    print(f"malicious mean:   {malicious_mean:.1f}  (min {malicious_min:.1f})")
    print(f"separation gap:   {malicious_min - benign_max:+.1f}")
    print(f"confusions:       {confusions}")
    print(
        f"worst-case FPR:   "
        f"{confusions['false_positive']}/{len(benign_scores)} "
        f"({100 * confusions['false_positive'] / max(1, len(benign_scores)):.1f}%)"
    )
    print(
        f"worst-case FNR:   "
        f"{confusions['false_negative']}/{len(malicious_scores)} "
        f"({100 * confusions['false_negative'] / max(1, len(malicious_scores)):.1f}%)"
    )

    if failures:
        print("\nFAILURES:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nAll calibration cases within expected bands.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())