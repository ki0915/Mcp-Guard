"""Measure detection rate and false-positive rate over the fixture sets.

Prints a markdown table for the README. Run: python scripts/accuracy_report.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dlp_proxy.detectors import engine  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "tests" / "data"


def run_set(name: str) -> tuple[int, int, list[str]]:
    """Return (passed, total, failed_ids) for one fixture file."""
    cases = json.loads((DATA / name).read_text(encoding="utf-8"))
    passed = 0
    failed: list[str] = []
    for case in cases:
        findings = engine.scan(case["text"])
        got_kinds = {f.kind for f in findings}
        got_rules = {f.rule for f in findings}
        expected = set(case["expect_kinds"])
        ok = expected <= got_kinds
        if not expected:
            ok = not findings
        for rule in case.get("expect_rules", []):
            ok = ok and rule in got_rules
        if ok:
            passed += 1
        else:
            failed.append(case["id"])
    return passed, len(cases), failed


def main() -> int:
    rows = []
    all_ok = True
    for name, label in [
        ("pii_cases.json", "한국 PII (positive+negative controls)"),
        ("secret_cases.json", "시크릿 (positive+negative controls)"),
        ("benign_cases.json", "정상 텍스트 (false-positive set)"),
    ]:
        passed, total, failed = run_set(name)
        pct = 100.0 * passed / total
        rows.append((label, passed, total, pct, failed))
        if failed:
            all_ok = False

    print("| 테스트셋 | 통과 | 전체 | 정확도 |")
    print("|---|---|---|---|")
    for label, passed, total, pct, _failed in rows:
        print(f"| {label} | {passed} | {total} | {pct:.1f}% |")
    print()
    for label, _p, _t, _pct, failed in rows:
        if failed:
            print(f"FAILED in {label}: {failed}")

    # Headline numbers: detection rate over positive cases only,
    # FP rate over the benign set.
    pii = json.loads((DATA / "pii_cases.json").read_text(encoding="utf-8"))
    sec = json.loads((DATA / "secret_cases.json").read_text(encoding="utf-8"))
    positives = [c for c in pii + sec if c["expect_kinds"]]
    detected = 0
    for c in positives:
        got = {f.kind for f in engine.scan(c["text"])}
        if set(c["expect_kinds"]) <= got:
            detected += 1
    benign = json.loads((DATA / "benign_cases.json").read_text(encoding="utf-8"))
    fp = sum(1 for c in benign if engine.scan(c["text"]))
    print()
    print(f"탐지율 (positive {len(positives)}건): {100.0 * detected / len(positives):.1f}%")
    print(f"오탐율 (benign {len(benign)}건): {100.0 * fp / len(benign):.1f}%")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
