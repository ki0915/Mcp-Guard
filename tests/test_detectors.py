"""Case-driven detector tests: every fixture case must match its expectation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dlp_proxy.detectors import engine

DATA = Path(__file__).parent / "data"


def load_cases(name: str) -> list[dict]:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


ALL_CASES = load_cases("pii_cases.json") + load_cases("secret_cases.json") + load_cases(
    "benign_cases.json"
)


@pytest.mark.parametrize("case", ALL_CASES, ids=lambda c: c["id"])
def test_case(case: dict) -> None:
    findings = engine.scan(case["text"])
    got_kinds = {f.kind for f in findings}
    expected = set(case["expect_kinds"])
    assert expected <= got_kinds, (
        f"{case['id']}: expected kinds {expected}, got {got_kinds} "
        f"(rules: {[f.rule for f in findings]})"
    )
    if not expected:
        assert not findings, (
            f"{case['id']}: expected no findings, got "
            f"{[(f.kind, f.rule) for f in findings]}"
        )
    for rule in case.get("expect_rules", []):
        assert rule in {f.rule for f in findings}, (
            f"{case['id']}: expected rule {rule}, got {[f.rule for f in findings]}"
        )


def test_samples_are_masked() -> None:
    findings = engine.scan("합성 주민번호 800101-1000008 테스트 카드 4111111111111111")
    for f in findings:
        assert f.sample == "***"
        assert "800101-1000008" not in f.sample
        assert "4111111111111111" not in f.sample
