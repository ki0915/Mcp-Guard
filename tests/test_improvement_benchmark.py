"""Freeze the public synthetic before/after benchmark claims in CI."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from dlp_proxy.detectors.engine import Scanner
from scripts.improvement_report import _contextual_rules, _evaluate

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "tests" / "data" / "evasion_benchmark.json"
EVIDENCE = ROOT / "docs" / "evidence" / "improvement-report.json"


def test_synthetic_evasion_benchmark_matches_published_claims() -> None:
    raw = DATASET.read_bytes()
    document = json.loads(raw.decode("utf-8"))
    assert document["synthetic_only"] is True
    assert len(document["cases"]) == 90

    baseline = _evaluate(Scanner(enable_transforms=False), document["cases"])
    enhanced = _evaluate(
        Scanner(_contextual_rules(), enable_transforms=True), document["cases"]
    )

    assert baseline["confusion_matrix"] == {"tp": 10, "fn": 50, "fp": 0, "tn": 30}
    assert enhanced["confusion_matrix"] == {"tp": 56, "fn": 4, "fp": 0, "tn": 30}
    assert enhanced["missed_case_ids"] == [
        "residual-double-base64",
        "residual-percent-body",
        "residual-slash-split",
        "residual-semantic-paraphrase",
    ]
    assert enhanced["by_category"]["base64"]["recall_percent"] == 100.0
    assert enhanced["by_category"]["contextual"]["recall_percent"] == 100.0
    assert enhanced["by_category"]["digit-split"]["recall_percent"] == 100.0
    assert enhanced["by_category"]["nfkc"]["recall_percent"] == 100.0


def test_published_evidence_is_bound_to_exact_dataset() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    assert evidence["dataset"]["sha256"] == hashlib.sha256(DATASET.read_bytes()).hexdigest()
    assert evidence["dataset"]["synthetic_only"] is True
    assert evidence["improvement"]["recall_percentage_points"] == 76.666
    assert evidence["improvement"]["false_positive_rate_percentage_points"] == 0.0
    assert evidence["scan_latency"]["raw_only_baseline"]["rounds"] == 200
    assert evidence["scan_latency"]["enhanced"]["samples"] == 18_000
