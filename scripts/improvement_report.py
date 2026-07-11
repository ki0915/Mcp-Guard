"""Measure the raw-only baseline against the enhanced synthetic DLP corpus.

The JSON emitted to stdout contains no case text or matched value.  It is safe
to archive as public evidence after reviewing case IDs and environment fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import sys
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dlp_proxy.custom_rules import compile_custom_rules  # noqa: E402
from dlp_proxy.detectors.engine import Scanner  # noqa: E402
from dlp_proxy.policy import VALID_ACTIONS  # noqa: E402

DEFAULT_DATASET = ROOT / "tests" / "data" / "evasion_benchmark.json"


def _contextual_rules():
    return compile_custom_rules(
        [
            {
                "id": "merger-context",
                "kind": "confidential",
                "action": "block",
                "matcher": {
                    "type": "contextual",
                    "groups": [
                        ["인수계획", "합병검토", "acquisition", "merger"],
                        ["후보대상", "검토대상", "target", "candidate"],
                        ["대상회사", "후보기업", "company", "vendor"],
                    ],
                    "window_chars": 160,
                    "ignore_case": True,
                },
            },
            {
                "id": "roadmap-context",
                "kind": "confidential",
                "action": "block",
                "matcher": {
                    "type": "contextual",
                    "groups": [
                        ["출시계획", "배포일정", "launch", "release"],
                        ["미공개정보", "사전공개금지", "embargoed", "unannounced"],
                        ["신제품명", "프로젝트명", "product", "project"],
                    ],
                    "window_chars": 160,
                    "ignore_case": True,
                },
            },
        ],
        VALID_ACTIONS,
    )


def _expected_match(case: dict[str, Any], findings: list[Any]) -> bool:
    kinds = set(case.get("expect_kinds", ()))
    rules = set(case.get("expect_rules", ()))
    return any(finding.kind in kinds or finding.rule in rules for finding in findings)


def _evaluate(scanner: Scanner, cases: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    missed: list[str] = []
    false_positive: list[str] = []
    unexpected_only: list[str] = []
    category_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"positive": 0, "detected": 0, "benign": 0, "false_positive": 0}
    )
    for case in cases:
        findings = scanner.scan(case["text"])
        bucket = category_counts[case["category"]]
        if case["label"] == "sensitive":
            bucket["positive"] += 1
            matched = _expected_match(case, findings)
            if matched:
                tp += 1
                bucket["detected"] += 1
            else:
                fn += 1
                missed.append(case["id"])
                if findings:
                    unexpected_only.append(case["id"])
        else:
            bucket["benign"] += 1
            if findings:
                fp += 1
                bucket["false_positive"] += 1
                false_positive.append(case["id"])
            else:
                tn += 1

    by_category: dict[str, dict[str, int | float | None]] = {}
    for category, counts in sorted(category_counts.items()):
        positive = counts["positive"]
        benign = counts["benign"]
        by_category[category] = {
            **counts,
            "recall_percent": _percent(counts["detected"], positive),
            "false_positive_rate_percent": _percent(counts["false_positive"], benign),
        }
    return {
        "confusion_matrix": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "positive_cases": tp + fn,
        "benign_cases": fp + tn,
        "recall_percent": _percent(tp, tp + fn),
        "false_positive_rate_percent": _percent(fp, fp + tn),
        "missed_case_ids": missed,
        "false_positive_case_ids": false_positive,
        "unexpected_finding_only_case_ids": unexpected_only,
        "by_category": by_category,
    }


def _latency(
    baseline: Scanner,
    enhanced: Scanner,
    cases: list[dict[str, Any]],
    rounds: int,
) -> dict[str, Any]:
    for scanner in (baseline, enhanced):
        for case in cases:
            scanner.scan(case["text"])

    samples: dict[str, list[int]] = {"raw_only_baseline": [], "enhanced": []}
    for round_index in range(rounds):
        order = (
            (("raw_only_baseline", baseline), ("enhanced", enhanced))
            if round_index % 2 == 0
            else (("enhanced", enhanced), ("raw_only_baseline", baseline))
        )
        for name, scanner in order:
            for case in cases:
                started = time.perf_counter_ns()
                scanner.scan(case["text"])
                samples[name].append(time.perf_counter_ns() - started)

    result = {
        name: _latency_summary(values, rounds, len(cases))
        for name, values in samples.items()
    }
    result["delta_ms"] = {
        metric: round(result["enhanced"][metric] - result["raw_only_baseline"][metric], 6)
        for metric in ("mean_ms", "p50_ms", "p95_ms", "p99_ms")
    }
    return result


def _latency_summary(values_ns: list[int], rounds: int, case_count: int) -> dict[str, Any]:
    values_ms = sorted(value / 1_000_000 for value in values_ns)
    return {
        "samples": len(values_ms),
        "rounds": rounds,
        "cases_per_round": case_count,
        "mean_ms": round(statistics.fmean(values_ms), 6),
        "p50_ms": round(_nearest_rank(values_ms, 0.50), 6),
        "p95_ms": round(_nearest_rank(values_ms, 0.95), 6),
        "p99_ms": round(_nearest_rank(values_ms, 0.99), 6),
    }


def _nearest_rank(values: list[float], quantile: float) -> float:
    return values[max(0, math.ceil(quantile * len(values)) - 1)]


def _percent(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(100.0 * numerator / denominator, 3)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--rounds", type=int, default=200)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 10_000:
        parser.error("--rounds must be between 1 and 10000")

    raw = args.dataset.read_bytes()
    document = json.loads(raw.decode("utf-8"))
    if document.get("synthetic_only") is not True:
        raise ValueError("benchmark dataset must declare synthetic_only=true")
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("benchmark dataset has no cases")
    ids = [case.get("id") for case in cases]
    if len(set(ids)) != len(ids):
        raise ValueError("benchmark dataset contains duplicate case IDs")

    baseline = Scanner(enable_transforms=False)
    enhanced = Scanner(_contextual_rules(), enable_transforms=True)
    baseline_result = _evaluate(baseline, cases)
    enhanced_result = _evaluate(enhanced, cases)
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset": {
            "path": str(args.dataset.relative_to(ROOT)).replace("\\", "/"),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "synthetic_only": True,
            "cases": len(cases),
            "positive_cases": sum(case["label"] == "sensitive" for case in cases),
            "benign_cases": sum(case["label"] == "benign" for case in cases),
        },
        "scope": {
            "baseline": "built-in detectors on raw text only; no transforms or contextual rules",
            "enhanced": (
                "built-ins plus NFKC, digit compaction, one-pass Base64 "
                "and 2 contextual rules"
            ),
            "metric_unit": "case-level expected-detector match",
        },
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "raw_only_baseline": baseline_result,
        "enhanced": enhanced_result,
        "improvement": {
            "recall_percentage_points": round(
                enhanced_result["recall_percent"] - baseline_result["recall_percent"], 3
            ),
            "false_positive_rate_percentage_points": round(
                enhanced_result["false_positive_rate_percent"]
                - baseline_result["false_positive_rate_percent"],
                3,
            ),
        },
        "scan_latency": _latency(baseline, enhanced, cases, args.rounds),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
