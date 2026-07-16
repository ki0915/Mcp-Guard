"""Policy loading and action resolution tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from dlp_proxy import policy as policy_mod
from dlp_proxy.detectors import Finding


def _finding(kind: str, rule: str) -> Finding:
    return Finding(kind=kind, start=0, end=1, rule=rule, sample="a****")


def test_load_default_policy() -> None:
    pol = policy_mod.load("configs/policy.yaml")
    assert pol.kind_actions["rrn"] == "block"
    assert pol.kind_actions["phone"] == "redact"
    assert pol.default_action == "alert"
    assert pol.sse_mode == "buffer"


def test_rule_override_beats_kind() -> None:
    pol = policy_mod.load("configs/policy.yaml")
    assert pol.action_for(_finding("rrn", "rrn-checksum")) == "block"
    assert pol.action_for(_finding("rrn", "rrn-format-only")) == "alert"


def test_unknown_kind_gets_default() -> None:
    pol = policy_mod.Policy(default_action="alert")
    assert pol.action_for(_finding("newkind", "newrule")) == "alert"


def test_programmatic_policy_defaults_protect_sensitive_kinds() -> None:
    pol = policy_mod.Policy()
    assert pol.action_for(_finding("rrn", "rrn-checksum")) == "block"
    assert pol.action_for(_finding("card", "card-luhn")) == "block"
    assert pol.action_for(_finding("secret", "generic-high-entropy")) == "block"


def test_invalid_action_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    data = yaml.safe_load(Path("configs/policy.yaml").read_text(encoding="utf-8"))
    data["rules"]["rrn"] = "explode"
    bad.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid action"):
        policy_mod.load(str(bad))


def test_invalid_sse_mode_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad-sse.yaml"
    data = yaml.safe_load(Path("configs/policy.yaml").read_text(encoding="utf-8"))
    data["scan"]["sse_mode"] = "unsafe-stream"
    bad.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError, match="sse_mode must be buffer or event"):
        policy_mod.load(str(bad))


@pytest.mark.parametrize("kind", ["rrn", "card", "secret"])
def test_sensitive_kind_cannot_forward_raw_text(tmp_path: Path, kind: str) -> None:
    data = yaml.safe_load(Path("configs/policy.yaml").read_text(encoding="utf-8"))
    data["rules"][kind] = "alert"
    path = tmp_path / f"unsafe-{kind}.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ValueError, match=rf"rules\.{kind} must be block or redact"):
        policy_mod.load(str(path))


@pytest.mark.parametrize("rule", ["rrn-checksum", "card-luhn", "aws-access-key"])
def test_sensitive_rule_override_cannot_forward_raw_text(
    tmp_path: Path, rule: str
) -> None:
    data = yaml.safe_load(Path("configs/policy.yaml").read_text(encoding="utf-8"))
    data["rule_overrides"][rule] = "alert"
    path = tmp_path / "unsafe-rule-override.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ValueError, match=rf"rule_overrides\.{rule} must be block or redact"):
        policy_mod.load(str(path))


def test_unknown_rule_override_is_rejected_as_a_probable_typo(tmp_path: Path) -> None:
    data = yaml.safe_load(Path("configs/policy.yaml").read_text(encoding="utf-8"))
    data["rule_overrides"]["aws-access-kye"] = "block"
    path = tmp_path / "unknown-rule-override.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ValueError, match="known built-in detector rule"):
        policy_mod.load(str(path))


def test_safe_summary_reports_hardened_and_degraded_posture() -> None:
    hardened = policy_mod.load("configs/policy.yaml").safe_summary()
    assert hardened["posture"] == "hardened"
    assert hardened["fail_open_controls"] == []

    degraded = policy_mod.Policy(
        scan_response=False,
        oversize_action="alert",
        kind_actions={"rrn": "alert", "card": "block", "secret": "block"},
    ).safe_summary()
    assert degraded["posture"] == "degraded"
    assert degraded["fail_open_controls"] == [
        "oversize_alert",
        "response_scan_disabled",
        "sensitive_kind_forwarding",
    ]
