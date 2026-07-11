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
