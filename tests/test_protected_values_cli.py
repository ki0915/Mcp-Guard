"""Safe local protected-value registration with synthetic values only."""

from __future__ import annotations

import argparse
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from dlp_proxy import policy
from scripts.protected_values_cli import (
    REPO_ROOT,
    add_allowlist_entry,
    add_entry,
    allowlist_entry,
    literal_entry,
    probe_value,
    remove_record,
    safe_inventory,
    token_entry,
)


def _args(rule_id: str) -> argparse.Namespace:
    return argparse.Namespace(
        id=rule_id,
        action="block",
        direction=["request", "response"],
        method=["post"],
        path_prefix=["/v1"],
    )


def test_add_literal_creates_valid_atomic_document(tmp_path: Path) -> None:
    raw = "SYNTH-ORION-ALPHA-7Q9X"
    target = tmp_path / "protected.yaml"
    add_entry(
        target,
        literal_entry(_args("project-code"), raw),
        allow_repository_path=True,
    )
    loaded = policy.load("configs/policy.yaml", str(target))
    assert loaded.safe_summary()["protected_values"] == 1
    document = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert document["protected_values"][0]["literal"] == raw


def test_add_token_stores_only_digest_and_length(tmp_path: Path) -> None:
    raw = "SYNTHETIC_TOKEN_7Q9X2M4P8N6K"
    target = tmp_path / "protected.yaml"
    add_entry(
        target,
        token_entry(_args("deploy-token"), raw),
        allow_repository_path=True,
    )
    serialized = target.read_text(encoding="utf-8")
    assert raw not in serialized
    assert hashlib.sha256(raw.encode()).hexdigest() in serialized
    assert f"length: {len(raw)}" in serialized


def test_repository_path_is_rejected_by_default() -> None:
    target = REPO_ROOT / "configs" / "must-not-be-created.yaml"
    with pytest.raises(ValueError, match="inside the repository"):
        add_entry(target, literal_entry(_args("blocked"), "SYNTHETIC-VALUE"))
    assert not target.exists()


def test_duplicate_rule_does_not_replace_valid_file(tmp_path: Path) -> None:
    target = tmp_path / "protected.yaml"
    entry = literal_entry(_args("duplicate"), "SYNTHETIC-VALUE-ONE")
    add_entry(target, entry, allow_repository_path=True)
    before = target.read_bytes()
    with pytest.raises(ValueError, match="duplicated"):
        add_entry(target, entry, allow_repository_path=True)
    assert target.read_bytes() == before


def test_add_allowlist_stores_hash_and_required_scope(tmp_path: Path) -> None:
    raw = "010-0000-0000"
    args = argparse.Namespace(
        id="synthetic-phone",
        reason="synthetic fixture",
        expires_at=(datetime.now(UTC) + timedelta(days=1)).isoformat(),
        target=["phone-mobile"],
        direction=["request"],
        method=["post"],
        path_prefix=["/demo"],
    )
    target = tmp_path / "protected.yaml"
    add_allowlist_entry(
        target,
        allowlist_entry(args, raw),
        allow_repository_path=True,
    )
    serialized = target.read_text(encoding="utf-8")
    assert raw not in serialized
    assert hashlib.sha256(raw.encode()).hexdigest() in serialized
    loaded = policy.load("configs/policy.yaml", str(target))
    assert loaded.safe_summary()["allowlist_active"] == 1


def test_safe_inventory_never_returns_literal_or_digest(tmp_path: Path) -> None:
    raw = "SYNTH-REGISTRY-INVENTORY-7Q9X"
    target = tmp_path / "protected.yaml"
    add_entry(
        target,
        literal_entry(_args("inventory-item"), raw),
        allow_repository_path=True,
    )

    inventory = safe_inventory(target)
    serialized = yaml.safe_dump(inventory, allow_unicode=True)

    assert inventory["summary"]["protected_values"] == 1
    assert inventory["protected_values"] == [
        {
            "id": "inventory-item",
            "action": "block",
            "match_type": "literal",
            "directions": ["request", "response"],
            "method_count": 1,
            "path_prefix_count": 1,
        }
    ]
    assert raw not in serialized
    assert hashlib.sha256(raw.encode()).hexdigest() not in serialized


def test_remove_is_exact_validated_and_does_not_damage_file(tmp_path: Path) -> None:
    target = tmp_path / "protected.yaml"
    add_entry(
        target,
        literal_entry(_args("remove-me"), "SYNTH-REMOVE-ME-7Q9X"),
        allow_repository_path=True,
    )
    add_entry(
        target,
        literal_entry(_args("keep-me"), "SYNTH-KEEP-ME-7Q9X"),
        allow_repository_path=True,
    )

    remove_record(
        target,
        "protected_values",
        "remove-me",
        allow_repository_path=True,
    )
    document = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert [entry["id"] for entry in document["protected_values"]] == ["keep-me"]

    before = target.read_bytes()
    with pytest.raises(ValueError, match="not found exactly once"):
        remove_record(
            target,
            "protected_values",
            "missing",
            allow_repository_path=True,
        )
    assert target.read_bytes() == before


def test_hidden_probe_returns_only_safe_decision_metadata(tmp_path: Path) -> None:
    raw = "SYNTH-PROBE-BLOCK-7Q9X"
    target = tmp_path / "protected.yaml"
    add_entry(
        target,
        literal_entry(_args("probe-item"), raw),
        allow_repository_path=True,
    )

    result = probe_value(
        raw,
        policy_path=Path("configs/policy.yaml"),
        protected_path=target,
        direction="request",
        method="POST",
        path="/v1/chat",
    )
    serialized = yaml.safe_dump(result)

    assert result == {
        "decision": "block",
        "finding_count": 1,
        "actions": {"block": 1},
        "kinds": {"confidential": 1},
        "scan_enabled": True,
    }
    assert raw not in serialized
    assert "probe-item" not in serialized


def test_probe_reflects_disabled_scan_and_oversize_controls(tmp_path: Path) -> None:
    config = yaml.safe_load(Path("configs/policy.yaml").read_text(encoding="utf-8"))
    config["scan"]["request"] = False
    disabled_path = tmp_path / "disabled-policy.yaml"
    disabled_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    disabled = probe_value(
        "SYNTH-PROBE-DISABLED-7Q9X",
        policy_path=disabled_path,
        protected_path=None,
        direction="request",
        method="POST",
        path="/v1/chat",
    )
    assert disabled["decision"] == "allow"
    assert disabled["scan_enabled"] is False

    config["scan"]["request"] = True
    config["scan"]["max_body_bytes"] = 8
    oversize_path = tmp_path / "oversize-policy.yaml"
    oversize_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    oversize = probe_value(
        "SYNTH-PROBE-OVERSIZE-7Q9X",
        policy_path=oversize_path,
        protected_path=None,
        direction="request",
        method="POST",
        path="/v1/chat",
    )
    assert oversize == {
        "decision": "block",
        "finding_count": 0,
        "actions": {"block": 1},
        "kinds": {"oversize_control": 1},
        "scan_enabled": True,
    }
