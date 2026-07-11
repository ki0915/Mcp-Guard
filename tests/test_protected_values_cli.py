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
