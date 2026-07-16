"""Tests for the synthetic fixture admission control."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from scripts.verify_synthetic_fixtures import validate_manifest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "tests" / "data"


def _copy_data(tmp_path: Path) -> tuple[Path, Path]:
    data = tmp_path / "data"
    shutil.copytree(SOURCE, data)
    return data, data / "synthetic-manifest.json"


def test_repository_fixtures_pass_synthetic_guard() -> None:
    assert validate_manifest(SOURCE, SOURCE / "synthetic-manifest.json") == []


def test_guard_rejects_unreviewed_byte_change(tmp_path: Path) -> None:
    data, manifest = _copy_data(tmp_path)
    path = data / "benign_cases.json"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    errors = validate_manifest(data, manifest)

    assert any("SHA-256 mismatch" in error for error in errors)


def test_guard_rejects_unregistered_dataset(tmp_path: Path) -> None:
    data, manifest = _copy_data(tmp_path)
    (data / "copied-production-log.json").write_text("[]", encoding="utf-8")

    errors = validate_manifest(data, manifest)

    assert "unregistered fixture file: copied-production-log.json" in errors


def test_guard_rejects_sensitive_case_without_synthetic_marker(tmp_path: Path) -> None:
    data, manifest_path = _copy_data(tmp_path)
    fixture_path = data / "secret_cases.json"
    cases = json.loads(fixture_path.read_text(encoding="utf-8"))
    cases[0]["text"] = "api_key=Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
    fixture_path.write_text(json.dumps(cases), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        if entry["path"] == fixture_path.name:
            entry["sha256"] = hashlib.sha256(fixture_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    errors = validate_manifest(data, manifest_path)

    assert any("sensitive fixture lacks a visible synthetic marker" in error for error in errors)


def test_guard_rejects_synthetic_declaration_removed(tmp_path: Path) -> None:
    data, manifest_path = _copy_data(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["synthetic_only"] = False
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    errors = validate_manifest(data, manifest_path)

    assert "manifest synthetic_only must be true" in errors
