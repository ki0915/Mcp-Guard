"""User-defined information, protected values, and policy safety guards."""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from dlp_proxy import policy
from dlp_proxy.custom_rules import compile_custom_rules, scan_rules
from dlp_proxy.detectors import Finding
from dlp_proxy.detectors.engine import Scanner


def _write_yaml(path: Path, value: dict) -> Path:
    path.write_text(yaml.safe_dump(value, allow_unicode=True), encoding="utf-8")
    return path


def _policy_data(**overrides) -> dict:
    value = {
        "version": 1,
        "strict_config": True,
        "upstream": "http://upstream.test",
        "default_action": "alert",
        "rules": {
            "phone": "redact",
            "rrn": "block",
            "card": "block",
            "secret": "block",
        },
        "rule_overrides": {"rrn-format-only": "alert"},
        "scan": {
            "request": True,
            "response": True,
            "max_body_bytes": 1_048_576,
            "oversize_action": "block",
            "unscannable_action": "block",
        },
        "expose_block_detail": False,
        "custom_regex_timeout_ms": 25,
        "custom_rules": [],
    }
    value.update(overrides)
    return value


def test_custom_literal_and_regex_are_scoped(tmp_path: Path) -> None:
    custom = [
        {
            "id": "project-code",
            "kind": "confidential",
            "action": "block",
            "scope": {
                "directions": ["request"],
                "methods": ["POST"],
                "path_prefixes": ["/v1/hr"],
            },
            "matcher": {
                "type": "literal",
                "values": ["SYNTH-ORION-ALPHA-7Q9X"],
            },
        },
        {
            "id": "employee-id",
            "kind": "business_identifier",
            "action": "redact",
            "scope": {"directions": ["response"]},
            "matcher": {"type": "regex", "pattern": r"\bEMP-[0-9]{8}\b"},
        },
    ]
    path = _write_yaml(tmp_path / "policy.yaml", _policy_data(custom_rules=custom))
    loaded = policy.load(str(path))
    scanner = Scanner(loaded.custom_rules, loaded.custom_regex_timeout_ms)

    findings = scanner.scan(
        "SYNTH-ORION-ALPHA-7Q9X",
        direction="request",
        method="POST",
        path="/v1/hr/export",
    )
    assert {finding.rule for finding in findings} == {"custom:project-code"}
    assert not scanner.scan(
        "SYNTH-ORION-ALPHA-7Q9X",
        direction="request",
        method="GET",
        path="/v1/hr/export",
    )
    assert not scanner.scan(
        "SYNTH-ORION-ALPHA-7Q9X",
        direction="request",
        method="POST",
        path="/v1/hr-old",
    )
    response = scanner.scan(
        "employee EMP-00000000",
        direction="response",
        method="POST",
        path="/v1/other",
    )
    assert {finding.rule for finding in response} == {"custom:employee-id"}

    isolated = Scanner()
    assert not isolated.scan(
        "SYNTH-ORION-ALPHA-7Q9X",
        direction="request",
        method="POST",
        path="/v1/hr/export",
    )


def test_protected_literal_and_bounded_sha256_token(tmp_path: Path) -> None:
    token = "SYNTHETIC_TOKEN_7Q9X2M4P8N6K"
    secret = {
        "version": 1,
        "protected_values": [
            {
                "id": "project-code",
                "action": "block",
                "literal": "SYNTH-ORION-ALPHA-7Q9X",
            },
            {
                "id": "deploy-token",
                "action": "block",
                "sha256": hashlib.sha256(token.encode()).hexdigest(),
                "token": {"charset": "ascii_token", "length": len(token)},
            },
        ],
        "allowlist": [],
    }
    protected_path = _write_yaml(tmp_path / "protected.yaml", secret)
    loaded = policy.load("configs/policy.yaml", str(protected_path))
    scanner = Scanner(loaded.custom_rules, loaded.custom_regex_timeout_ms)
    text = f"code SYNTH-ORION-ALPHA-7Q9X token {token}"
    findings = scanner.scan(text, direction="request", method="POST", path="/v1/")
    assert {finding.rule for finding in findings} == {
        "protected:project-code",
        "protected:deploy-token",
    }
    assert all(finding.sample == "***" for finding in findings)
    assert not scanner.scan(
        f"prefix{token}suffix", direction="request", method="POST", path="/v1/"
    )
    serialized = repr(loaded) + json.dumps(loaded.safe_summary())
    assert "SYNTH-ORION" not in serialized
    assert token not in serialized
    assert secret["protected_values"][1]["sha256"] not in serialized


def test_example_protected_values_file_is_valid() -> None:
    loaded = policy.load(
        "configs/policy.yaml", "configs/protected-values.example.yaml"
    )
    assert loaded.safe_summary()["protected_values"] == 2


@pytest.mark.parametrize(
    "mutator,match",
    [
        (lambda data: data.update({"unexpected": True}), "unsupported option"),
        (lambda data: data["scan"].update({"request": "false"}), "must be a boolean"),
        (lambda data: data["scan"].update({"max_body_bytes": -1}), "between 1"),
        (lambda data: data.update({"custom_regex_timeout_ms": 0}), "between 1"),
    ],
)
def test_strict_policy_rejects_unsafe_values(tmp_path: Path, mutator, match: str) -> None:
    data = _policy_data()
    mutator(data)
    path = _write_yaml(tmp_path / "bad.yaml", data)
    with pytest.raises(ValueError, match=match):
        policy.load(str(path))


def test_missing_explicit_files_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="policy file is missing"):
        policy.load(str(tmp_path / "missing-policy.yaml"))
    with pytest.raises(FileNotFoundError, match="protected values file is missing"):
        policy.load("configs/policy.yaml", str(tmp_path / "missing-protected.yaml"))


def test_invalid_matchers_do_not_echo_sensitive_material(tmp_path: Path) -> None:
    raw = _policy_data(
        custom_rules=[
            {
                "id": "bad-regex",
                "action": "block",
                "matcher": {"type": "regex", "pattern": "SECRET-SYNTH-("},
            }
        ]
    )
    path = _write_yaml(tmp_path / "bad.yaml", raw)
    with pytest.raises(ValueError) as caught:
        policy.load(str(path))
    assert "SECRET-SYNTH" not in str(caught.value)


def test_zero_width_and_timeout_rules_fail_closed() -> None:
    with pytest.raises(ValueError, match="must not match empty"):
        compile_custom_rules(
            [
                {
                    "id": "empty",
                    "action": "block",
                    "matcher": {"type": "regex", "pattern": "a*"},
                }
            ],
            policy.VALID_ACTIONS,
        )

    rules = compile_custom_rules(
        [
            {
                "id": "bounded",
                "action": "alert",
                "matcher": {"type": "regex", "pattern": "^(a+)+$"},
            }
        ],
        policy.VALID_ACTIONS,
    )
    started = time.perf_counter()
    findings = scan_rules(
        "a" * 100_000 + "!",
        rules,
        direction="request",
        method="POST",
        path="/",
        timeout_ms=1,
    )
    assert time.perf_counter() - started < 1.0
    assert any(finding.kind == "policy_error" for finding in findings)


def test_allowlist_is_exact_scoped_expiring_and_not_for_protected_kinds(
    tmp_path: Path,
) -> None:
    raw = "010-0000-0000"
    secret = {
        "version": 1,
        "protected_values": [],
        "allowlist": [
            {
                "id": "synthetic-demo-phone",
                "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "reason": "synthetic demo fixture",
                "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
                "targets": ["phone-mobile"],
                "scope": {
                    "directions": ["request"],
                    "methods": ["POST"],
                    "path_prefixes": ["/demo"],
                },
            }
        ],
    }
    protected_path = _write_yaml(tmp_path / "protected.yaml", secret)
    loaded = policy.load("configs/policy.yaml", str(protected_path))
    phone = Finding("phone", 0, len(raw), "phone-mobile", "***")
    assert loaded.allow_for(
        raw, phone, direction="request", method="POST", path="/demo/chat"
    )
    assert not loaded.allow_for(
        raw, phone, direction="response", method="POST", path="/demo/chat"
    )
    assert not loaded.allow_for(
        raw, phone, direction="request", method="GET", path="/demo/chat"
    )
    assert not loaded.allow_for(
        raw, phone, direction="request", method="POST", path="/demo-old"
    )
    rrn = Finding("rrn", 0, len(raw), "phone-mobile", "***")
    assert not loaded.allow_for(
        raw, rrn, direction="request", method="POST", path="/demo/chat"
    )


@pytest.mark.parametrize("missing", ["directions", "methods", "path_prefixes"])
def test_allowlist_requires_every_narrow_scope_dimension(
    tmp_path: Path, missing: str
) -> None:
    raw = "010-0000-0000"
    scope = {
        "directions": ["request"],
        "methods": ["POST"],
        "path_prefixes": ["/demo"],
    }
    scope.pop(missing)
    path = _write_yaml(
        tmp_path / f"missing-{missing}.yaml",
        {
            "version": 1,
            "protected_values": [],
            "allowlist": [
                {
                    "id": "incomplete-scope",
                    "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                    "reason": "synthetic invalid fixture",
                    "expires_at": (
                        datetime.now(UTC) + timedelta(days=1)
                    ).isoformat(),
                    "targets": ["phone-mobile"],
                    "scope": scope,
                }
            ],
        },
    )
    with pytest.raises(ValueError, match="scope must include"):
        policy.load("configs/policy.yaml", str(path))


def test_expired_allowlist_is_inactive(tmp_path: Path) -> None:
    raw = "010-0000-0000"
    secret = {
        "version": 1,
        "protected_values": [],
        "allowlist": [
            {
                "id": "expired",
                "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "reason": "expired synthetic fixture",
                "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
                "targets": ["phone-mobile"],
                "scope": {
                    "directions": ["request"],
                    "methods": ["POST"],
                    "path_prefixes": ["/demo"],
                },
            }
        ],
    }
    path = _write_yaml(tmp_path / "protected.yaml", secret)
    loaded = policy.load("configs/policy.yaml", str(path))
    finding = Finding("phone", 0, len(raw), "phone-mobile", "***")
    assert not loaded.allow_for(
        raw, finding, direction="request", method="POST", path="/demo"
    )
    assert loaded.safe_summary()["allowlist_expired"] == 1


@pytest.mark.parametrize("target", ["rrn-checksum", "unknown-detector-rule"])
def test_allowlist_rejects_protected_or_unknown_targets(
    tmp_path: Path, target: str
) -> None:
    raw = "SYNTHETIC-ALLOW-VALUE"
    secret = {
        "version": 1,
        "protected_values": [],
        "allowlist": [
            {
                "id": "unsafe-target",
                "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "reason": "synthetic invalid fixture",
                "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
                "targets": [target],
                "scope": {
                    "directions": ["request"],
                    "methods": ["POST"],
                    "path_prefixes": ["/demo"],
                },
            }
        ],
    }
    path = _write_yaml(tmp_path / "protected.yaml", secret)
    with pytest.raises(ValueError, match="allowlist"):
        policy.load("configs/policy.yaml", str(path))


def test_policy_error_action_cannot_be_downgraded() -> None:
    loaded = policy.Policy(
        default_action="alert",
        kind_actions={"policy_error": "alert"},
        rule_actions={"custom-regex-timeout:bounded": "alert"},
    )
    finding = Finding("policy_error", 0, 1, "custom-regex-timeout:bounded", "***")
    assert loaded.action_for(finding) == "block"


def test_minimal_policy_cannot_start_with_alert_defaults(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path / "unsafe-minimal.yaml", {"version": 1})
    with pytest.raises(ValueError, match="required security options"):
        policy.load(str(path))


def test_sha256_protected_match_flood_becomes_one_policy_error() -> None:
    loaded = policy.load(
        "configs/policy.yaml",
        "configs/protected-values.example.yaml",
    )
    token = "SYNTHETIC_TOKEN_7Q9X2M4P8N6K"
    findings = scan_rules(
        " ".join([token] * 101),
        loaded.custom_rules,
        direction="request",
        method="POST",
        path="/v1/chat",
        timeout_ms=25,
    )
    assert len(findings) == 1
    assert findings[0].kind == "policy_error"
    assert findings[0].rule.startswith("custom-match-limit:")


def test_builtin_match_flood_becomes_one_policy_error() -> None:
    findings = Scanner().scan(" ".join(["010-0000-0000"] * 257))
    assert len(findings) == 1
    assert findings[0].kind == "policy_error"
    assert findings[0].rule == "scan-finding-limit"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
def test_protected_values_file_mode_is_enforced_when_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protected_path = _write_yaml(
        tmp_path / "protected.yaml",
        {
            "version": 1,
            "protected_values": [
                {
                    "id": "synthetic-mode-test",
                    "action": "block",
                    "literal": "SYNTH-MODE-ONLY-7Q9X",
                }
            ],
            "allowlist": [],
        },
    )
    monkeypatch.setenv("DLP_ENFORCE_PROTECTED_FILE_MODE", "true")

    protected_path.chmod(0o644)
    with pytest.raises(ValueError, match="permissions are too broad"):
        policy.load("configs/policy.yaml", str(protected_path))

    protected_path.chmod(0o440)
    loaded = policy.load("configs/policy.yaml", str(protected_path))
    assert loaded.safe_summary()["protected_values"] == 1
