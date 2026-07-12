"""Strict policy and protected-value configuration.

The policy YAML is safe for a ConfigMap and contains non-sensitive matcher
metadata. Raw confidential values are loaded only from a separate file such
as a read-only Kubernetes Secret volume.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .custom_rules import (
    CompiledRule,
    Scope,
    compile_custom_rules,
    compile_protected_values,
    parse_scope,
)
from .detectors import Finding

VALID_ACTIONS = frozenset({"redact", "block", "alert"})
CONTROL_ACTIONS = frozenset({"block", "alert"})
_BLOCK_ACTION = "block"
SSE_MODES = frozenset({"buffer", "event"})
PROTECTED_KINDS = frozenset({"rrn", "card", "secret", "confidential", "policy_error"})
MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_ALLOWLIST_ENTRIES = 128
MAX_ALLOWLIST_TTL = timedelta(days=30)

_CONFIG_KEYS = {
    "version",
    "strict_config",
    "upstream",
    "default_action",
    "rules",
    "rule_overrides",
    "scan",
    "expose_block_detail",
    "custom_regex_timeout_ms",
    "custom_rules",
}
_CONFIG_REQUIRED = {
    "version",
    "strict_config",
    "upstream",
    "default_action",
    "rules",
    "scan",
}
_SCAN_REQUIRED = {
    "request",
    "response",
    "max_body_bytes",
    "oversize_action",
    "unscannable_action",
}
_SENSITIVE_KIND_ACTIONS = frozenset({"rrn", "card", "secret"})
_RULE_NAME = re.compile(r"^[a-z][a-z0-9:._-]{0,127}$")
_ENTRY_ID = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_BUILTIN_RULE_KINDS = {
    "rrn-checksum": "rrn",
    "rrn-format-only": "rrn",
    "phone-intl": "phone",
    "phone-mobile": "phone",
    "phone-mobile-plain": "phone",
    "phone-landline": "phone",
    "phone-service": "phone",
    "phone-landline-plain-context": "phone",
    "phone-service-plain-context": "phone",
    "card-luhn": "card",
    "account-context": "account",
    "aws-access-key": "secret",
    "github-token": "secret",
    "anthropic-key": "secret",
    "openai-key": "secret",
    "slack-token": "secret",
    "google-api-key": "secret",
    "jwt": "secret",
    "private-key-block": "secret",
    "generic-high-entropy": "secret",
    "kw-daeoebi": "keyword",
    "kw-gimil": "keyword",
    "kw-sanae-hangjeong": "keyword",
    "kw-confidential": "keyword",
    "kw-internal-only": "keyword",
    "kw-do-not-distribute": "keyword",
}


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    id: str
    sha256: str = field(repr=False)
    reason: str
    expires_at: datetime
    targets: frozenset[str]
    scope: Scope

    def active(self, now: datetime) -> bool:
        return now < self.expires_at

    def matches(
        self,
        digest: str,
        finding: Finding,
        *,
        direction: str,
        method: str,
        path: str,
        now: datetime,
    ) -> bool:
        return (
            self.active(now)
            and finding.rule in self.targets
            and digest == self.sha256
            and self.scope.applies(direction, method, path)
        )


@dataclass(slots=True)
class Policy:
    upstream: str = "http://localhost:9000"
    default_action: str = "alert"
    # These "block" strings are DLP action labels, never credentials.
    kind_actions: dict[str, str] = field(
        default_factory=lambda: {
            "rrn": "block",
            "card": "block",
            "secret": _BLOCK_ACTION,
        }
    )
    rule_actions: dict[str, str] = field(default_factory=dict)
    scan_request: bool = True
    scan_response: bool = True
    max_body_bytes: int = 1_048_576
    oversize_action: str = "block"
    unscannable_action: str = "block"
    sse_mode: str = "buffer"
    expose_block_detail: bool = False
    custom_regex_timeout_ms: int = 25
    custom_rules: tuple[CompiledRule, ...] = field(default_factory=tuple, repr=False)
    allowlist: tuple[AllowlistEntry, ...] = field(default_factory=tuple, repr=False)

    def action_for(self, finding: Finding) -> str:
        if finding.kind == "policy_error":
            return "block"
        if finding.rule in self.rule_actions:
            return self.rule_actions[finding.rule]
        return self.kind_actions.get(finding.kind, self.default_action)

    def allow_for(
        self,
        raw_value: str,
        finding: Finding,
        *,
        direction: str,
        method: str,
        path: str,
        now: datetime | None = None,
    ) -> AllowlistEntry | None:
        """Return a narrow, unexpired exact exception for a non-protected kind."""
        if finding.kind in PROTECTED_KINDS or not self.allowlist:
            return None
        digest = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
        current = now or datetime.now(UTC)
        for entry in self.allowlist:
            if entry.matches(
                digest,
                finding,
                direction=direction,
                method=method,
                path=path,
                now=current,
            ):
                return entry
        return None

    def safe_summary(self, now: datetime | None = None) -> dict[str, object]:
        """Return operational counts without IDs, matchers, paths, or digests."""
        current = now or datetime.now(UTC)
        custom_count = sum(rule.rule.startswith("custom:") for rule in self.custom_rules)
        protected_count = sum(rule.rule.startswith("protected:") for rule in self.custom_rules)
        active = sum(entry.active(current) for entry in self.allowlist)
        return {
            "status": "loaded",
            "custom_rules": custom_count,
            "protected_values": protected_count,
            "allowlist_active": active,
            "allowlist_expired": len(self.allowlist) - active,
            "scan_request": self.scan_request,
            "scan_response": self.scan_response,
            "oversize_action": self.oversize_action,
            "unscannable_action": self.unscannable_action,
            "sse_mode": self.sse_mode,
        }


def load(path: str | None = None, protected_path: str | None = None) -> Policy:
    """Load and validate policy plus optional protected values, failing closed."""
    selected_path = path or os.environ.get("DLP_POLICY_PATH", "configs/policy.yaml")
    data = _read_yaml(selected_path, "policy")
    strict = _bool(data.get("strict_config", True), "strict_config")
    if strict:
        _unknown(data, _CONFIG_KEYS, "policy")
        _require(data, _CONFIG_REQUIRED, "policy")
    version = data.get("version", 1)
    if isinstance(version, bool) or version != 1:
        raise ValueError("policy.version must be 1")

    upstream = os.environ.get("DLP_UPSTREAM", data.get("upstream", "http://localhost:9000"))
    _validate_upstream(upstream)
    default_action = _action(data.get("default_action", "alert"), "default_action")
    kind_actions = _action_mapping(data.get("rules", {}), "rules")
    missing_sensitive_actions = _SENSITIVE_KIND_ACTIONS - kind_actions.keys()
    if missing_sensitive_actions:
        raise ValueError("rules must explicitly configure rrn, card, and secret")
    rule_actions = _action_mapping(data.get("rule_overrides", {}), "rule_overrides")

    scan = _mapping(data.get("scan", {}), "scan")
    if strict:
        _unknown(
            scan,
            {
                "request",
                "response",
                "max_body_bytes",
                "oversize_action",
                "unscannable_action",
                "sse_mode",
            },
            "scan",
        )
        _require(scan, _SCAN_REQUIRED, "scan")
    scan_request = _bool(scan.get("request", True), "scan.request")
    scan_response = _bool(scan.get("response", True), "scan.response")
    max_body_bytes = scan.get("max_body_bytes", 1_048_576)
    if (
        isinstance(max_body_bytes, bool)
        or not isinstance(max_body_bytes, int)
        or not 1 <= max_body_bytes <= MAX_BODY_BYTES
    ):
        raise ValueError(f"scan.max_body_bytes must be between 1 and {MAX_BODY_BYTES}")
    oversize_action = _control_action(scan.get("oversize_action", "block"), "scan.oversize_action")
    unscannable_action = _control_action(
        scan.get("unscannable_action", "block"), "scan.unscannable_action"
    )
    sse_mode = scan.get("sse_mode", "buffer")
    if not isinstance(sse_mode, str) or sse_mode not in SSE_MODES:
        raise ValueError("scan.sse_mode must be buffer or event")
    expose_block_detail = _bool(
        data.get("expose_block_detail", False), "expose_block_detail"
    )
    timeout_ms = data.get("custom_regex_timeout_ms", 25)
    if (
        isinstance(timeout_ms, bool)
        or not isinstance(timeout_ms, int)
        or not 1 <= timeout_ms <= 100
    ):
        raise ValueError("custom_regex_timeout_ms must be between 1 and 100")

    configured = compile_custom_rules(data.get("custom_rules", []), VALID_ACTIONS)
    selected_protected = (
        protected_path
        if protected_path is not None
        else os.environ.get("DLP_PROTECTED_VALUES_PATH", "")
    )
    protected: tuple[CompiledRule, ...] = ()
    allowlist: tuple[AllowlistEntry, ...] = ()
    if selected_protected:
        secret_data = _read_yaml(selected_protected, "protected values")
        _unknown(secret_data, {"version", "protected_values", "allowlist"}, "protected values")
        secret_version = secret_data.get("version", 1)
        if isinstance(secret_version, bool) or secret_version != 1:
            raise ValueError("protected values version must be 1")
        protected = compile_protected_values(secret_data.get("protected_values", []), VALID_ACTIONS)
        allowlist = _parse_allowlist(secret_data.get("allowlist", []))

    ids: set[str] = set()
    for rule in configured + protected:
        if rule.id in ids:
            raise ValueError("custom/protected rule IDs must be unique")
        ids.add(rule.id)
        if rule.rule in rule_actions:
            raise ValueError("rule_overrides must not override custom/protected actions")
        rule_actions[rule.rule] = rule.action

    known_rule_kinds = dict(_BUILTIN_RULE_KINDS)
    known_rule_kinds.update({rule.rule: rule.kind for rule in configured + protected})
    for entry in allowlist:
        for target in entry.targets:
            kind = known_rule_kinds.get(target)
            if kind is None:
                raise ValueError("allowlist targets an unknown detector rule")
            if kind in PROTECTED_KINDS:
                raise ValueError("allowlist must not target a protected detector kind")

    return Policy(
        upstream=upstream,
        default_action=default_action,
        kind_actions=kind_actions,
        rule_actions=rule_actions,
        scan_request=scan_request,
        scan_response=scan_response,
        max_body_bytes=max_body_bytes,
        oversize_action=oversize_action,
        unscannable_action=unscannable_action,
        sse_mode=sse_mode,
        expose_block_detail=expose_block_detail,
        custom_regex_timeout_ms=timeout_ms,
        custom_rules=configured + protected,
        allowlist=allowlist,
    )


def _parse_allowlist(raw: object) -> tuple[AllowlistEntry, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValueError("allowlist must be a list")
    if len(raw) > MAX_ALLOWLIST_ENTRIES:
        raise ValueError(f"allowlist exceeds limit {MAX_ALLOWLIST_ENTRIES}")
    now = datetime.now(UTC)
    out: list[AllowlistEntry] = []
    seen: set[str] = set()
    for index, value in enumerate(raw):
        label = f"allowlist[{index}]"
        item = _mapping(value, label)
        _unknown(item, {"id", "sha256", "reason", "expires_at", "targets", "scope"}, label)
        entry_id = item.get("id")
        if not isinstance(entry_id, str) or not _ENTRY_ID.fullmatch(entry_id):
            raise ValueError(f"{label}.id is invalid")
        if entry_id in seen:
            raise ValueError(f"{label}.id is duplicated")
        seen.add(entry_id)
        digest = item.get("sha256")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError(f"{label}.sha256 is invalid")
        reason = item.get("reason")
        if (
            not isinstance(reason, str)
            or not 3 <= len(reason) <= 200
            or "\n" in reason
            or "\r" in reason
        ):
            raise ValueError(f"{label}.reason is invalid")
        expires_at = _timestamp(item.get("expires_at"), f"{label}.expires_at")
        if expires_at > now + MAX_ALLOWLIST_TTL:
            raise ValueError(f"{label}.expires_at exceeds the 30-day maximum")
        targets_raw = item.get("targets")
        if not isinstance(targets_raw, list) or not targets_raw:
            raise ValueError(f"{label}.targets must be a non-empty list")
        if not all(
            isinstance(target, str) and _RULE_NAME.fullmatch(target)
            for target in targets_raw
        ):
            raise ValueError(f"{label}.targets is invalid")
        if "*" in targets_raw:
            raise ValueError(f"{label}.targets must not contain wildcards")
        scope = parse_scope(item.get("scope"), label, require_narrow=True)
        out.append(
            AllowlistEntry(
                id=entry_id,
                sha256=digest.lower(),
                reason=reason,
                expires_at=expires_at,
                targets=frozenset(targets_raw),
                scope=scope,
            )
        )
    return tuple(out)


def _timestamp(value: object, label: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"{label} is invalid") from None
    else:
        raise ValueError(f"{label} is invalid")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _read_yaml(path: str, label: str) -> dict[str, Any]:
    selected = Path(path)
    if not selected.is_file():
        raise FileNotFoundError(f"{label} file is missing")
    if (
        label == "protected values"
        and os.name == "posix"
        and os.environ.get("DLP_ENFORCE_PROTECTED_FILE_MODE", "").lower()
        in {"1", "true", "yes"}
    ):
        mode = stat.S_IMODE(selected.stat().st_mode)
        if mode & 0o037:
            raise ValueError("protected values file permissions are too broad")
    try:
        with selected.open(encoding="utf-8") as handle:
            value = yaml.safe_load(handle) or {}
    except (OSError, UnicodeError, yaml.YAMLError):
        raise ValueError(f"{label} file could not be read safely") from None
    return _mapping(value, label)


def _action_mapping(value: object, label: str) -> dict[str, str]:
    mapping = _mapping(value, label)
    out: dict[str, str] = {}
    for key, action in mapping.items():
        if not _RULE_NAME.fullmatch(key):
            raise ValueError(f"{label} contains an invalid rule name")
        out[key] = _action(action, f"{label}.{key}")
    return out


def _action(value: object, label: str) -> str:
    if not isinstance(value, str) or value not in VALID_ACTIONS:
        raise ValueError(f"{label} has an invalid action")
    return value


def _control_action(value: object, label: str) -> str:
    if not isinstance(value, str) or value not in CONTROL_ACTIONS:
        raise ValueError(f"{label} must be block or alert")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be a mapping")
    return value


def _unknown(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{label} contains unsupported option {unknown[0]!r}")


def _require(value: dict[str, Any], required: set[str], label: str) -> None:
    if not required <= value.keys():
        raise ValueError(f"{label} is missing required security options")


def _validate_upstream(value: object) -> None:
    if not isinstance(value, str):
        raise ValueError("upstream must be a URL")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("upstream must be an http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("upstream credentials must be sent in headers, not the URL")
