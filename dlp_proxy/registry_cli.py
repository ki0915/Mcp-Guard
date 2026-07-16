"""Safely manage and verify an external protected-values registry.

Raw values are accepted only through a hidden prompt.  Commands never print
literal material, digests, probe text, or matched samples.  Updates are
validated with the production policy loader and atomically replaced.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from . import policy
from .custom_rules import PROTECTED_ACTIONS
from .detectors.engine import Scanner

REPO_ROOT = Path(__file__).resolve().parent.parent
_ASCII_TOKEN = re.compile(r"^[A-Za-z0-9_./+=:@#$%!?~-]{8,512}$")
_SECTIONS = {"protected-values": "protected_values", "allowlist": "allowlist"}


def _scope(args: argparse.Namespace) -> dict[str, list[str]]:
    value: dict[str, list[str]] = {}
    if getattr(args, "direction", None):
        value["directions"] = args.direction
    if getattr(args, "method", None):
        value["methods"] = [method.upper() for method in args.method]
    if getattr(args, "path_prefix", None):
        value["path_prefixes"] = args.path_prefix
    return value


def literal_entry(args: argparse.Namespace, value: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"id": args.id, "action": args.action, "literal": value}
    scope = _scope(args)
    if scope:
        entry["scope"] = scope
    return entry


def token_entry(args: argparse.Namespace, value: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": args.id,
        "action": args.action,
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "token": {"charset": "ascii_token", "length": len(value)},
    }
    scope = _scope(args)
    if scope:
        entry["scope"] = scope
    return entry


def allowlist_entry(args: argparse.Namespace, value: str) -> dict[str, Any]:
    return {
        "id": args.id,
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "reason": args.reason,
        "expires_at": args.expires_at,
        "targets": args.target,
        "scope": _scope(args),
    }


def add_entry(
    path: Path,
    entry: dict[str, Any],
    *,
    allow_repository_path: bool = False,
    policy_path: Path | None = None,
) -> None:
    _add_record(
        path,
        "protected_values",
        entry,
        allow_repository_path=allow_repository_path,
        policy_path=policy_path,
    )


def add_allowlist_entry(
    path: Path,
    entry: dict[str, Any],
    *,
    allow_repository_path: bool = False,
    policy_path: Path | None = None,
) -> None:
    _add_record(
        path,
        "allowlist",
        entry,
        allow_repository_path=allow_repository_path,
        policy_path=policy_path,
    )


def _add_record(
    path: Path,
    section: str,
    entry: dict[str, Any],
    *,
    allow_repository_path: bool = False,
    policy_path: Path | None = None,
) -> None:
    target = _target(path, allow_repository_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    document = _read_document(target)
    document.setdefault("protected_values", [])
    document.setdefault("allowlist", [])
    document[section].append(entry)
    _validate_and_write(target, document, policy_path)


def remove_record(
    path: Path,
    section: str,
    entry_id: str,
    *,
    allow_repository_path: bool = False,
    policy_path: Path | None = None,
) -> None:
    """Remove exactly one ID without ever serializing its protected material."""
    if section not in {"protected_values", "allowlist"}:
        raise ValueError("unsupported registry section")
    target = _target(path, allow_repository_path)
    if not target.exists():
        raise ValueError("protected-values file does not exist")
    document = _read_document(target)
    records = document.get(section, [])
    if not isinstance(records, list):
        raise ValueError(f"{section} must be a list")
    kept = [
        record
        for record in records
        if not isinstance(record, dict) or record.get("id") != entry_id
    ]
    if len(records) - len(kept) != 1:
        raise ValueError("registry ID was not found exactly once")
    document[section] = kept
    document.setdefault("protected_values", [])
    document.setdefault("allowlist", [])
    _validate_and_write(target, document, policy_path)


def safe_inventory(path: Path, policy_path: Path | None = None) -> dict[str, Any]:
    """Return management metadata without matchers, values, or digests."""
    target = path.expanduser().resolve()
    loaded = policy.load(str(_policy_path(policy_path)), str(target))
    document = _read_document(target)
    protected: list[dict[str, Any]] = []
    for record in document.get("protected_values", []):
        if not isinstance(record, dict):
            continue
        scope = record.get("scope") if isinstance(record.get("scope"), dict) else {}
        protected.append(
            {
                "id": record.get("id"),
                "action": record.get("action"),
                "match_type": "literal" if "literal" in record else "sha256-token",
                "directions": scope.get("directions", [
                    "request", "request-path", "request-query", "response"
                ]),
                "method_count": len(scope.get("methods", [])),
                "path_prefix_count": len(scope.get("path_prefixes", [])),
            }
        )
    exceptions: list[dict[str, Any]] = []
    for record in document.get("allowlist", []):
        if not isinstance(record, dict):
            continue
        exceptions.append(
            {
                "id": record.get("id"),
                "expires_at": record.get("expires_at"),
                "target_count": len(record.get("targets", [])),
            }
        )
    return {
        "summary": loaded.safe_summary(),
        "protected_values": protected,
        "allowlist": exceptions,
    }


def probe_value(
    value: str,
    *,
    policy_path: Path,
    protected_path: Path | None,
    direction: str,
    method: str,
    path: str,
) -> dict[str, Any]:
    """Evaluate hidden input and return only non-sensitive decision metadata."""
    loaded = policy.load(
        str(policy_path), str(protected_path) if protected_path is not None else None
    )
    scan_enabled = loaded.scan_response if direction == "response" else loaded.scan_request
    if not scan_enabled:
        return {
            "decision": "allow",
            "finding_count": 0,
            "actions": {},
            "kinds": {},
            "scan_enabled": False,
        }
    if (
        direction in {"request", "response"}
        and len(value.encode("utf-8")) > loaded.max_body_bytes
    ):
        return {
            "decision": loaded.oversize_action,
            "finding_count": 0,
            "actions": {loaded.oversize_action: 1},
            "kinds": {"oversize_control": 1},
            "scan_enabled": True,
        }
    scanner = Scanner(loaded.custom_rules, loaded.custom_regex_timeout_ms)
    findings = scanner.scan(value, direction=direction, method=method, path=path)
    actions: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    for finding in findings:
        exception = loaded.allow_for(
            value[finding.start : finding.end],
            finding,
            direction=direction,
            method=method,
            path=path,
        )
        action = "allow" if exception is not None else loaded.action_for(finding)
        actions[action] += 1
        kinds[finding.kind] += 1
    decision = "allow"
    for candidate in ("block", "redact", "alert"):
        if actions[candidate]:
            decision = candidate
            break
    return {
        "decision": decision,
        "finding_count": len(findings),
        "actions": dict(sorted(actions.items())),
        "kinds": dict(sorted(kinds.items())),
        "scan_enabled": True,
    }


def _target(path: Path, allow_repository_path: bool) -> Path:
    target = path.expanduser().resolve()
    inside_checkout = target.is_relative_to(REPO_ROOT) or any(
        (parent / ".git").exists() for parent in (target.parent, *target.parents)
    )
    if not allow_repository_path and inside_checkout:
        raise ValueError("refusing to store protected values inside the repository")
    return target


def _policy_path(value: Path | None) -> Path:
    if value is not None:
        return value.expanduser().resolve()
    environment = os.environ.get("DLP_POLICY_PATH")
    if environment:
        return Path(environment).expanduser().resolve()
    working_copy = Path.cwd() / "configs" / "policy.yaml"
    if working_copy.exists():
        return working_copy.resolve()
    return (REPO_ROOT / "configs" / "policy.yaml").resolve()


def _validate_and_write(
    target: Path, document: dict[str, Any], policy_path: Path | None
) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=target.parent,
        prefix=".protected-values-validate-",
        suffix=".yaml",
        delete=False,
    ) as handle:
        yaml.safe_dump(document, handle, allow_unicode=True, sort_keys=False)
        validation_path = Path(handle.name)
    try:
        policy.load(str(_policy_path(policy_path)), str(validation_path))
    finally:
        validation_path.unlink(missing_ok=True)
    _atomic_write(target, document)


def _read_document(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "protected_values": [], "allowlist": []}
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError):
        raise ValueError("existing protected-values file is not safe YAML") from None
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("existing protected-values root must be a mapping")
    return value


def _atomic_write(path: Path, document: dict[str, Any]) -> None:
    fd, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=".protected-values-", suffix=".yaml"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            yaml.safe_dump(document, handle, allow_unicode=True, sort_keys=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--id", required=True)
    parser.add_argument("--action", choices=sorted(PROTECTED_ACTIONS), default="block")
    parser.add_argument(
        "--direction",
        action="append",
        choices=["request", "request-path", "request-query", "response"],
    )
    parser.add_argument("--method", action="append")
    parser.add_argument("--path-prefix", action="append")
    parser.add_argument("--allow-repository-path", action="store_true", help=argparse.SUPPRESS)


def _add_allowlist_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--id", required=True)
    parser.add_argument("--target", action="append", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument(
        "--direction",
        action="append",
        required=True,
        choices=["request", "request-path", "request-query", "response"],
    )
    parser.add_argument("--method", action="append", required=True)
    parser.add_argument("--path-prefix", action="append", required=True)
    parser.add_argument("--allow-repository-path", action="store_true", help=argparse.SUPPRESS)


def _hidden_value(prompt: str, *, confirm: bool) -> str | None:
    value = getpass.getpass(prompt)
    if confirm and value != getpass.getpass("Confirm protected value (hidden): "):
        print("Values do not match.")
        return None
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    literal = subparsers.add_parser("add-literal")
    token = subparsers.add_parser("add-token", aliases=["add-sha256"])
    allowlist = subparsers.add_parser("add-allowlist")
    _add_common_arguments(literal)
    _add_common_arguments(token)
    _add_allowlist_arguments(allowlist)

    listing = subparsers.add_parser("list")
    listing.add_argument("--file", required=True, type=Path)
    listing.add_argument("--policy", type=Path)

    remove = subparsers.add_parser("remove")
    remove.add_argument("--file", required=True, type=Path)
    remove.add_argument("--policy", type=Path)
    remove.add_argument("--section", required=True, choices=sorted(_SECTIONS))
    remove.add_argument("--id", required=True)
    remove.add_argument("--allow-repository-path", action="store_true", help=argparse.SUPPRESS)

    probe = subparsers.add_parser("probe")
    probe.add_argument("--policy", type=Path)
    probe.add_argument("--file", type=Path)
    probe.add_argument(
        "--direction",
        default="request",
        choices=["request", "request-path", "request-query", "response"],
    )
    probe.add_argument("--method", default="POST")
    probe.add_argument("--path", default="/")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "list":
            print(json.dumps(safe_inventory(args.file, args.policy), ensure_ascii=False, indent=2))
            return 0
        if args.command == "remove":
            remove_record(
                args.file,
                _SECTIONS[args.section],
                args.id,
                allow_repository_path=args.allow_repository_path,
                policy_path=_policy_path(args.policy),
            )
            print("Registry entry removed. No protected material was printed.")
            return 0
        if args.command == "probe":
            value = _hidden_value("Probe value (hidden): ", confirm=False)
            if value is None or not value:
                print("Probe value must not be empty.")
                return 2
            result = probe_value(
                value,
                policy_path=args.policy,
                protected_path=args.file,
                direction=args.direction,
                method=args.method.upper(),
                path=args.path,
            )
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 0

        value = _hidden_value("Protected value (hidden): ", confirm=True)
        if value is None:
            return 2
        if args.command == "add-literal":
            if not 8 <= len(value) <= 512:
                print("Literal must be 8-512 characters.")
                return 2
            entry = literal_entry(args, value)
        elif args.command in {"add-token", "add-sha256"}:
            if not _ASCII_TOKEN.fullmatch(value):
                print("Token does not satisfy the documented ascii_token contract.")
                return 2
            entry = token_entry(args, value)
        else:
            if not value:
                print("Allowlisted value must not be empty.")
                return 2
            entry = allowlist_entry(args, value)
        writer = add_allowlist_entry if args.command == "add-allowlist" else add_entry
        writer(
            args.file,
            entry,
            allow_repository_path=args.allow_repository_path,
            policy_path=args.policy,
        )
    except (OSError, ValueError) as exc:
        print(f"Protected-values registry operation failed: {exc}")
        return 2
    print("Protected-values registry updated. No raw value was printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
