"""Safely create a protected-values file outside the repository.

Raw values are read with a hidden prompt, never a command-line argument. The
file is atomically replaced and restricted to the current user where the OS
supports POSIX-style mode bits.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from dlp_proxy import policy  # noqa: E402

_ASCII_TOKEN = re.compile(r"^[A-Za-z0-9_./+=:@#$%!?~-]{8,512}$")


def _scope(args: argparse.Namespace) -> dict[str, list[str]]:
    value: dict[str, list[str]] = {}
    if args.direction:
        value["directions"] = args.direction
    if args.method:
        value["methods"] = [method.upper() for method in args.method]
    if args.path_prefix:
        value["path_prefixes"] = args.path_prefix
    return value


def literal_entry(args: argparse.Namespace, value: str) -> dict:
    entry = {"id": args.id, "action": args.action, "literal": value}
    scope = _scope(args)
    if scope:
        entry["scope"] = scope
    return entry


def token_entry(args: argparse.Namespace, value: str) -> dict:
    entry = {
        "id": args.id,
        "action": args.action,
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "token": {"charset": "ascii_token", "length": len(value)},
    }
    scope = _scope(args)
    if scope:
        entry["scope"] = scope
    return entry


def allowlist_entry(args: argparse.Namespace, value: str) -> dict:
    return {
        "id": args.id,
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "reason": args.reason,
        "expires_at": args.expires_at,
        "targets": args.target,
        "scope": _scope(args),
    }


def add_entry(path: Path, entry: dict, *, allow_repository_path: bool = False) -> None:
    _add_record(
        path,
        "protected_values",
        entry,
        allow_repository_path=allow_repository_path,
    )


def add_allowlist_entry(
    path: Path, entry: dict, *, allow_repository_path: bool = False
) -> None:
    _add_record(path, "allowlist", entry, allow_repository_path=allow_repository_path)


def _add_record(
    path: Path,
    section: str,
    entry: dict,
    *,
    allow_repository_path: bool = False,
) -> None:
    target = path.expanduser().resolve()
    if not allow_repository_path and target.is_relative_to(REPO_ROOT):
        raise ValueError("refusing to store protected values inside the repository")
    target.parent.mkdir(parents=True, exist_ok=True)
    document = _read_document(target)
    document.setdefault("protected_values", [])
    document.setdefault("allowlist", [])
    document[section].append(entry)

    # Validate through the same production loader before replacing the file.
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
        policy.load(str(REPO_ROOT / "configs" / "policy.yaml"), str(validation_path))
    finally:
        validation_path.unlink(missing_ok=True)
    _atomic_write(target, document)


def _read_document(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "protected_values": [], "allowlist": []}
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError):
        raise ValueError("existing protected-values file is not safe YAML") from None
    if not isinstance(value, dict):
        raise ValueError("existing protected-values root must be a mapping")
    return value


def _atomic_write(path: Path, document: dict) -> None:
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
    parser.add_argument("--id", required=True)
    parser.add_argument("--action", choices=sorted(policy.VALID_ACTIONS), default="block")
    parser.add_argument("--direction", action="append", choices=[
        "request", "request-path", "request-query", "response"
    ])
    parser.add_argument("--method", action="append")
    parser.add_argument("--path-prefix", action="append")
    parser.add_argument("--allow-repository-path", action="store_true", help=argparse.SUPPRESS)


def _add_allowlist_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file", required=True, type=Path)
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    literal = subparsers.add_parser("add-literal")
    token = subparsers.add_parser("add-token")
    allowlist = subparsers.add_parser("add-allowlist")
    _add_common_arguments(literal)
    _add_common_arguments(token)
    _add_allowlist_arguments(allowlist)
    args = parser.parse_args()

    value = getpass.getpass("Protected value (hidden): ")
    confirmation = getpass.getpass("Confirm protected value (hidden): ")
    if value != confirmation:
        print("Values do not match.")
        return 2
    if args.command == "add-literal":
        if not 8 <= len(value) <= 512:
            print("Literal must be 8-512 characters.")
            return 2
        entry = literal_entry(args, value)
    elif args.command == "add-token":
        if not _ASCII_TOKEN.fullmatch(value):
            print("Token does not satisfy the documented ascii_token contract.")
            return 2
        entry = token_entry(args, value)
    else:
        if not value:
            print("Allowlisted value must not be empty.")
            return 2
        entry = allowlist_entry(args, value)
    try:
        writer = add_allowlist_entry if args.command == "add-allowlist" else add_entry
        writer(args.file, entry, allow_repository_path=args.allow_repository_path)
    except (OSError, ValueError) as exc:
        print(f"Could not update protected-values file: {exc}")
        return 2
    print("Protected-values file updated. No raw value was printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
