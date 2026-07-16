"""Fail closed when committed detector fixtures lose synthetic-data controls.

This is a repository hygiene control, not proof that a value cannot belong to a
real person. It makes fixture additions and byte changes explicit and reviewable.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = ROOT / "tests" / "data"
DEFAULT_MANIFEST = DEFAULT_DATA / "synthetic-manifest.json"
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
SYNTHETIC_MARKERS = (
    "synthetic",
    "fake",
    "example",
    "fixture",
    "placeholder",
    "test",
    "합성",
    "가상",
    "테스트",
)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _cases(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return document
    if isinstance(document, dict) and isinstance(document.get("cases"), list):
        return document["cases"]
    raise ValueError("fixture must be a case array or an object containing a cases array")


def _is_sensitive(case: dict[str, Any]) -> bool:
    return bool(
        case.get("expect_kinds")
        or case.get("expect_rules")
        or case.get("label") == "sensitive"
    )


def _synthetic_marker_present(case: dict[str, Any]) -> bool:
    source = f"{case.get('text', '')} {case.get('note', '')}"
    candidates = [unicodedata.normalize("NFKC", source).casefold()]
    for token in BASE64_TOKEN.findall(source):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        candidates.append(unicodedata.normalize("NFKC", decoded).casefold())
    return any(marker in candidate for marker in SYNTHETIC_MARKERS for candidate in candidates)


def validate_manifest(data_dir: Path, manifest_path: Path) -> list[str]:
    """Return deterministic validation errors; an empty list means pass."""

    errors: list[str] = []
    try:
        manifest = _load_json(manifest_path)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"manifest unreadable: {exc}"]

    if manifest.get("schema_version") != 1:
        errors.append("manifest schema_version must equal 1")
    if manifest.get("synthetic_only") is not True:
        errors.append("manifest synthetic_only must be true")

    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        return errors + ["manifest files must be a non-empty array"]

    registered: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append("manifest file entry must be an object")
            continue
        name = entry.get("path")
        if not isinstance(name, str) or Path(name).name != name or not name.endswith(".json"):
            errors.append(f"invalid fixture path: {name!r}")
            continue
        if name in registered:
            errors.append(f"duplicate manifest entry: {name}")
            continue
        registered.add(name)
        if entry.get("synthetic_only") is not True:
            errors.append(f"{name}: synthetic_only must be true")
        provenance = entry.get("provenance")
        if not isinstance(provenance, str) or len(provenance.strip()) < 20:
            errors.append(f"{name}: provenance must explain how fixtures were fabricated")

        path = data_dir / name
        try:
            raw = path.read_bytes()
        except OSError as exc:
            errors.append(f"{name}: unreadable: {exc}")
            continue
        digest = hashlib.sha256(raw).hexdigest()
        if entry.get("sha256") != digest:
            errors.append(f"{name}: SHA-256 mismatch; review the change and update the manifest")
        try:
            cases = _cases(json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{name}: invalid fixture document: {exc}")
            continue
        if entry.get("case_count") != len(cases):
            errors.append(f"{name}: case_count must equal {len(cases)}")

        ids: set[str] = set()
        for index, case in enumerate(cases):
            case_id = case.get("id") if isinstance(case, dict) else None
            if not isinstance(case_id, str) or not case_id:
                errors.append(f"{name}: case {index} has no non-empty id")
                continue
            if case_id in ids:
                errors.append(f"{name}: duplicate case id {case_id}")
            ids.add(case_id)
            if not isinstance(case.get("text"), str):
                errors.append(f"{name}:{case_id}: text must be a string")
            elif _is_sensitive(case) and not _synthetic_marker_present(case):
                errors.append(
                    f"{name}:{case_id}: sensitive fixture lacks a visible synthetic marker"
                )

    discovered = {
        path.name for path in data_dir.glob("*.json") if path.resolve() != manifest_path.resolve()
    }
    for name in sorted(discovered - registered):
        errors.append(f"unregistered fixture file: {name}")
    for name in sorted(registered - discovered):
        errors.append(f"registered fixture file missing: {name}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    errors = validate_manifest(args.data_dir, args.manifest)
    if errors:
        print("Synthetic fixture guard: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    file_count = len(_load_json(args.manifest)["files"])
    print(f"Synthetic fixture guard: PASS ({file_count} registered datasets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
