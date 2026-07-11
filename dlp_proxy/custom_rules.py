"""Validated, bounded user-defined DLP matchers.

Non-sensitive classification patterns come from the policy ConfigMap. Exact
confidential values come from a separately mounted Kubernetes Secret. No raw
matcher value is exposed through ``repr`` or a :class:`Finding` sample.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any

import regex

from .detectors.base import Finding

VALID_DIRECTIONS = frozenset({"request", "request-path", "request-query", "response"})
MAX_CUSTOM_RULES = 64
MAX_PROTECTED_VALUES = 512
MAX_PATTERN_CHARS = 512
MAX_LITERALS_PER_RULE = 100
MAX_LITERAL_CHARS = 512
MAX_MATCHES_PER_RULE = 100
MAX_FINDINGS_PER_TEXT = 256
MIN_CONTEXT_GROUPS = 2
MAX_CONTEXT_GROUPS = 8
MAX_CONTEXT_LITERALS_PER_GROUP = 8
MIN_CONTEXT_WINDOW_CHARS = 16
MAX_CONTEXT_WINDOW_CHARS = 1024
MAX_CONTEXT_LITERAL_CHARS = 128

_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ASCII_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_./+=:@#$%!?~-])"
    r"[A-Za-z0-9_./+=:@#$%!?~-]{8,512}"
    r"(?![A-Za-z0-9_./+=:@#$%!?~-])"
)


@dataclass(frozen=True, slots=True)
class Scope:
    directions: frozenset[str]
    methods: frozenset[str] = frozenset()
    path_prefixes: tuple[str, ...] = ()

    def applies(self, direction: str, method: str, path: str) -> bool:
        if direction not in self.directions:
            return False
        if self.methods and method.upper() not in self.methods:
            return False
        return not self.path_prefixes or any(
            _path_prefix_matches(path, prefix) for prefix in self.path_prefixes
        )


@dataclass(frozen=True, slots=True)
class CompiledRule:
    id: str
    rule: str
    kind: str
    action: str
    scope: Scope
    match_type: str
    matcher: Any = field(default=None, repr=False, compare=False)
    digest: str | None = field(default=None, repr=False)
    token_length: int | None = None
    context_window_chars: int | None = None
    protected: bool = False


def compile_custom_rules(raw: object, valid_actions: frozenset[str]) -> tuple[CompiledRule, ...]:
    """Compile bounded non-sensitive literal, regex, or contextual rules."""
    items = _list(raw, "custom_rules")
    if len(items) > MAX_CUSTOM_RULES:
        raise ValueError(f"custom_rules exceeds limit {MAX_CUSTOM_RULES}")
    out: list[CompiledRule] = []
    seen: set[str] = set()
    for index, value in enumerate(items):
        label = f"custom_rules[{index}]"
        item = _mapping(value, label)
        _unknown(item, {"id", "kind", "action", "scope", "matcher", "description"}, label)
        rule_id = _rule_id(item.get("id"), label, seen)
        description = item.get("description")
        if description is not None and (
            not isinstance(description, str) or len(description) > 200
        ):
            raise ValueError(f"{label}.description is invalid")
        kind = item.get("kind", "confidential")
        if not isinstance(kind, str) or not _KIND_RE.fullmatch(kind):
            raise ValueError(f"{label}.kind is invalid")
        action = _action(item.get("action"), valid_actions, label)
        scope = _scope(item.get("scope"), label, require_narrow=False)
        matcher_raw = _mapping(item.get("matcher"), f"{label}.matcher")
        match_type = matcher_raw.get("type")
        context_window_chars: int | None = None
        if match_type == "literal":
            _unknown(
                matcher_raw,
                {"type", "values", "ignore_case", "whole_word"},
                f"{label}.matcher",
            )
            values = _string_list(matcher_raw.get("values"), f"{label}.matcher.values")
            if not values or len(values) > MAX_LITERALS_PER_RULE:
                raise ValueError(f"{label}.matcher.values count is invalid")
            if any(len(text) < 3 or len(text) > MAX_LITERAL_CHARS for text in values):
                raise ValueError(f"{label}.matcher contains an invalid literal length")
            ignore_case = _boolean(matcher_raw.get("ignore_case", False), f"{label}.matcher")
            whole_word = _boolean(matcher_raw.get("whole_word", False), f"{label}.matcher")
            dedupe_values = [text.casefold() for text in values] if ignore_case else values
            if len(set(dedupe_values)) != len(values):
                raise ValueError(f"{label}.matcher contains duplicate literals")
            body = "|".join(regex.escape(text) for text in sorted(values, key=len, reverse=True))
            pattern = f"(?:{body})"
            if whole_word:
                pattern = rf"(?<!\w){pattern}(?!\w)"
            compiled = _compile(pattern, ignore_case, label)
        elif match_type == "regex":
            _unknown(matcher_raw, {"type", "pattern", "ignore_case"}, f"{label}.matcher")
            pattern = matcher_raw.get("pattern")
            if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_PATTERN_CHARS:
                raise ValueError(f"{label}.matcher.pattern length is invalid")
            ignore_case = _boolean(matcher_raw.get("ignore_case", False), f"{label}.matcher")
            compiled = _compile(pattern, ignore_case, label)
            _reject_obvious_empty_match(compiled, label)
        elif match_type == "contextual":
            _unknown(
                matcher_raw,
                {"type", "groups", "window_chars", "ignore_case"},
                f"{label}.matcher",
            )
            groups = _context_groups(matcher_raw.get("groups"), f"{label}.matcher")
            ignore_case = _boolean(matcher_raw.get("ignore_case", False), f"{label}.matcher")
            window_chars = matcher_raw.get("window_chars")
            if (
                isinstance(window_chars, bool)
                or not isinstance(window_chars, int)
                or not MIN_CONTEXT_WINDOW_CHARS
                <= window_chars
                <= MAX_CONTEXT_WINDOW_CHARS
            ):
                raise ValueError(f"{label}.matcher.window_chars is invalid")
            if any(len(value) > window_chars for group in groups for value in group):
                raise ValueError(f"{label}.matcher.window_chars is too small")
            context_window_chars = window_chars
            normalized: set[str] = set()
            compiled_groups = []
            for group in groups:
                dedupe_values = [text.casefold() for text in group] if ignore_case else group
                if len(set(dedupe_values)) != len(group):
                    raise ValueError(f"{label}.matcher contains duplicate literals")
                for value in dedupe_values:
                    if value in normalized:
                        raise ValueError(f"{label}.matcher repeats a literal across groups")
                    if any(value in prior or prior in value for prior in normalized):
                        raise ValueError(f"{label}.matcher contains overlapping literals")
                    normalized.add(value)
                body = "|".join(
                    regex.escape(text) for text in sorted(group, key=len, reverse=True)
                )
                compiled_groups.append(_compile(f"(?:{body})", ignore_case, label))
            compiled = tuple(compiled_groups)
        else:
            raise ValueError(
                f"{label}.matcher.type must be literal, regex, or contextual"
            )
        out.append(
            CompiledRule(
                id=rule_id,
                rule=f"custom:{rule_id}",
                kind=kind,
                action=action,
                scope=scope,
                match_type=str(match_type),
                matcher=compiled,
                context_window_chars=context_window_chars,
            )
        )
    return tuple(out)


def compile_protected_values(
    raw: object, valid_actions: frozenset[str]
) -> tuple[CompiledRule, ...]:
    """Compile exact literals or bounded SHA-256 token fingerprints."""
    items = _list(raw, "protected_values")
    if len(items) > MAX_PROTECTED_VALUES:
        raise ValueError(f"protected_values exceeds limit {MAX_PROTECTED_VALUES}")
    out: list[CompiledRule] = []
    seen: set[str] = set()
    seen_material: set[tuple[object, ...]] = set()
    for index, value in enumerate(items):
        label = f"protected_values[{index}]"
        item = _mapping(value, label)
        _unknown(
            item,
            {"id", "action", "scope", "literal", "sha256", "token", "ignore_case"},
            label,
        )
        rule_id = _rule_id(item.get("id"), label, seen)
        action = _action(item.get("action"), valid_actions, label)
        scope = _scope(item.get("scope"), label, require_narrow=False)
        literal = item.get("literal")
        digest = item.get("sha256")
        if (literal is None) == (digest is None):
            raise ValueError(f"{label} must set exactly one of literal or sha256")
        if literal is not None:
            if not isinstance(literal, str) or not 8 <= len(literal) <= MAX_LITERAL_CHARS:
                raise ValueError(f"{label}.literal length is invalid")
            if "token" in item:
                raise ValueError(f"{label}.token is only valid with sha256")
            ignore_case = _boolean(item.get("ignore_case", False), label)
            material = ("literal", literal.casefold() if ignore_case else literal, ignore_case)
            if material in seen_material:
                raise ValueError(f"{label} duplicates protected match material")
            seen_material.add(material)
            compiled = _compile(regex.escape(literal), ignore_case, label)
            out.append(
                CompiledRule(
                    id=rule_id,
                    rule=f"protected:{rule_id}",
                    kind="confidential",
                    action=action,
                    scope=scope,
                    match_type="literal",
                    matcher=compiled,
                    protected=True,
                )
            )
            continue
        if "ignore_case" in item:
            raise ValueError(f"{label}.ignore_case is only valid with literal")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise ValueError(f"{label}.sha256 is invalid")
        token = _mapping(item.get("token"), f"{label}.token")
        _unknown(token, {"charset", "length"}, f"{label}.token")
        if token.get("charset") != "ascii_token":
            raise ValueError(f"{label}.token.charset must be ascii_token")
        length = token.get("length")
        if isinstance(length, bool) or not isinstance(length, int) or not 8 <= length <= 512:
            raise ValueError(f"{label}.token.length is invalid")
        material = ("sha256", digest.lower(), length)
        if material in seen_material:
            raise ValueError(f"{label} duplicates protected match material")
        seen_material.add(material)
        out.append(
            CompiledRule(
                id=rule_id,
                rule=f"protected:{rule_id}",
                kind="confidential",
                action=action,
                scope=scope,
                match_type="sha256",
                digest=digest.lower(),
                token_length=length,
                protected=True,
            )
        )
    return tuple(out)


def scan_rules(
    text: str,
    rules: tuple[CompiledRule, ...],
    *,
    direction: str,
    method: str,
    path: str,
    timeout_ms: int,
) -> list[Finding]:
    """Scan configured rules with per-rule time and match-count bounds."""
    findings: list[Finding] = []
    digest_rules: dict[str, list[CompiledRule]] = {}
    timeout = timeout_ms / 1000
    for rule in rules:
        if not rule.scope.applies(direction, method, path):
            continue
        if rule.match_type == "sha256":
            digest_rules.setdefault(str(rule.digest), []).append(rule)
            continue
        if rule.match_type == "contextual":
            contextual = _scan_contextual_rule(text, rule, timeout)
            if contextual and contextual[0].kind == "policy_error":
                return contextual
            findings.extend(contextual)
            if len(findings) > MAX_FINDINGS_PER_TEXT:
                return [_policy_error(text, "finding-limit", "global")]
            continue
        count = 0
        try:
            for match in rule.matcher.finditer(text, timeout=timeout):
                if match.start() == match.end():
                    return [_policy_error(text, "zero-width", rule.id)]
                count += 1
                if count > MAX_MATCHES_PER_RULE:
                    return [_policy_error(text, "match-limit", rule.id)]
                findings.append(
                    Finding(
                        kind=rule.kind,
                        start=match.start(),
                        end=match.end(),
                        rule=rule.rule,
                        sample="***",
                    )
                )
                if len(findings) > MAX_FINDINGS_PER_TEXT:
                    return [_policy_error(text, "finding-limit", "global")]
        except TimeoutError:
            return [_policy_error(text, "regex-timeout", rule.id)]

    if digest_rules:
        digest_counts: dict[str, int] = {}
        for token_match in _ASCII_TOKEN.finditer(text):
            token = token_match.group(0)
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            for rule in digest_rules.get(digest, ()):  # digest lookup never exposes token
                if len(token) != rule.token_length:
                    continue
                digest_counts[rule.id] = digest_counts.get(rule.id, 0) + 1
                if digest_counts[rule.id] > MAX_MATCHES_PER_RULE:
                    return [_policy_error(text, "match-limit", rule.id)]
                findings.append(
                    Finding(
                        kind=rule.kind,
                        start=token_match.start(),
                        end=token_match.end(),
                        rule=rule.rule,
                        sample="***",
                    )
                )
                if len(findings) > MAX_FINDINGS_PER_TEXT:
                    return [_policy_error(text, "finding-limit", "global")]
    return findings


def _scan_contextual_rule(
    text: str, rule: CompiledRule, timeout: float
) -> list[Finding]:
    """Find minimal spans containing one escaped literal from every group.

    ``timeout`` is a shared wall-clock budget for all group scans and the
    bounded window join, rather than a fresh budget for each group.
    """
    patterns = rule.matcher
    window_chars = rule.context_window_chars
    if (
        not isinstance(patterns, tuple)
        or not patterns
        or not isinstance(window_chars, int)
    ):
        return [_policy_error(text, "context-invalid", rule.id)]

    deadline = time.perf_counter() + timeout
    occurrences: list[tuple[int, int, int]] = []
    by_group: list[list[tuple[int, int]]] = []
    for group_index, pattern in enumerate(patterns):
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return [_policy_error(text, "context-timeout", rule.id)]
        count = 0
        group_occurrences: list[tuple[int, int]] = []
        try:
            for match in pattern.finditer(text, overlapped=True, timeout=remaining):
                count += 1
                if count > MAX_MATCHES_PER_RULE:
                    return [_policy_error(text, "match-limit", rule.id)]
                occurrences.append((match.start(), match.end(), group_index))
                group_occurrences.append((match.start(), match.end()))
                if time.perf_counter() >= deadline:
                    return [_policy_error(text, "context-timeout", rule.id)]
        except TimeoutError:
            return [_policy_error(text, "context-timeout", rule.id)]
        if count == 0:
            return []
        by_group.append(group_occurrences)

    occurrences.sort(key=lambda item: (item[0], item[1], item[2]))
    spans: list[tuple[int, int]] = []
    seen_spans: set[tuple[int, int]] = set()
    # Every valid combination has an earliest occurrence. Anchor each bounded
    # occurrence in turn, then select one fitting occurrence from every other
    # group. This avoids combinatorial products while correctly ignoring long,
    # irrelevant overlapping alternatives inside the same character window.
    for anchor_start, anchor_end, anchor_group in occurrences:
        limit = anchor_start + window_chars
        if anchor_end > limit:
            continue
        end = anchor_end
        complete = True
        for group_index, group_occurrences in enumerate(by_group):
            if group_index == anchor_group:
                continue
            selected_end = next(
                (
                    occurrence_end
                    for occurrence_start, occurrence_end in group_occurrences
                    if occurrence_start >= anchor_start and occurrence_end <= limit
                ),
                None,
            )
            if selected_end is None:
                complete = False
                break
            end = max(end, selected_end)
        span = (anchor_start, end)
        if complete and span not in seen_spans:
            seen_spans.add(span)
            spans.append(span)
            if len(spans) > MAX_MATCHES_PER_RULE:
                return [_policy_error(text, "match-limit", rule.id)]
        if time.perf_counter() >= deadline:
            return [_policy_error(text, "context-timeout", rule.id)]

    return [
        Finding(
            kind=rule.kind,
            start=start,
            end=end,
            rule=rule.rule,
            sample="***",
        )
        for start, end in spans
    ]


def parse_scope(raw: object, label: str, *, require_narrow: bool = False) -> Scope:
    """Public strict scope parser shared by allowlist validation."""
    return _scope(raw, label, require_narrow=require_narrow)


def _policy_error(text: str, reason: str, rule_id: str) -> Finding:
    return Finding(
        kind="policy_error",
        start=0,
        end=len(text),
        rule=f"custom-{reason}:{rule_id}",
        sample="***",
    )


def _compile(pattern: str, ignore_case: bool, label: str):
    flags = regex.VERSION1 | (regex.IGNORECASE if ignore_case else 0)
    try:
        return regex.compile(pattern, flags)
    except regex.error:
        raise ValueError(f"{label}.matcher is invalid") from None


def _reject_obvious_empty_match(compiled, label: str) -> None:
    for probe in ("", "a", " ", "\n", "SYNTHETIC"):
        match = compiled.search(probe)
        if match is not None and match.start() == match.end():
            raise ValueError(f"{label}.matcher must not match empty text")


def _scope(raw: object, label: str, *, require_narrow: bool) -> Scope:
    if raw is None:
        if require_narrow:
            raise ValueError(f"{label}.scope is required")
        return Scope(VALID_DIRECTIONS)
    value = _mapping(raw, f"{label}.scope")
    _unknown(value, {"directions", "methods", "path_prefixes"}, f"{label}.scope")
    directions = frozenset(
        _string_list(value.get("directions", sorted(VALID_DIRECTIONS)), f"{label}.scope")
    )
    if not directions or not directions <= VALID_DIRECTIONS:
        raise ValueError(f"{label}.scope.directions is invalid")
    methods = frozenset(
        method.upper() for method in _string_list(value.get("methods", []), f"{label}.scope")
    )
    if any(not re.fullmatch(r"[A-Z]{3,10}", method) for method in methods):
        raise ValueError(f"{label}.scope.methods is invalid")
    prefixes = tuple(_string_list(value.get("path_prefixes", []), f"{label}.scope"))
    if any(not prefix.startswith("/") or len(prefix) > 256 for prefix in prefixes):
        raise ValueError(f"{label}.scope.path_prefixes is invalid")
    if require_narrow and (
        "directions" not in value or not methods or not prefixes
    ):
        raise ValueError(
            f"{label}.scope must include directions, methods and path_prefixes"
        )
    return Scope(directions, methods, prefixes)


def _path_prefix_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(normalized + "/")


def _rule_id(value: object, label: str, seen: set[str]) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValueError(f"{label}.id is invalid")
    if value in seen:
        raise ValueError(f"{label}.id is duplicated")
    seen.add(value)
    return value


def _action(value: object, valid_actions: frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in valid_actions:
        raise ValueError(f"{label}.action is invalid")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} boolean option is invalid")
    return value


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be a mapping")
    return value


def _list(value: object, label: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return value


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a string list")
    return value


def _context_groups(value: object, label: str) -> list[list[str]]:
    if not isinstance(value, list) or not (
        MIN_CONTEXT_GROUPS <= len(value) <= MAX_CONTEXT_GROUPS
    ):
        raise ValueError(f"{label}.groups count is invalid")
    groups: list[list[str]] = []
    for group in value:
        if not isinstance(group, list) or not (
            1 <= len(group) <= MAX_CONTEXT_LITERALS_PER_GROUP
        ):
            raise ValueError(f"{label}.groups contains an invalid group")
        if not all(isinstance(item, str) for item in group):
            raise ValueError(f"{label}.groups must contain only string literals")
        if any(
            len(item) < 3 or len(item) > MAX_CONTEXT_LITERAL_CHARS
            for item in group
        ):
            raise ValueError(f"{label}.groups contains an invalid literal length")
        groups.append(group)
    return groups


def _unknown(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{label} contains unsupported option {unknown[0]!r}")
