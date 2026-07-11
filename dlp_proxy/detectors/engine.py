"""Detection engine: built-ins plus per-policy custom rules."""

from __future__ import annotations

from ..custom_rules import MAX_FINDINGS_PER_TEXT, CompiledRule, scan_rules
from . import account, card, keywords, phone, rrn, secrets
from .base import Finding

_DETECTORS = (rrn, phone, card, account, secrets, keywords)


class Scanner:
    """A policy-isolated scanner; no mutable global rule state."""

    __slots__ = ("custom_rules", "regex_timeout_ms")

    def __init__(
        self, custom_rules: tuple[CompiledRule, ...] = (), regex_timeout_ms: int = 25
    ) -> None:
        self.custom_rules = custom_rules
        self.regex_timeout_ms = regex_timeout_ms

    def scan(
        self,
        text: str,
        *,
        direction: str = "request",
        method: str = "POST",
        path: str = "/",
    ) -> list[Finding]:
        all_findings = _scan_builtins(text)
        if len(all_findings) > MAX_FINDINGS_PER_TEXT:
            return [_finding_limit(text)]
        if self.custom_rules:
            all_findings.extend(
                scan_rules(
                    text,
                    self.custom_rules,
                    direction=direction,
                    method=method,
                    path=path,
                    timeout_ms=self.regex_timeout_ms,
                )
            )
        findings = _dedupe_exact(all_findings)
        if len(findings) > MAX_FINDINGS_PER_TEXT:
            return [_finding_limit(text)]
        return findings


def _scan_builtins(text: str) -> list[Finding]:
    all_findings: list[Finding] = []
    for det in _DETECTORS:
        all_findings.extend(det.scan(text))
    return all_findings


def _dedupe_exact(findings: list[Finding]) -> list[Finding]:
    """Keep overlapping policies; drop only exact duplicate decisions.

    Overlap is resolved after actions are known. Dropping it here could let a
    broad alert/redact finding hide a nested custom block rule.
    """
    out: list[Finding] = []
    seen: set[tuple[str, int, int, str]] = set()
    for finding in sorted(findings, key=lambda item: (item.start, -item.end, item.rule)):
        key = (finding.kind, finding.start, finding.end, finding.rule)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _finding_limit(text: str) -> Finding:
    return Finding(
        kind="policy_error",
        start=0,
        end=len(text),
        rule="scan-finding-limit",
        sample="***",
    )


_DEFAULT_SCANNER = Scanner()


def scan(text: str) -> list[Finding]:
    """Compatibility helper for built-in detector tests."""
    return _DEFAULT_SCANNER.scan(text)
