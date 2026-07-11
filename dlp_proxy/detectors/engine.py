"""Detection engine: built-ins plus per-policy custom rules."""

from __future__ import annotations

from ..custom_rules import MAX_FINDINGS_PER_TEXT, CompiledRule, scan_rules
from ..transforms import Base64View, TextView, decode_base64_views, normalized_views
from . import account, card, keywords, phone, rrn, secrets
from .base import Finding

_DETECTORS = (rrn, phone, card, account, secrets, keywords)


class Scanner:
    """A policy-isolated scanner; no mutable global rule state."""

    __slots__ = ("custom_rules", "regex_timeout_ms", "enable_transforms")

    def __init__(
        self,
        custom_rules: tuple[CompiledRule, ...] = (),
        regex_timeout_ms: int = 25,
        *,
        enable_transforms: bool = True,
    ) -> None:
        self.custom_rules = custom_rules
        self.regex_timeout_ms = regex_timeout_ms
        self.enable_transforms = enable_transforms

    def scan(
        self,
        text: str,
        *,
        direction: str = "request",
        method: str = "POST",
        path: str = "/",
    ) -> list[Finding]:
        all_findings = self._scan_raw(
            text, direction=direction, method=method, path=path
        )
        if len(all_findings) > MAX_FINDINGS_PER_TEXT:
            return [_finding_limit(text)]
        if self.enable_transforms:
            for view in normalized_views(text):
                mapped = self._scan_view(
                    view, direction=direction, method=method, path=path
                )
                all_findings.extend(mapped)
                if len(all_findings) > MAX_FINDINGS_PER_TEXT:
                    return [_finding_limit(text)]

            decoded = decode_base64_views(text)
            if decoded.limit_exceeded:
                return [_transform_limit(text)]
            for view in decoded.views:
                all_findings.extend(
                    self._scan_base64(
                        view, direction=direction, method=method, path=path
                    )
                )
                if len(all_findings) > MAX_FINDINGS_PER_TEXT:
                    return [_finding_limit(text)]
        findings = _dedupe_exact(all_findings)
        if len(findings) > MAX_FINDINGS_PER_TEXT:
            return [_finding_limit(text)]
        return findings

    def _scan_raw(
        self, text: str, *, direction: str, method: str, path: str
    ) -> list[Finding]:
        findings = _scan_builtins(text)
        if self.custom_rules:
            findings.extend(
                scan_rules(
                    text,
                    self.custom_rules,
                    direction=direction,
                    method=method,
                    path=path,
                    timeout_ms=self.regex_timeout_ms,
                )
            )
        return findings

    def _scan_view(
        self, view: TextView, *, direction: str, method: str, path: str
    ) -> list[Finding]:
        return [
            _map_view_finding(view, finding)
            for finding in self._scan_raw(
                view.text, direction=direction, method=method, path=path
            )
        ]

    def _scan_base64(
        self, view: Base64View, *, direction: str, method: str, path: str
    ) -> list[Finding]:
        decoded_findings = self._scan_raw(
            view.text, direction=direction, method=method, path=path
        )
        for normalized in normalized_views(view.text):
            decoded_findings.extend(
                self._scan_view(
                    normalized, direction=direction, method=method, path=path
                )
            )
        decoded_findings = _dedupe_exact(decoded_findings)
        return [
            Finding(
                kind=finding.kind,
                start=view.start,
                end=view.end,
                rule=finding.rule,
                sample="***",
                source=f"base64:{finding.source}",
            )
            for finding in decoded_findings
        ]


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


def _transform_limit(text: str) -> Finding:
    return Finding(
        kind="policy_error",
        start=0,
        end=len(text),
        rule="scan-transform-limit",
        sample="***",
        source="transform-control",
    )


def _map_view_finding(view: TextView, finding: Finding) -> Finding:
    start, end = view.original_span(finding.start, finding.end)
    return Finding(
        kind=finding.kind,
        start=start,
        end=end,
        rule=finding.rule,
        sample="***",
        source=view.source,
    )


_DEFAULT_SCANNER = Scanner()


def scan(text: str) -> list[Finding]:
    """Compatibility helper for built-in detector tests."""
    return _DEFAULT_SCANNER.scan(text)
