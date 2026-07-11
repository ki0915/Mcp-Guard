"""Synthetic-only regression tests for representation-evasion scan views."""

from __future__ import annotations

import base64

from dlp_proxy.app import _replace_findings
from dlp_proxy.custom_rules import compile_protected_values
from dlp_proxy.detectors.engine import Scanner
from dlp_proxy.policy import VALID_ACTIONS
from dlp_proxy.transforms import MAX_BASE64_TOKENS


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def test_nfkc_fullwidth_phone_maps_to_original_span() -> None:
    obfuscated = "０１０－００００－００００"
    text = f"합성 연락처 {obfuscated}"

    findings = Scanner().scan(text)

    phone = next(finding for finding in findings if finding.kind == "phone")
    assert text[phone.start : phone.end] == obfuscated
    assert phone.source == "nfkc"
    redacted = _replace_findings(text, [phone])
    assert obfuscated not in redacted
    assert "[REDACTED:phone]" in redacted


def test_digit_spacing_and_zero_width_are_compacted_between_digits() -> None:
    obfuscated = "0 1\u200b0 0 0 0 0 0 0 0 0"
    text = f"synthetic mobile {obfuscated}"

    findings = Scanner().scan(text)

    phone = next(finding for finding in findings if finding.kind == "phone")
    assert text[phone.start : phone.end] == obfuscated
    assert "digit-compact" in phone.source


def test_digit_split_plain_landline_requires_phone_context() -> None:
    scanner = Scanner()
    findings = scanner.scan("synthetic office phone 0 2 0 0 0 0 0 0 0 0")
    assert any(finding.rule == "phone-landline-plain-context" for finding in findings)
    assert not scanner.scan("synthetic inventory 0 2 0 0 0 0 0 0 0 0")


def test_base64_phone_maps_to_complete_encoded_token() -> None:
    token = _b64("synthetic mobile 010-0000-0000")
    text = f"payload={token}"

    findings = Scanner().scan(text)

    phone = next(finding for finding in findings if finding.kind == "phone")
    assert text[phone.start : phone.end] == token
    assert phone.source == "base64:raw"
    assert token not in _replace_findings(text, [phone])


def test_base64_protected_literal_is_detected_without_exposing_value() -> None:
    synthetic_secret = "SYNTHETIC-PROTECTED-VALUE-9001"
    rules = compile_protected_values(
        [
            {
                "id": "synthetic-demo",
                "action": "block",
                "scope": {"directions": ["request"]},
                "literal": synthetic_secret,
            }
        ],
        VALID_ACTIONS,
    )
    token = _b64(synthetic_secret)

    findings = Scanner(rules).scan(token)

    protected = next(finding for finding in findings if finding.rule == "protected:synthetic-demo")
    assert protected.source == "base64:raw"
    assert protected.sample == "***"
    assert synthetic_secret not in repr(protected)


def test_base64_decoder_does_not_recurse() -> None:
    nested = _b64(_b64("synthetic mobile 010-0000-0000"))
    assert not Scanner().scan(nested)


def test_benign_base64_text_does_not_fire() -> None:
    token = _b64("ordinary synthetic release note with no identifier")
    assert not Scanner().scan(f"payload={token}")


def test_base64_candidate_limit_fails_closed() -> None:
    tokens = [_b64(f"SYNTHETIC NOTE {index:04d}") for index in range(MAX_BASE64_TOKENS + 1)]

    findings = Scanner().scan(" ".join(tokens))

    assert len(findings) == 1
    assert findings[0].kind == "policy_error"
    assert findings[0].rule == "scan-transform-limit"


def test_raw_only_baseline_disables_all_derived_views() -> None:
    fullwidth = "０１０－００００－００００"
    encoded = _b64("synthetic mobile 010-0000-0000")
    assert not Scanner(enable_transforms=False).scan(f"{fullwidth} {encoded}")
