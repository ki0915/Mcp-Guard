"""Confidentiality keyword detector (대외비, 기밀, CONFIDENTIAL, ...).

Pure keyword presence — cheap and noisy by design; intended for the ``alert``
action rather than block. Word-boundary rules differ for Korean (no \\b around
Hangul), so Korean terms match as substrings while Latin terms require word
boundaries.
"""

from __future__ import annotations

import re

from .base import Finding, mask_sample

KIND = "keyword"

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("kw-daeoebi", re.compile(r"대외비")),
    ("kw-gimil", re.compile(r"기밀")),
    ("kw-sanae-hangjeong", re.compile(r"사내\s?한정|내부\s?자료")),
    ("kw-confidential", re.compile(r"(?i)\bconfidential\b")),
    ("kw-internal-only", re.compile(r"(?i)\binternal\s+(?:use\s+)?only\b")),
    ("kw-do-not-distribute", re.compile(r"(?i)\bdo\s+not\s+distribute\b")),
]


def scan(text: str) -> list[Finding]:
    out: list[Finding] = []
    for rule, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            out.append(
                Finding(
                    kind=KIND,
                    start=m.start(),
                    end=m.end(),
                    rule=rule,
                    sample=mask_sample(m.group(0)),
                )
            )
    return out
