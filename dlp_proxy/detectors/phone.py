"""Korean phone number detector.

Covers mobile (01X), Seoul (02) and regional landlines (03X-06X), service
numbers (070, 15XX/16XX/18XX), and the international +82 form. Separators may
be hyphen, dot, or space; unseparated 11-digit mobile numbers also match.
"""

from __future__ import annotations

import re

from .base import Finding, dedupe_overlaps, mask_sample

KIND = "phone"

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("phone-intl", re.compile(r"\+82[-. ]?1?0[-. ]?\d{3,4}[-. ]?\d{4}(?!\d)")),
    ("phone-mobile", re.compile(r"(?<!\d)01[016789][-. ]\d{3,4}[-. ]\d{4}(?!\d)")),
    ("phone-mobile-plain", re.compile(r"(?<![\d-])01[016789]\d{7,8}(?![\d-])")),
    ("phone-landline", re.compile(r"(?<!\d)0(?:2|[3-6]\d)[-. ]\d{3,4}[-. ]\d{4}(?!\d)")),
    (
        "phone-service",
        re.compile(r"(?<!\d)(?:070[-. ]\d{4}[-. ]\d{4}|1[5-9]\d{2}[-. ]\d{4})(?!\d)"),
    ),
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
    return dedupe_overlaps(out)
