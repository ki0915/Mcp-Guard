"""주민등록번호 (Korean resident registration number) detector.

Format: YYMMDD-GNNNNNC where G encodes century/gender (1-8). Candidates are
validated by date plausibility and the classic mod-11 checksum. RRNs issued
after 2020-10 have random tails with no valid checksum; those still match on
format+date but are reported with rule ``rrn-format-only`` so accuracy stats
and policy can distinguish them (see README limitations).
"""

from __future__ import annotations

import re
from datetime import date

from .base import Finding, mask_sample

KIND = "rrn"

_RRN = re.compile(r"(?<!\d)(\d{2})(\d{2})(\d{2})([- ]?)([1-8])(\d{5})(\d)(?!\d)")

_WEIGHTS = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)

# A space separator also matches price/quantity lists ("단가 750615 1000002"),
# so space-separated candidates additionally need an identity-context keyword
# nearby. Hyphenated and unseparated forms are distinctive enough on their own.
_SPACE_CONTEXT = re.compile(
    r"주민|등록번호|생년월일|신원|고객|명의|본인|피보험자|resident|rrn|ssn", re.IGNORECASE
)
_CONTEXT_WINDOW = 30


def _digits_only(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())


def _valid_date(d13: str) -> bool:
    # 1/2/5/6 encode 1900s; 3/4/7/8 encode 2000s. The regex excludes
    # obsolete 1800s codes. Reject impossible calendar dates and future DOBs.
    century = 1900 if d13[6] in "1256" else 2000
    try:
        dob = date(century + int(d13[:2]), int(d13[2:4]), int(d13[4:6]))
    except ValueError:
        return False
    return dob <= date.today()


def _checksum_ok(d13: str) -> bool:
    total = sum(int(d13[i]) * _WEIGHTS[i] for i in range(12))
    return (11 - total % 11) % 10 == int(d13[12])


def scan(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _RRN.finditer(text):
        digits = _digits_only(m.group(0))
        if len(digits) != 13 or not _valid_date(digits):
            continue
        if m.group(4) == " ":
            lo = max(0, m.start() - _CONTEXT_WINDOW)
            hi = min(len(text), m.end() + _CONTEXT_WINDOW)
            if not _SPACE_CONTEXT.search(text[lo:hi]):
                continue
        rule = "rrn-checksum" if _checksum_ok(digits) else "rrn-format-only"
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
