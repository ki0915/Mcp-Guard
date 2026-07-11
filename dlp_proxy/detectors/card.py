"""Payment card number detector (Luhn-validated).

Matches 14-16 digit runs, optionally grouped by hyphen/space, then validates
with the Luhn algorithm and a first-digit IIN filter. Non-Luhn digit runs
(order numbers, timestamps) do not fire.
"""

from __future__ import annotations

import re

from .base import Finding, mask_sample

KIND = "card"

_CARD = re.compile(r"(?<![\d-])(?:\d{4}[- ]?){3}\d{2,4}(?![\d-])")

# First digits seen on cards circulating in KR: Visa 4, MC 2/5, Amex 3,
# domestic/UnionPay 6/9. Filters Luhn-valid noise starting 0/1/7/8.
_IIN_FIRST = frozenset("234569")


def _luhn_ok(digits: str) -> bool:
    total = 0
    double = False
    for ch in reversed(digits):
        d = int(ch)
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def scan(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _CARD.finditer(text):
        digits = "".join(ch for ch in m.group(0) if ch.isdigit())
        if not (14 <= len(digits) <= 16):
            continue
        if digits[0] not in _IIN_FIRST or not _luhn_ok(digits):
            continue
        out.append(
            Finding(
                kind=KIND,
                start=m.start(),
                end=m.end(),
                rule="card-luhn",
                sample=mask_sample(m.group(0)),
            )
        )
    return out
