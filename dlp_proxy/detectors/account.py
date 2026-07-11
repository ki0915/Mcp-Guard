"""Korean bank account number detector (context-gated).

Account formats vary by bank (10-14 digits, assorted grouping), so raw digit
runs are far too noisy. A candidate must satisfy BOTH:

1. a hyphen-grouped digit pattern typical of KR banks, and
2. a context keyword (계좌, 입금, bank name, ...) within ±40 chars.

This deliberately trades recall for precision; see README limitations.
"""

from __future__ import annotations

import re

from .base import Finding, mask_sample

KIND = "account"

_ACCOUNT = re.compile(r"(?<![\d-])\d{2,6}-\d{2,6}-\d{2,8}(?:-\d{1,4})?(?![\d-])")

_CONTEXT = re.compile(
    r"계좌|계좌번호|입금|송금|account|acct|bank|"
    r"국민|신한|우리|하나|농협|기업|카카오뱅크|토스뱅크|새마을|우체국",
    re.IGNORECASE,
)

_WINDOW = 40


def scan(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _ACCOUNT.finditer(text):
        raw = m.group(0)
        digits = "".join(ch for ch in raw if ch.isdigit())
        if not (10 <= len(digits) <= 14):
            continue
        # Phone-shaped numbers (leading 0) are the phone detector's job.
        if raw[0] == "0":
            continue
        lo = max(0, m.start() - _WINDOW)
        hi = min(len(text), m.end() + _WINDOW)
        if not _CONTEXT.search(text[lo:hi]):
            continue
        out.append(
            Finding(
                kind=KIND,
                start=m.start(),
                end=m.end(),
                rule="account-context",
                sample=mask_sample(raw),
            )
        )
    return out
