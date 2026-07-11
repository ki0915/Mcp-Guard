"""Hardcoded credential detector.

Two strategies:

1. Known-prefix rules (AWS AKIA, GitHub ghp_, OpenAI sk-, Slack xox, Google
   AIza, JWT, PEM private key header) — high confidence, no entropy check.
2. Generic assignment rules: ``key/secret/token/password`` identifiers
   assigned a string of >=16 chars whose Shannon entropy exceeds 3.5
   bits/char. The entropy gate keeps dictionary-ish values like
   "mypassword123456" from firing while catching random key material.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from .base import Finding, dedupe_overlaps, mask_sample

KIND = "secret"

_PREFIX_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    ),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

# Identifier may carry arbitrary prefixes/suffixes (client_secret,
# AWS_SECRET_ACCESS_KEY, db-password-prod). Bare "key" is NOT in the core
# alternation ("monkey", "keyboard" would fire); it only counts with an
# api/access/private/secret qualifier somewhere in the identifier.
_ASSIGN = re.compile(
    r"(?i)\b[\w-]*(?:secret|token|passwd|password|credential|"
    r"api[_-]?key|access[_-]?key|private[_-]?key)[\w-]*[\"']?\s*[:=]\s*[\"']?"
    r"([A-Za-z0-9+/_=.!@#$%^&*?~-]{16,})"
)

_ENTROPY_MIN = 3.5  # bits per char


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def scan(text: str) -> list[Finding]:
    out: list[Finding] = []
    for rule, pattern in _PREFIX_RULES:
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
    for m in _ASSIGN.finditer(text):
        value = m.group(1)
        if shannon_entropy(value) < _ENTROPY_MIN:
            continue
        if value.count(".") > 4:  # likely hostname/version string
            continue
        out.append(
            Finding(
                kind=KIND,
                start=m.start(1),
                end=m.end(1),
                rule="generic-high-entropy",
                sample=mask_sample(value),
            )
        )
    return dedupe_overlaps(out)
