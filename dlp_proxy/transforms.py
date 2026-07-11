"""Bounded scan views for common representation evasions.

The proxy always edits the original input.  Every derived character therefore
keeps an exact source span so a finding in an NFKC/compacted view can be mapped
back without reconstructing or logging the sensitive value.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

MAX_BASE64_TOKENS = 64
MAX_BASE64_TOKEN_CHARS = 4096
MAX_BASE64_DECODED_BYTES = 64 * 1024

_BASE64_TOKEN = re.compile(
    rf"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{{16,{MAX_BASE64_TOKEN_CHARS}}}={{0,2}}"
    r"(?![A-Za-z0-9+/_=-])"
)


@dataclass(frozen=True, slots=True)
class TextView:
    """Derived text plus an original half-open span for every character."""

    text: str
    starts: tuple[int, ...]
    ends: tuple[int, ...]
    source: str

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        if start < 0 or end <= start or end > len(self.text):
            raise ValueError("derived finding has an invalid span")
        return self.starts[start], self.ends[end - 1]


@dataclass(frozen=True, slots=True)
class Base64View:
    """A decoded token whose findings map to the complete encoded token."""

    text: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class DecodeResult:
    views: tuple[Base64View, ...]
    limit_exceeded: bool = False


def normalized_views(text: str) -> tuple[TextView, ...]:
    """Return only changed NFKC and digit-compacted views.

    Digit compaction removes a run of whitespace/Unicode formatting controls
    only when it sits between two decimal digits.  Punctuation is deliberately
    retained to avoid turning arbitrary prose into identifiers.
    """
    nfkc = _nfkc_view(text)
    out: list[TextView] = []
    if nfkc.text != text:
        out.append(nfkc)
    else:
        nfkc = TextView(nfkc.text, nfkc.starts, nfkc.ends, "raw")
    compact = _digit_compact_view(nfkc)
    if compact.text != nfkc.text:
        out.append(compact)
    return tuple(out)


def decode_base64_views(text: str) -> DecodeResult:
    """Decode bounded UTF-8 Base64 tokens without recursive decoding."""
    views: list[Base64View] = []
    total = 0
    candidates = 0
    for match in _BASE64_TOKEN.finditer(text):
        candidates += 1
        if candidates > MAX_BASE64_TOKENS:
            return DecodeResult(tuple(views), limit_exceeded=True)
        token = match.group(0)
        payload = token + "=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(payload, altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            continue
        total += len(decoded)
        if total > MAX_BASE64_DECODED_BYTES:
            return DecodeResult(tuple(views), limit_exceeded=True)
        try:
            decoded_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(decoded_text) < 8 or not _mostly_printable(decoded_text):
            continue
        views.append(Base64View(decoded_text, match.start(), match.end()))
    return DecodeResult(tuple(views))


def _nfkc_view(text: str) -> TextView:
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for index, char in enumerate(text):
        normalized = unicodedata.normalize("NFKC", char)
        for output in normalized:
            chars.append(output)
            starts.append(index)
            ends.append(index + 1)
    return TextView("".join(chars), tuple(starts), tuple(ends), "nfkc")


def _digit_compact_view(view: TextView) -> TextView:
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    removable = _removable_separator_indexes(view.text)
    index = 0
    while index < len(view.text):
        if index not in removable:
            chars.append(view.text[index])
            starts.append(view.starts[index])
            ends.append(view.ends[index])
        index += 1
    source = "nfkc+digit-compact" if view.source == "nfkc" else "digit-compact"
    return TextView("".join(chars), tuple(starts), tuple(ends), source)


def _digit_separator(char: str) -> bool:
    return char.isspace() or unicodedata.category(char) == "Cf"


def _removable_separator_indexes(text: str) -> set[int]:
    """Select suspicious separators, preserving normal one-gap number groups."""
    removable: set[int] = set()
    index = 0
    while index < len(text):
        if not text[index].isdecimal():
            index += 1
            continue
        runs: list[tuple[int, int]] = []
        cursor = index + 1
        while cursor < len(text):
            if text[cursor].isdecimal():
                cursor += 1
                continue
            if not _digit_separator(text[cursor]):
                break
            run_start = cursor
            while cursor < len(text) and _digit_separator(text[cursor]):
                cursor += 1
            if cursor >= len(text) or not text[cursor].isdecimal():
                break
            runs.append((run_start, cursor))
        contains_format_control = any(
            unicodedata.category(text[position]) == "Cf"
            for start, end in runs
            for position in range(start, end)
        )
        if len(runs) >= 2 or contains_format_control:
            for start, end in runs:
                removable.update(range(start, end))
        index = max(index + 1, cursor)
    return removable


def _mostly_printable(text: str) -> bool:
    printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
    return printable / max(1, len(text)) >= 0.85
