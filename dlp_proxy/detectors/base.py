"""Core detection types shared by all detectors."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Finding:
    """A single match inside a scanned body.

    ``sample`` is pre-masked and safe to write to audit logs; the raw matched
    value is never stored on the finding.
    """

    kind: str  # detector category: rrn/phone/card/account/secret/keyword
    start: int  # character offset in scanned text
    end: int
    rule: str  # sub-rule that fired, e.g. "aws-access-key"
    sample: str  # masked sample for audit logs
    source: str = "raw"  # raw/nfkc/digit-compact/base64; never sensitive


def mask_sample(value: str, keep: int = 0) -> str:
    """Return a fixed non-reversible audit marker.

    The previous prefix-preserving sample leaked birth-date/token fragments.
    ``value`` and ``keep`` remain accepted for detector compatibility, but no
    portion of the match is ever returned.
    """
    del value, keep
    return "***"


def dedupe_overlaps(findings: list[Finding]) -> list[Finding]:
    """Drop findings overlapping an earlier-listed one (first wins).

    Callers list higher-confidence patterns first, so when two rules match the
    same span only the stronger rule survives.
    """
    out: list[Finding] = []
    for f in findings:
        if any(f.start < g.end and g.start < f.end for g in out):
            continue
        out.append(f)
    return out
