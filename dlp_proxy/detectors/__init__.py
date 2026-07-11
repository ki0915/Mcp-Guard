from .base import Finding, dedupe_overlaps, mask_sample


def scan(text: str) -> list[Finding]:
    """Lazy compatibility wrapper that avoids policy/custom import cycles."""
    from .engine import scan as engine_scan

    return engine_scan(text)

__all__ = ["Finding", "dedupe_overlaps", "mask_sample", "scan"]
