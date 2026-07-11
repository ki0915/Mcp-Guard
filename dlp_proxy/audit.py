"""Audit logging: one JSON line per policy decision.

Written to stdout (collected by the container runtime / cluster log pipeline)
and optionally mirrored to ``DLP_AUDIT_FILE``. Raw matched values are never
logged — findings carry only masked samples. Every line carries the request
id (``rid``) so decisions and the forward record of one request correlate.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
from datetime import UTC, datetime
from typing import IO

from .detectors import Finding

_lock = threading.Lock()
_audit_file: IO[str] | None = None


def _file() -> IO[str] | None:
    """Open the mirror file once, lazily (env read at first use, not import)."""
    global _audit_file
    if _audit_file is None:
        path = os.environ.get("DLP_AUDIT_FILE", "")
        if not path:
            return None
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("audit destination must be a regular file")
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            _audit_file = os.fdopen(fd, "a", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise
    return _audit_file


def log_decision(
    *,
    rid: str,
    direction: str,  # "request" | "request-path" | "request-query" | "response"
    method: str,
    path: str,
    client: str,
    finding: Finding,
    action: str,
    exception_id: str | None = None,
) -> None:
    record = {
        "ts": datetime.now(UTC).isoformat(),
        "event": "dlp.decision",
        "rid": rid,
        "direction": direction,
        "method": method,
        "path": path,
        "client": client,
        "kind": finding.kind,
        "rule": finding.rule,
        "sample": finding.sample,
        "action": action,
    }
    if exception_id is not None:
        record["exception_id"] = exception_id
    _emit(record)


def log_control(
    *,
    rid: str,
    direction: str,
    method: str,
    path: str,
    client: str,
    control: str,
    action: str,
) -> None:
    """Audit fail-closed/fail-open controls without body material."""
    _emit(
        {
            "ts": datetime.now(UTC).isoformat(),
            "event": "dlp.control",
            "rid": rid,
            "direction": direction,
            "method": method,
            "path": path,
            "client": client,
            "control": control,
            "action": action,
        }
    )


def log_passthrough(
    *, rid: str, method: str, path: str, client: str, status: int, ms: float
) -> None:
    _emit(
        {
            "ts": datetime.now(UTC).isoformat(),
            "event": "dlp.forward",
            "rid": rid,
            "method": method,
            "path": path,
            "client": client,
            "status": status,
            "duration_ms": round(ms, 2),
        }
    )


def _emit(record: dict) -> None:
    line = json.dumps(record, ensure_ascii=False)
    with _lock:
        print(line, file=sys.stdout, flush=True)
        fh = _file()
        if fh is not None:
            fh.write(line + "\n")
            fh.flush()
