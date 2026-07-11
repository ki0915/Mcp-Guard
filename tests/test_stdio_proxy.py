"""stdio MCP adapter tests. Every apparent identifier is synthetic."""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

from dlp_proxy.policy import Policy
from dlp_proxy.stdio_proxy import MessageFilter, run_proxy

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC_PHONE = "010-0000-0000"
SYNTHETIC_RRN = "800101-1000008"


def _policy(**overrides) -> Policy:
    values = {
        "upstream": "http://unused.invalid",
        "default_action": "alert",
        "kind_actions": {
            "rrn": "block",
            "card": "block",
            "secret": "block",
            "phone": "redact",
            "account": "redact",
            "keyword": "alert",
        },
        "rule_actions": {"rrn-format-only": "alert"},
    }
    values.update(overrides)
    return Policy(**values)


def _line(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8") + b"\n"


def _json(payload: bytes | None) -> dict:
    assert payload is not None
    return json.loads(payload)


def test_request_payload_is_redacted_and_audit_uses_stderr(
    monkeypatch, capsys
) -> None:
    monkeypatch.setenv("DLP_AUDIT_STREAM", "stderr")
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"text": f"synthetic contact {SYNTHETIC_PHONE}"},
    }

    decision = MessageFilter(_policy()).filter_line(_line(message), "request")

    assert not decision.blocked
    assert decision.client_error is None
    assert _json(decision.outbound)["params"]["text"] == (
        "synthetic contact [REDACTED:phone]"
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert '"action": "redact"' in captured.err
    assert SYNTHETIC_PHONE not in captured.err


def test_blocked_request_gets_generic_error_and_is_not_forwarded(
    monkeypatch, capsys
) -> None:
    monkeypatch.setenv("DLP_AUDIT_STREAM", "stderr")
    message = {
        "jsonrpc": "2.0",
        "id": "synthetic-id-7",
        "method": "tools/call",
        "params": {"text": f"synthetic resident number {SYNTHETIC_RRN}"},
    }

    decision = MessageFilter(_policy()).filter_line(_line(message), "request")

    assert decision.blocked
    assert decision.outbound is None
    error = _json(decision.client_error)
    assert error == {
        "jsonrpc": "2.0",
        "id": "synthetic-id-7",
        "error": {"code": -32099, "message": "blocked by DLP policy"},
    }
    assert SYNTHETIC_RRN not in decision.client_error.decode("utf-8")
    assert "rrn" not in decision.client_error.decode("utf-8")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert SYNTHETIC_RRN not in captured.err


def test_blocked_notification_is_dropped_without_response(monkeypatch) -> None:
    monkeypatch.setenv("DLP_AUDIT_STREAM", "stderr")
    notification = {
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {"text": SYNTHETIC_RRN},
    }

    decision = MessageFilter(_policy()).filter_line(_line(notification), "request")

    assert decision.blocked
    assert decision.outbound is None
    assert decision.client_error is None


def test_response_is_redacted_or_replaced_with_generic_error(monkeypatch) -> None:
    monkeypatch.setenv("DLP_AUDIT_STREAM", "stderr")
    message_filter = MessageFilter(_policy())

    redact = message_filter.filter_line(
        _line({"jsonrpc": "2.0", "id": 3, "result": {"text": SYNTHETIC_PHONE}}),
        "response",
    )
    assert _json(redact.outbound)["result"]["text"] == "[REDACTED:phone]"

    block = message_filter.filter_line(
        _line({"jsonrpc": "2.0", "id": 4, "result": {"text": SYNTHETIC_RRN}}),
        "response",
    )
    assert block.blocked
    assert block.outbound is None
    assert _json(block.client_error)["error"]["code"] == -32099
    assert "rrn" not in block.client_error.decode("utf-8")


def test_invalid_json_fails_closed_without_reflecting_input(monkeypatch) -> None:
    monkeypatch.setenv("DLP_AUDIT_STREAM", "stderr")
    decision = MessageFilter(_policy()).filter_line(
        b'{"jsonrpc":"2.0","id":5,"params":"SYNTHETIC-BROKEN"\n',
        "request",
    )

    assert decision.blocked
    assert decision.outbound is None
    assert _json(decision.client_error) == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32099, "message": "blocked by DLP policy"},
    }
    assert b"SYNTHETIC-BROKEN" not in decision.client_error


def test_redaction_in_protocol_envelope_escalates_to_block(monkeypatch) -> None:
    monkeypatch.setenv("DLP_AUDIT_STREAM", "stderr")
    message = {
        "jsonrpc": "2.0",
        "id": SYNTHETIC_PHONE,
        "method": "tools/call",
        "params": {},
    }

    decision = MessageFilter(_policy()).filter_line(_line(message), "request")

    assert decision.blocked
    assert decision.outbound is None
    assert _json(decision.client_error)["error"]["code"] == -32099


def test_run_proxy_uses_exec_api_and_never_a_shell() -> None:
    source = inspect.getsource(run_proxy)

    assert "asyncio.create_subprocess_exec" in source
    assert "create_subprocess_shell" not in source


def test_cli_forces_audit_to_stderr_and_stdout_stays_json_only() -> None:
    child = (
        "import sys\n"
        "print('synthetic child diagnostic', file=sys.stderr, flush=True)\n"
        "for line in sys.stdin:\n"
        "    sys.stdout.write(line)\n"
        "    sys.stdout.flush()\n"
    )
    message = _line(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"text": SYNTHETIC_PHONE},
        }
    )
    env = os.environ.copy()
    env["DLP_AUDIT_STREAM"] = "stdout"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "dlp_proxy.stdio_proxy",
            "--policy",
            str(ROOT / "configs" / "policy.yaml"),
            "--",
            sys.executable,
            "-u",
            "-c",
            child,
        ],
        cwd=ROOT,
        env=env,
        input=message,
        capture_output=True,
        timeout=15,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    protocol_lines = completed.stdout.splitlines()
    assert len(protocol_lines) == 1
    assert _json(protocol_lines[0])["params"]["text"] == "[REDACTED:phone]"
    assert b'"event": "dlp.decision"' not in completed.stdout
    assert b'"event": "dlp.decision"' in completed.stderr
    assert b"synthetic child diagnostic" in completed.stderr
    assert b"diagnostic" not in completed.stdout
    assert SYNTHETIC_PHONE.encode() not in completed.stdout
    assert SYNTHETIC_PHONE.encode() not in completed.stderr


def test_adapter_exits_if_child_dies_while_client_stdin_is_open() -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "dlp_proxy.stdio_proxy",
            "--policy",
            str(ROOT / "configs" / "policy.yaml"),
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(0)",
        ],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.wait(timeout=10) == 0
        assert process.stdout is not None
        assert process.stdout.read() == b""
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
