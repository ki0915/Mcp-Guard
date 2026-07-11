"""Newline-delimited JSON-RPC DLP adapter for stdio MCP servers.

The adapter owns stdout exclusively for JSON-RPC messages. Audit records and
the child process's stderr are sent to stderr, so they can never corrupt the
protocol stream. Launch a server with::

    dlp-stdio-proxy -- python -m example_mcp_server
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import select
import sys
import threading
import uuid
from dataclasses import dataclass
from typing import Any, BinaryIO

from . import audit
from . import policy as policy_mod
from .detectors import Finding
from .detectors.engine import Scanner

_METHOD = "STDIO"
_PATH = "/stdio"
_CLIENT = "local-stdio"
_MAX_DEPTH = 64


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MessageDecision:
    """Result of filtering one protocol line.

    ``outbound`` is safe to forward in the original direction. ``client_error``
    is a generic response that must go to the MCP client instead. A blocked
    notification has neither field set, as JSON-RPC notifications have no
    response.
    """

    outbound: bytes | None
    client_error: bytes | None
    blocked: bool


@dataclass(frozen=True, slots=True)
class _TransformResult:
    value: Any
    blocked: bool = False
    changed: bool = False


class _CappedLineReader:
    """Read newline records with a bounded buffer and recover after overflow."""

    __slots__ = ("buffer", "reader")

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self.reader = reader
        self.buffer = bytearray()

    async def readline(self) -> tuple[bytes, bool] | None:
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self.buffer[: newline + 1])
                del self.buffer[: newline + 1]
                return raw, len(_strip_line_ending(raw)) > policy_mod.MAX_BODY_BYTES
            if len(self.buffer) > policy_mod.MAX_BODY_BYTES:
                await self._discard_remainder()
                return b"", True
            chunk = await self.reader.read(64 * 1024)
            if not chunk:
                if not self.buffer:
                    return None
                raw = bytes(self.buffer)
                self.buffer.clear()
                return raw, len(raw) > policy_mod.MAX_BODY_BYTES
            self.buffer.extend(chunk)

    async def _discard_remainder(self) -> None:
        self.buffer.clear()
        while True:
            chunk = await self.reader.read(64 * 1024)
            if not chunk:
                return
            newline = chunk.find(b"\n")
            if newline >= 0:
                self.buffer.extend(chunk[newline + 1 :])
                return


@dataclass(frozen=True, slots=True)
class _QueuedLine:
    item: tuple[bytes, bool] | None
    consumed: threading.Event


class MessageFilter:
    """Apply one validated HTTP DLP policy to JSON-RPC values."""

    def __init__(self, pol: policy_mod.Policy) -> None:
        self.policy = pol
        self.scanner = Scanner(pol.custom_rules, pol.custom_regex_timeout_ms)

    def filter_line(
        self, raw_line: bytes, direction: str, *, hard_oversize: bool = False
    ) -> MessageDecision:
        if direction not in {"request", "response"}:
            raise ValueError("direction must be request or response")
        rid = uuid.uuid4().hex[:12]
        payload = _strip_line_ending(raw_line)
        if not payload and not hard_oversize:
            return MessageDecision(None, None, False)

        if hard_oversize:
            self._control(rid, direction, "stdio-hard-line-limit", "block")
            return self._blocked(None, known_message=False)

        if len(payload) > self.policy.max_body_bytes:
            action = self.policy.oversize_action
            self._control(rid, direction, "oversized-body", action)
            if action == "block":
                parsed = self._parse(payload)
                return self._blocked(parsed, known_message=isinstance(parsed, dict))
            return MessageDecision(payload + b"\n", None, False)

        scan_enabled = (
            self.policy.scan_request if direction == "request" else self.policy.scan_response
        )
        if not scan_enabled:
            return MessageDecision(payload + b"\n", None, False)

        parsed = self._parse(payload)
        if not isinstance(parsed, dict):
            action = self.policy.unscannable_action
            self._control(rid, direction, "invalid-json-rpc", action)
            if action == "alert":
                return MessageDecision(payload + b"\n", None, False)
            return self._blocked(None, known_message=False)

        transformed = self._transform(parsed, direction, rid, depth=0, mutable=False)
        if transformed.blocked:
            return self._blocked(parsed, known_message=True)
        if not transformed.changed:
            return MessageDecision(payload + b"\n", None, False)
        try:
            encoded = _encode_message(transformed.value)
        except (TypeError, ValueError):
            self._control(rid, direction, "json-serialization", "block")
            return self._blocked(parsed, known_message=True)
        return MessageDecision(encoded, None, False)

    def _transform(
        self,
        value: Any,
        direction: str,
        rid: str,
        *,
        depth: int,
        mutable: bool,
    ) -> _TransformResult:
        if depth > _MAX_DEPTH:
            self._control(rid, direction, "json-depth-limit", "block")
            return _TransformResult(value, blocked=True)

        if isinstance(value, str):
            return self._filter_text(value, direction, rid, mutable=mutable)
        if value is None or isinstance(value, bool):
            return _TransformResult(value)
        if isinstance(value, (int, float)):
            # JSON-RPC identifiers and numeric types cannot be safely replaced
            # by a redact marker without changing protocol semantics.
            result = self._filter_text(str(value), direction, rid, mutable=False)
            return _TransformResult(value, blocked=result.blocked)
        if isinstance(value, list):
            changed = False
            output: list[Any] = []
            for item in value:
                result = self._transform(
                    item, direction, rid, depth=depth + 1, mutable=True
                )
                if result.blocked:
                    return _TransformResult(value, blocked=True)
                output.append(result.value)
                changed = changed or result.changed
            return _TransformResult(output if changed else value, changed=changed)
        if isinstance(value, dict):
            changed = False
            output: dict[str, Any] = {}
            for key, item in value.items():
                key_result = self._filter_text(key, direction, rid, mutable=False)
                if key_result.blocked:
                    return _TransformResult(value, blocked=True)
                item_mutable = not (depth == 0 and key in {"jsonrpc", "id", "method"})
                item_result = self._transform(
                    item,
                    direction,
                    rid,
                    depth=depth + 1,
                    mutable=item_mutable,
                )
                if item_result.blocked:
                    return _TransformResult(value, blocked=True)
                output[key] = item_result.value
                changed = changed or item_result.changed
            return _TransformResult(output if changed else value, changed=changed)

        self._control(rid, direction, "unsupported-json-type", "block")
        return _TransformResult(value, blocked=True)

    def _filter_text(
        self, text: str, direction: str, rid: str, *, mutable: bool
    ) -> _TransformResult:
        findings = self.scanner.scan(
            text,
            direction=direction,
            method=_METHOD,
            path=_PATH,
        )
        if not findings:
            return _TransformResult(text)

        blocking: list[Finding] = []
        redactions: list[Finding] = []
        for finding in findings:
            exception = self.policy.allow_for(
                text[finding.start : finding.end],
                finding,
                direction=direction,
                method=_METHOD,
                path=_PATH,
            )
            action = "allow" if exception is not None else self.policy.action_for(finding)
            audit.log_decision(
                rid=rid,
                direction=direction,
                method=_METHOD,
                path=_PATH,
                client=_CLIENT,
                finding=finding,
                action=action,
                exception_id=exception.id if exception else None,
            )
            if action == "block":
                blocking.append(finding)
            elif action == "redact":
                redactions.append(finding)

        if blocking:
            return _TransformResult(text, blocked=True)
        if not redactions:
            return _TransformResult(text)
        if not mutable:
            # Changing a key, method, id, or numeric JSON value could reroute a
            # call or break response correlation. Escalate redact to block.
            self._control(rid, direction, "immutable-json-redaction", "block")
            return _TransformResult(text, blocked=True)
        redacted = _replace_findings(text, redactions)
        return _TransformResult(redacted, changed=redacted != text)

    def _parse(self, payload: bytes) -> dict[str, Any] | None:
        try:
            text = payload.decode("utf-8")
            value = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
            return None
        return value if isinstance(value, dict) else None

    def _blocked(self, value: dict[str, Any] | None, *, known_message: bool) -> MessageDecision:
        if known_message and value is not None and "id" not in value:
            # JSON-RPC notifications never receive a response.
            return MessageDecision(None, None, True)
        identifier: Any = None
        if value is not None and "id" in value:
            candidate = value["id"]
            if candidate is None or (
                isinstance(candidate, (str, int, float)) and not isinstance(candidate, bool)
            ):
                identifier = candidate
        return MessageDecision(None, _generic_error(identifier), True)

    @staticmethod
    def _control(rid: str, direction: str, control: str, action: str) -> None:
        audit.log_control(
            rid=rid,
            direction=direction,
            method=_METHOD,
            path=_PATH,
            client=_CLIENT,
            control=control,
            action=action,
        )


def _replace_findings(text: str, findings: list[Finding]) -> str:
    merged: list[tuple[int, int, set[str]]] = []
    for finding in sorted(findings, key=lambda item: (item.start, item.end)):
        if merged and finding.start < merged[-1][1]:
            start, end, kinds = merged[-1]
            merged[-1] = (start, max(end, finding.end), kinds | {finding.kind})
        else:
            merged.append((finding.start, finding.end, {finding.kind}))
    for start, end, kinds in reversed(merged):
        label = next(iter(kinds)) if len(kinds) == 1 else "multiple"
        text = text[:start] + f"[REDACTED:{label}]" + text[end:]
    return text


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise _DuplicateKey("duplicate JSON object key")
        output[key] = value
    return output


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _strip_line_ending(raw_line: bytes) -> bytes:
    payload = raw_line[:-1] if raw_line.endswith(b"\n") else raw_line
    return payload[:-1] if payload.endswith(b"\r") else payload


def _encode_message(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
        + b"\n"
    )


def _generic_error(identifier: Any) -> bytes:
    return _encode_message(
        {
            "jsonrpc": "2.0",
            "id": identifier,
            "error": {"code": -32099, "message": "blocked by DLP policy"},
        }
    )


def _write_bytes(stream: BinaryIO, payload: bytes) -> None:
    stream.write(payload)
    stream.flush()


def _deliver_parent_line(
    loop: asyncio.AbstractEventLoop,
    queue: asyncio.Queue[_QueuedLine],
    stop: threading.Event,
    item: tuple[bytes, bool] | None,
) -> bool:
    consumed = threading.Event()
    try:
        loop.call_soon_threadsafe(queue.put_nowait, _QueuedLine(item, consumed))
    except RuntimeError:
        return False
    while not stop.is_set():
        if consumed.wait(0.1):
            return True
    return False


def _start_parent_reader(
    loop: asyncio.AbstractEventLoop,
    stream: BinaryIO,
    queue: asyncio.Queue[_QueuedLine],
    stop: threading.Event,
) -> threading.Thread:
    """Read stdin on a cancellable daemon thread with one-line backpressure."""

    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError):
        descriptor = None

    def read_chunk() -> bytes | None:
        if descriptor is None:
            return stream.read(64 * 1024)
        if os.name != "nt":
            readable, _, _ = select.select([descriptor], [], [], 0.1)
            if not readable:
                return None
        return os.read(descriptor, 64 * 1024)

    def read_lines() -> None:
        buffer = bytearray()
        discarding = False
        try:
            while not stop.is_set():
                newline = buffer.find(b"\n")
                if newline >= 0:
                    raw = bytes(buffer[: newline + 1])
                    del buffer[: newline + 1]
                    hard = discarding or len(_strip_line_ending(raw)) > policy_mod.MAX_BODY_BYTES
                    discarding = False
                    if not _deliver_parent_line(loop, queue, stop, (raw, hard)):
                        return
                    continue
                if not discarding and len(buffer) > policy_mod.MAX_BODY_BYTES:
                    buffer.clear()
                    discarding = True

                chunk = read_chunk()
                if chunk is None:
                    continue
                if not chunk:
                    if discarding:
                        if not _deliver_parent_line(loop, queue, stop, (b"", True)):
                            return
                    elif buffer:
                        raw = bytes(buffer)
                        hard = len(raw) > policy_mod.MAX_BODY_BYTES
                        if not _deliver_parent_line(loop, queue, stop, (raw, hard)):
                            return
                    _deliver_parent_line(loop, queue, stop, None)
                    return
                if discarding:
                    newline = chunk.find(b"\n")
                    if newline < 0:
                        continue
                    buffer.extend(chunk[newline + 1 :])
                    discarding = False
                    if not _deliver_parent_line(loop, queue, stop, (b"", True)):
                        return
                else:
                    buffer.extend(chunk)
        except (OSError, ValueError):
            if not stop.is_set():
                _deliver_parent_line(loop, queue, stop, None)

    thread = threading.Thread(
        target=read_lines,
        name="dlp-stdio-reader",
        daemon=True,
    )
    thread.start()
    return thread


def _cancel_parent_reader(thread: threading.Thread) -> None:
    """Cancel a Windows thread blocked in ``os.read`` during child failure."""
    if os.name != "nt" or not thread.is_alive() or thread.native_id is None:
        return
    import ctypes

    thread_terminate = 0x0001
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenThread.restype = ctypes.c_void_p
    kernel32.CancelSynchronousIo.argtypes = [ctypes.c_void_p]
    kernel32.CancelSynchronousIo.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenThread(thread_terminate, False, thread.native_id)
    if handle:
        try:
            kernel32.CancelSynchronousIo(handle)
        finally:
            kernel32.CloseHandle(handle)


async def run_proxy(
    command: list[str],
    pol: policy_mod.Policy,
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    stderr: BinaryIO | None = None,
) -> int:
    """Run ``command`` without a shell and proxy JSON-RPC until it exits."""
    if not command:
        raise ValueError("a child command is required")
    os.environ["DLP_AUDIT_STREAM"] = "stderr"
    input_stream = stdin or sys.stdin.buffer
    output_stream = stdout or sys.stdout.buffer
    error_stream = stderr or sys.stderr.buffer

    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=policy_mod.MAX_BODY_BYTES + 2,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise RuntimeError("child stdio pipes were not created")

    message_filter = MessageFilter(pol)
    output_lock = asyncio.Lock()
    child_lines = _CappedLineReader(process.stdout)
    input_queue: asyncio.Queue[_QueuedLine] = asyncio.Queue()
    input_stop = threading.Event()
    input_thread = _start_parent_reader(
        asyncio.get_running_loop(), input_stream, input_queue, input_stop
    )

    async def write_client(payload: bytes) -> None:
        async with output_lock:
            await asyncio.to_thread(_write_bytes, output_stream, payload)

    async def requests() -> None:
        try:
            while True:
                queued = await input_queue.get()
                try:
                    if queued.item is None:
                        break
                    raw_line, hard_oversize = queued.item
                    decision = message_filter.filter_line(
                        raw_line, "request", hard_oversize=hard_oversize
                    )
                    if decision.client_error is not None:
                        await write_client(decision.client_error)
                    if decision.outbound is not None:
                        process.stdin.write(decision.outbound)
                        await process.stdin.drain()
                finally:
                    queued.consumed.set()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            process.stdin.close()
            try:
                await process.stdin.wait_closed()
            except (BrokenPipeError, ConnectionResetError, asyncio.CancelledError):
                pass

    async def responses() -> None:
        while True:
            item = await child_lines.readline()
            if item is None:
                break
            raw_line, hard_oversize = item
            decision = message_filter.filter_line(
                raw_line, "response", hard_oversize=hard_oversize
            )
            if decision.client_error is not None:
                await write_client(decision.client_error)
            if decision.outbound is not None:
                await write_client(decision.outbound)

    async def child_errors() -> None:
        while chunk := await process.stderr.read(64 * 1024):
            await asyncio.to_thread(_write_bytes, error_stream, chunk)

    request_task = asyncio.create_task(requests())
    response_task = asyncio.create_task(responses())
    error_task = asyncio.create_task(child_errors())
    process_task = asyncio.create_task(process.wait())
    try:
        done, _pending = await asyncio.wait(
            {request_task, process_task}, return_when=asyncio.FIRST_COMPLETED
        )
        if process_task in done and not request_task.done():
            request_task.cancel()
        if request_task in done and not process_task.done():
            await process_task
        await asyncio.gather(response_task, error_task)
        request_result = (await asyncio.gather(request_task, return_exceptions=True))[0]
        if isinstance(request_result, BaseException) and not isinstance(
            request_result, asyncio.CancelledError
        ):
            raise request_result
    finally:
        input_stop.set()
        _cancel_parent_reader(input_thread)
        input_thread.join(timeout=2)
        if process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            await process.wait()
    return_code = process.returncode
    if return_code is None:
        return 1
    return return_code if return_code >= 0 else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Apply DLP policy to a newline-delimited JSON-RPC stdio server."
    )
    parser.add_argument("--policy", help="policy YAML (defaults to DLP_POLICY_PATH)")
    parser.add_argument(
        "--protected-values",
        help="protected-values YAML (defaults to DLP_PROTECTED_VALUES_PATH)",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="child command after --")
    return parser


def cli(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        _parser().print_usage(sys.stderr)
        return 2

    # stdout is the JSON-RPC transport. Never honor a conflicting inherited
    # setting here, as one audit line would corrupt the MCP connection.
    os.environ["DLP_AUDIT_STREAM"] = "stderr"
    try:
        pol = policy_mod.load(args.policy, args.protected_values)
    except (OSError, ValueError) as exc:
        print(f"dlp-stdio-proxy: configuration error: {exc}", file=sys.stderr)
        return 2
    try:
        return asyncio.run(run_proxy(command, pol))
    except (OSError, RuntimeError):
        print("dlp-stdio-proxy: child process could not be started", file=sys.stderr)
        return 127


def main() -> None:
    raise SystemExit(cli())


if __name__ == "__main__":
    main()
