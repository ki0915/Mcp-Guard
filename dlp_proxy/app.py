"""ASGI reverse proxy with DLP inspection.

Sits between clients and an external LLM API / MCP server. Buffers each
request and response body (up to a size cap), scans decodable text — body,
URL path, and query string — with the detection engine, applies policy
(redact/block/alert), and forwards via httpx.

Local endpoints (never proxied): /healthz, /metrics, /policy/status.
"""

from __future__ import annotations

import codecs
import os
import time
import uuid
from collections import Counter
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from urllib.parse import parse_qsl, quote, unquote, unquote_plus, urlencode

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from . import audit
from . import policy as policy_mod
from .detectors import Finding, engine

# Hop-by-hop headers must not be forwarded (RFC 9110 §7.6.1).
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)

# Content types we will attempt a cp949 fallback for when UTF-8 fails.
# Korean legacy encodings are common enough that a Korea-focused DLP tool
# must not fail-open on them; arbitrary binary types stay passthrough
# because cp949 "successfully" decodes most byte pairs into garbage.
_TEXTUAL_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/x-www-form-urlencoded",
)
_MAX_QUERY_BYTES = 16 * 1024
_MAX_QUERY_FIELDS = 128
_PATH_DECODE_ROUNDS = 5


def _connection_header_tokens(values: Iterable[str]) -> frozenset[str]:
    """Return lower-cased fields nominated by RFC ``Connection`` headers."""
    return frozenset(
        token.strip().lower()
        for value in values
        for token in value.split(",")
        if token.strip()
    )


class Ctx:
    """Per-request context handed through scan/policy helpers."""

    __slots__ = (
        "rid",
        "method",
        "path",
        "scope_path",
        "ambiguous_path",
        "audit_path",
        "client",
        "pol",
        "scanner",
        "metrics",
    )

    def __init__(self, rid: str, method: str, path: str, client: str, pol, scanner, metrics):
        self.rid = rid
        self.method = method
        self.path = path
        self.scope_path, self.ambiguous_path = _canonical_path(path)
        self.audit_path = path
        self.client = client
        self.pol = pol
        self.scanner = scanner
        self.metrics = metrics

    def scan(self, text: str, direction: str) -> list[Finding]:
        return self.scanner.scan(
            text,
            direction=direction,
            method=self.method,
            path=self.scope_path,
        )


def _canonical_path(path: str) -> tuple[str, bool]:
    """Decode policy/forwarding path consistently and flag ambiguous routing."""
    decoded = path
    decode_limit_hit = True
    for _ in range(_PATH_DECODE_ROUNDS):
        candidate = unquote(decoded)
        if candidate == decoded:
            decode_limit_hit = False
            break
        decoded = candidate
    segments = decoded.split("/")
    ambiguous = (
        decode_limit_hit
        or any(segment in {".", ".."} for segment in segments)
        or "\\" in decoded
        or "//" in decoded
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in decoded)
    )
    return decoded, ambiguous


def _replace_findings(text: str, findings: list[Finding]) -> str:
    """Merge overlapping spans, then redact without corrupting offsets."""
    if not findings:
        return text
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


def apply_policy(
    text: str, findings: list[Finding], ctx: Ctx, direction: str
) -> tuple[str, list[Finding]]:
    """Evaluate every overlap; any non-exempt block wins."""
    blocking: list[Finding] = []
    redactions: list[Finding] = []
    for f in findings:
        exception = ctx.pol.allow_for(
            text[f.start : f.end],
            f,
            direction=direction,
            method=ctx.method,
            path=ctx.scope_path,
        )
        action = "allow" if exception is not None else ctx.pol.action_for(f)
        audit.log_decision(
            rid=ctx.rid,
            direction=direction,
            method=ctx.method,
            path=ctx.audit_path,
            client=ctx.client,
            finding=f,
            action=action,
            exception_id=exception.id if exception else None,
        )
        ctx.metrics[("decision", action, f.kind)] += 1
        if action == "block":
            blocking.append(f)
        elif action == "redact":
            redactions.append(f)
    if blocking:
        return text, blocking
    return _replace_findings(text, redactions), []


def _blocked_response(ctx: Ctx, direction: str, findings: list[Finding]) -> JSONResponse:
    content: dict = {"error": "dlp_blocked", "message": f"{direction} blocked by DLP policy"}
    if ctx.pol.expose_block_detail:
        content["kinds"] = sorted(
            {f.kind for f in findings if ctx.pol.action_for(f) == "block"}
        )
    return JSONResponse(status_code=403, content=content)


def _control_decision(ctx: Ctx, direction: str, control: str, action: str) -> bool:
    audit.log_control(
        rid=ctx.rid,
        direction=direction,
        method=ctx.method,
        path=ctx.audit_path,
        client=ctx.client,
        control=control,
        action=action,
    )
    ctx.metrics[f"control.{control}.{direction}.{action}"] += 1
    return action == "block"


def _control_response(error: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": error, "message": message})


def _upstream_headers(
    upstream_response: httpx.Response, *, content_length: int | None
) -> list[tuple[bytes, bytes]]:
    """Copy end-to-end headers after httpx has decoded the response body."""
    raw: list[tuple[bytes, bytes]] = []
    blocked = _HOP_BY_HOP | _connection_header_tokens(
        upstream_response.headers.get_list("connection")
    )
    for key, value in upstream_response.headers.multi_items():
        lowered = key.lower()
        if lowered in blocked or lowered in {"content-encoding", "content-length"}:
            continue
        raw.append((key.encode("latin-1"), value.encode("latin-1")))
    if content_length is not None:
        raw.append((b"content-length", str(content_length).encode("latin-1")))
    return raw


def _streaming_upstream_response(
    upstream_response: httpx.Response,
    iterator: AsyncIterator[bytes],
    buffered: list[bytes] | None = None,
) -> StreamingResponse:
    """Relay an explicitly unscanned response without unbounded buffering."""

    async def relay() -> AsyncIterator[bytes]:
        try:
            for chunk in buffered or ():
                yield chunk
            async for chunk in iterator:
                yield chunk
        finally:
            await upstream_response.aclose()

    response = StreamingResponse(relay(), status_code=upstream_response.status_code)
    response.raw_headers = _upstream_headers(upstream_response, content_length=None)
    return response


def _decode(body: bytes, content_type: str) -> tuple[str | None, str]:
    """Decode a body to text; returns (text, encoding) or (None, "").

    Declared charset wins; otherwise UTF-8, then cp949 for textual content
    types (legacy Korean). Undecodable bodies pass through unscanned.
    """
    charset = ""
    for part in content_type.split(";")[1:]:
        k, _, v = part.strip().partition("=")
        if k.lower() == "charset" and v:
            charset = v.strip("\"' ").lower()

    candidates = []
    if charset:
        candidates.append(charset)
    else:
        candidates.append("utf-8")
        base_type = content_type.split(";")[0].strip().lower()
        if any(base_type.startswith(t) for t in _TEXTUAL_TYPES):
            candidates.append("cp949")

    for enc in candidates:
        try:
            codecs.lookup(enc)
        except LookupError:
            continue
        try:
            return body.decode(enc), enc
        except (UnicodeDecodeError, ValueError):
            continue
    return None, ""


def _scan_query(raw_query: str, ctx: Ctx) -> tuple[str, list[Finding], bool]:
    """Scan and policy-apply the query string.

    Returns (new_raw_query, blocking_findings, changed). Keys and values are
    scanned decoded, redacted per policy, then re-encoded; a non-empty
    blocking_findings list means the request must be rejected.
    """
    pairs = parse_qsl(
        raw_query,
        keep_blank_values=True,
        max_num_fields=_MAX_QUERY_FIELDS,
    )
    if not pairs:
        # Non-k=v query (rare); scan the decoded blob as one text.
        decoded = unquote_plus(raw_query)
        findings = ctx.scan(decoded, "request-query")
        if not findings:
            return raw_query, [], False
        new_text, blocking = apply_policy(decoded, findings, ctx, "request-query")
        if blocking:
            return raw_query, blocking, False
        return urlencode({"": new_text})[1:], [], True

    changed = False
    out: list[tuple[str, str]] = []
    for key, value in pairs:
        new_kv = []
        for part in (key, value):
            findings = ctx.scan(part, "request-query")
            if findings:
                new_part, blocking = apply_policy(part, findings, ctx, "request-query")
                if blocking:
                    return raw_query, blocking, False
                if new_part != part:
                    changed = True
                part = new_part
            new_kv.append(part)
        out.append((new_kv[0], new_kv[1]))
    return urlencode(out), [], changed


async def _read_capped(
    request: Request, cap: int
) -> tuple[bytes | None, AsyncIterator[bytes] | None]:
    """Read the request body up to ``cap`` bytes.

    Returns (body, None) when fully buffered, or (None, stream) when the cap
    was exceeded — the stream replays buffered chunks then the remainder, so
    oversized bodies are forwarded without ever being held in memory whole.
    """
    chunks: list[bytes] = []
    total = 0
    stream = request.stream()
    async for chunk in stream:
        chunks.append(chunk)
        total += len(chunk)
        if total > cap:

            async def replay() -> AsyncIterator[bytes]:
                for c in chunks:
                    yield c
                async for c in stream:
                    yield c

            return None, replay()
    return b"".join(chunks), None


def create_app(pol: policy_mod.Policy | None = None) -> FastAPI:
    pol = pol or policy_mod.load()
    scanner = engine.Scanner(pol.custom_rules, pol.custom_regex_timeout_ms)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.client = httpx.AsyncClient(
            base_url=pol.upstream,
            timeout=float(os.environ.get("DLP_UPSTREAM_TIMEOUT", "60")),
        )
        yield
        await app.state.client.aclose()

    app = FastAPI(title="dlp-proxy", lifespan=lifespan)
    app.state.metrics = Counter()
    app.state.scanner = scanner

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/policy/status")
    async def policy_status() -> JSONResponse:
        return JSONResponse(
            content=pol.safe_summary(),
            headers={"cache-control": "no-store"},
        )

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        """Prometheus exposition format."""
        lines = [
            "# HELP dlp_decisions_total DLP policy decisions by action and kind.",
            "# TYPE dlp_decisions_total counter",
        ]
        simple = [
            "# HELP dlp_events_total Proxy-level events.",
            "# TYPE dlp_events_total counter",
        ]
        for key, n in sorted(app.state.metrics.items(), key=lambda kv: str(kv[0])):
            if isinstance(key, tuple) and key[0] == "decision":
                _, action, kind = key
                lines.append(f'dlp_decisions_total{{action="{action}",kind="{kind}"}} {n}')
            else:
                simple.append(f'dlp_events_total{{event="{key}"}} {n}')
        return PlainTextResponse("\n".join(lines + simple) + "\n")

    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    async def proxy(request: Request, full_path: str) -> Response:
        started = time.perf_counter()
        mx: Counter = request.app.state.metrics
        ctx = Ctx(
            rid=uuid.uuid4().hex[:12],
            method=request.method,
            path="/" + full_path,
            client=request.client.host if request.client else "unknown",
            pol=pol,
            scanner=request.app.state.scanner,
            metrics=mx,
        )

        if ctx.ambiguous_path:
            ctx.audit_path = "[REJECTED:ambiguous-path]"
            _control_decision(ctx, "request-path", "ambiguous-path", "block")
            return _control_response(
                "dlp_ambiguous_path",
                "request path normalization is ambiguous",
                400,
            )

        # --- URL path + query string -------------------------------------
        raw_query = request.url.query
        forward_path = quote(ctx.scope_path, safe="/")
        if raw_query:
            query_bytes = len(raw_query.encode("utf-8"))
            query_fields = raw_query.count("&") + 1
            if query_bytes > _MAX_QUERY_BYTES or query_fields > _MAX_QUERY_FIELDS:
                _control_decision(ctx, "request-query", "query-limit", "block")
                return _control_response(
                    "dlp_query_too_large",
                    "request query exceeds the DLP inspection limit",
                    414,
                )
        if pol.scan_request:
            # A plus sign is literal in a URL path; only query strings use
            # application/x-www-form-urlencoded's plus-as-space convention.
            decoded_path = ctx.scope_path
            path_findings = ctx.scan(decoded_path, "request-path")
            if path_findings:
                # Never put a detected raw value back into the audit log's
                # path field, including alert-only findings.
                ctx.audit_path = _replace_findings(decoded_path, path_findings)
                new_path, blocking = apply_policy(
                    decoded_path, path_findings, ctx, "request-path"
                )
                if blocking:
                    mx["blocked.request"] += 1
                    return _blocked_response(ctx, "request", blocking)
                if new_path != decoded_path:
                    # Redacting path data can change upstream routing, but
                    # forwarding the original would violate the redact policy.
                    forward_path = quote(new_path, safe="/")
            if raw_query:
                new_query, blocking, changed = _scan_query(raw_query, ctx)
                if blocking:
                    mx["blocked.request"] += 1
                    return _blocked_response(ctx, "request", blocking)
                if changed:
                    raw_query = new_query

        # --- request body -------------------------------------------------
        body, oversized_stream = await _read_capped(request, pol.max_body_bytes)
        out_content: bytes | AsyncIterator[bytes]
        req_ct = request.headers.get("content-type", "")
        if oversized_stream is not None:
            mx["oversized.request"] += 1
            if _control_decision(
                ctx, "request", "oversized-body", pol.oversize_action
            ):
                return _control_response(
                    "dlp_body_too_large",
                    "request body exceeds the configured DLP scan limit",
                    413,
                )
            out_content = oversized_stream
        else:
            out_content = body
            if pol.scan_request and body:
                text, enc = _decode(body, req_ct)
                if text is None:
                    if _control_decision(
                        ctx, "request", "unscannable-body", pol.unscannable_action
                    ):
                        return _control_response(
                            "dlp_unscannable_body",
                            "request body could not be decoded for DLP inspection",
                            415,
                        )
                else:
                    findings = ctx.scan(text, "request")
                    if findings:
                        new_text, blocking = apply_policy(text, findings, ctx, "request")
                        if blocking:
                            mx["blocked.request"] += 1
                            return _blocked_response(ctx, "request", blocking)
                        if new_text != text:
                            out_content = new_text.encode(enc, errors="replace")

        blocked_request_headers = _HOP_BY_HOP | _connection_header_tokens(
            request.headers.getlist("connection")
        )
        fwd_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in blocked_request_headers
        }
        url = forward_path + ("?" + raw_query if raw_query else "")
        upstream: httpx.AsyncClient = request.app.state.client
        try:
            upstream_request = upstream.build_request(
                ctx.method,
                url,
                content=out_content,
                headers=fwd_headers,
            )
            up_resp = await upstream.send(upstream_request, stream=True)
        except httpx.HTTPError:
            mx["upstream.error"] += 1
            return JSONResponse(
                status_code=502,
                content={
                    "error": "upstream_unreachable",
                    "message": "the configured upstream could not be reached",
                },
            )

        # --- response body ------------------------------------------------
        response_iterator = up_resp.aiter_bytes(chunk_size=64 * 1024)
        if not pol.scan_response:
            elapsed_ms = (time.perf_counter() - started) * 1000
            audit.log_passthrough(
                rid=ctx.rid,
                method=ctx.method,
                path=ctx.audit_path,
                client=ctx.client,
                status=up_resp.status_code,
                ms=elapsed_ms,
            )
            mx["forwarded"] += 1
            return _streaming_upstream_response(up_resp, response_iterator)

        response_chunks: list[bytes] = []
        response_size = 0
        response_oversized = False
        try:
            async for chunk in response_iterator:
                response_chunks.append(chunk)
                response_size += len(chunk)
                if response_size > pol.max_body_bytes:
                    response_oversized = True
                    break
        except httpx.HTTPError:
            await up_resp.aclose()
            mx["upstream.error"] += 1
            return JSONResponse(
                status_code=502,
                content={
                    "error": "upstream_unreachable",
                    "message": "the configured upstream response was interrupted",
                },
            )

        if response_oversized:
            mx["oversized.response"] += 1
            if _control_decision(
                ctx, "response", "oversized-body", pol.oversize_action
            ):
                await up_resp.aclose()
                return _control_response(
                    "dlp_body_too_large",
                    "upstream response exceeds the configured DLP scan limit",
                    403,
                )
            elapsed_ms = (time.perf_counter() - started) * 1000
            audit.log_passthrough(
                rid=ctx.rid,
                method=ctx.method,
                path=ctx.audit_path,
                client=ctx.client,
                status=up_resp.status_code,
                ms=elapsed_ms,
            )
            mx["forwarded"] += 1
            return _streaming_upstream_response(
                up_resp,
                response_iterator,
                response_chunks,
            )

        await up_resp.aclose()
        resp_body = b"".join(response_chunks)
        resp_ct = up_resp.headers.get("content-type", "")
        if resp_body:
            text, enc = _decode(resp_body, resp_ct)
            if text is None:
                if _control_decision(
                    ctx, "response", "unscannable-body", pol.unscannable_action
                ):
                    return _control_response(
                        "dlp_unscannable_body",
                        "upstream response could not be decoded for DLP inspection",
                        403,
                    )
            else:
                findings = ctx.scan(text, "response")
                if findings:
                    new_text, blocking = apply_policy(text, findings, ctx, "response")
                    if blocking:
                        mx["blocked.response"] += 1
                        return _blocked_response(ctx, "response", blocking)
                    if new_text != text:
                        resp_body = new_text.encode(enc, errors="replace")

        elapsed_ms = (time.perf_counter() - started) * 1000
        audit.log_passthrough(
            rid=ctx.rid,
            method=ctx.method,
            path=ctx.audit_path,
            client=ctx.client,
            status=up_resp.status_code,
            ms=elapsed_ms,
        )
        mx["forwarded"] += 1

        resp = Response(content=resp_body, status_code=up_resp.status_code)
        resp.raw_headers = _upstream_headers(up_resp, content_length=len(resp_body))
        return resp

    return app
