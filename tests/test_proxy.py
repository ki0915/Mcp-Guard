"""End-to-end proxy tests: block / redact / alert / passthrough behavior.

Uses httpx.MockTransport injected into the app's upstream client so no real
network is involved.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import yaml

from dlp_proxy import policy as policy_mod
from dlp_proxy.app import _canonical_path, create_app
from dlp_proxy.custom_rules import compile_custom_rules
from dlp_proxy.policy import Policy

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def make_policy(**overrides) -> Policy:
    kwargs = dict(
        upstream="http://upstream.test",
        default_action="alert",
        kind_actions={
            "rrn": "block",
            "card": "block",
            "secret": "block",
            "phone": "redact",
            "account": "redact",
            "keyword": "alert",
        },
        rule_actions={"rrn-format-only": "alert"},
        expose_block_detail=True,
    )
    kwargs.update(overrides)
    return Policy(**kwargs)


def echo_upstream(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "echo": request.content.decode("utf-8", errors="replace"),
            "path": request.url.path,
            "query": request.url.query.decode(),
        },
    )


@asynccontextmanager
async def make_client(upstream_handler=echo_upstream, policy: Policy | None = None):
    app = create_app(policy or make_policy())
    # httpx ASGITransport doesn't run lifespan events; install the upstream
    # client by hand and close both clients on exit.
    app.state.client = httpx.AsyncClient(
        base_url="http://upstream.test", transport=httpx.MockTransport(upstream_handler)
    )
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy.test"
    )
    try:
        yield client
    finally:
        await client.aclose()
        await app.state.client.aclose()


async def test_clean_request_passes_through() -> None:
    async with make_client() as client:
        resp = await client.post("/v1/chat", content="회의 일정 요약해줘".encode())
        assert resp.status_code == 200
        assert "회의 일정" in resp.json()["echo"]


@pytest.mark.parametrize(
    "path",
    ["/allowed/../admin", "/allowed/%2e%2e/admin", "/allowed\\admin", "//admin"],
)
async def test_ambiguous_path_is_rejected(path: str) -> None:
    _, ambiguous = _canonical_path(path)
    assert ambiguous


async def test_encoded_dot_segment_never_reaches_upstream() -> None:
    def must_not_run(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"ambiguous path was forwarded: {request.url}")

    async with make_client(must_not_run) as client:
        response = await client.get("/allowed/%2e%2e/admin")
        assert response.status_code == 400
        assert response.json()["error"] == "dlp_ambiguous_path"


async def test_query_field_limit_never_reaches_upstream() -> None:
    def must_not_run(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"oversized query was forwarded: {request.url}")

    query = "&".join(f"synthetic{i}=ok" for i in range(129))
    async with make_client(must_not_run) as client:
        response = await client.get(f"/search?{query}")
        assert response.status_code == 414
        assert response.json()["error"] == "dlp_query_too_large"


async def test_decompressed_response_limit_blocks_compression_bomb() -> None:
    def compressed_upstream(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            content=gzip.compress(b"SYNTHETIC-CONTENT-" * 100),
            headers={
                "content-type": "text/plain",
                "content-encoding": "gzip",
            },
        )

    pol = make_policy(max_body_bytes=128, oversize_action="block")
    async with make_client(compressed_upstream, pol) as client:
        response = await client.post("/v1/chat", content=b"safe")
        assert response.status_code == 403
        assert response.json()["error"] == "dlp_body_too_large"


async def test_rrn_request_blocked() -> None:
    async with make_client() as client:
        resp = await client.post("/v1/chat", content="합성 주민번호 800101-1000008".encode())
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"] == "dlp_blocked"
        assert "rrn" in body["kinds"]


async def test_phone_request_redacted() -> None:
    async with make_client() as client:
        resp = await client.post("/v1/chat", content="가상 연락처 010-0000-0000".encode())
        assert resp.status_code == 200
        echoed = resp.json()["echo"]
        assert "010-0000-0000" not in echoed
        assert "[REDACTED:phone]" in echoed


async def test_request_connection_nominated_header_is_not_forwarded() -> None:
    def inspect_headers(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "removed": request.headers.get("x-remove"),
                "kept": request.headers.get("x-keep"),
            },
        )

    async with make_client(inspect_headers) as client:
        response = await client.get(
            "/headers",
            headers={
                "connection": "keep-alive, x-remove",
                "x-remove": "synthetic-hop-value",
                "x-keep": "synthetic-end-to-end",
            },
        )
        assert response.status_code == 200
        assert response.json() == {"removed": None, "kept": "synthetic-end-to-end"}


async def test_response_connection_nominated_header_is_not_forwarded() -> None:
    def connection_response(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            content=b"safe",
            headers=[
                ("connection", "x-remove"),
                ("x-remove", "synthetic-hop-value"),
                ("x-keep", "synthetic-end-to-end"),
            ],
        )

    async with make_client(connection_response) as client:
        response = await client.get("/headers")
        assert response.status_code == 200
        assert "x-remove" not in response.headers
        assert response.headers["x-keep"] == "synthetic-end-to-end"


async def test_keyword_alert_passes_through() -> None:
    async with make_client() as client:
        resp = await client.post("/v1/chat", content="대외비 문서 요약".encode())
        assert resp.status_code == 200
        assert "대외비" in resp.json()["echo"]


async def test_query_param_with_rrn_blocked() -> None:
    async with make_client() as client:
        resp = await client.get("/search", params={"q": "합성 주민번호 800101-1000008"})
        assert resp.status_code == 403
        assert resp.json()["error"] == "dlp_blocked"


async def test_query_param_with_phone_redacted() -> None:
    async with make_client() as client:
        resp = await client.get("/search", params={"q": "가상 연락처 010-0000-0000"})
        assert resp.status_code == 200
        forwarded_query = resp.json()["query"]
        assert "010-0000-0000" not in forwarded_query
        assert "REDACTED" in forwarded_query


async def test_path_phone_redacted_and_audit_path_masked(capsys) -> None:
    async with make_client() as client:
        resp = await client.get("/callback/010-0000-0000")
        assert resp.status_code == 200
        assert "010-0000-0000" not in resp.json()["path"]
        assert "[REDACTED:phone]" in resp.json()["path"]

    audit_output = capsys.readouterr().out
    assert "010-0000-0000" not in audit_output
    assert "[REDACTED:phone]" in audit_output


async def test_path_rrn_blocked_without_audit_leak(capsys) -> None:
    async with make_client() as client:
        resp = await client.get("/customer/800101-1000008")
        assert resp.status_code == 403

    audit_output = capsys.readouterr().out
    assert "800101-1000008" not in audit_output
    assert "[REDACTED:rrn]" in audit_output


async def test_euckr_body_scanned() -> None:
    async with make_client() as client:
        body = "합성 주민번호 800101-1000008".encode("euc-kr")
        resp = await client.post(
            "/v1/chat", content=body, headers={"content-type": "text/plain"}
        )
        assert resp.status_code == 403, "EUC-KR body must not bypass scanning"


async def test_response_with_pii_redacted() -> None:
    def leaky_upstream(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"answer": "고객 연락처는 010-9999-8888 입니다"})

    async with make_client(leaky_upstream) as client:
        resp = await client.post("/v1/chat", content=b"lookup customer")
        assert resp.status_code == 200
        assert "010-9999-8888" not in resp.text
        assert "[REDACTED:phone]" in resp.text


async def test_response_with_secret_blocked() -> None:
    def leaky_upstream(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"answer": "here is the key AKIAIOSFODNN7EXAMPLE"})

    async with make_client(leaky_upstream) as client:
        resp = await client.post("/v1/chat", content=b"what is our aws key")
        assert resp.status_code == 403
        assert resp.json()["error"] == "dlp_blocked"


async def test_multiple_set_cookie_preserved() -> None:
    def cookie_upstream(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[("set-cookie", "a=1; Path=/"), ("set-cookie", "b=2; Path=/")],
            json={"ok": True},
        )

    async with make_client(cookie_upstream) as client:
        resp = await client.get("/login")
        cookies = resp.headers.get_list("set-cookie")
        assert cookies == ["a=1; Path=/", "b=2; Path=/"]


async def test_oversized_body_blocked_by_default() -> None:
    pol = make_policy(max_body_bytes=64)
    async with make_client(policy=pol) as client:
        big = ("x" * 100 + " 합성 주민번호 800101-1000008").encode()
        resp = await client.post("/v1/chat", content=big)
        assert resp.status_code == 413
        assert resp.json()["error"] == "dlp_body_too_large"


async def test_oversized_body_alert_mode_is_explicit_fail_open() -> None:
    pol = make_policy(max_body_bytes=64, oversize_action="alert")
    async with make_client(policy=pol) as client:
        big = ("x" * 100 + " 합성 주민번호 800101-1000008").encode()
        resp = await client.post("/v1/chat", content=big)
        assert resp.status_code == 200
        assert "800101-1000008" in resp.json()["echo"]


async def test_binary_body_blocked_by_default() -> None:
    async with make_client() as client:
        resp = await client.post("/upload", content=b"\xff\xfe\x00binary\x00")
        assert resp.status_code == 415
        assert resp.json()["error"] == "dlp_unscannable_body"


async def test_binary_body_alert_mode_is_explicit_fail_open() -> None:
    pol = make_policy(unscannable_action="alert")
    async with make_client(policy=pol) as client:
        resp = await client.post("/upload", content=b"\xff\xfe\x00binary\x00")
        assert resp.status_code == 200


async def test_oversized_response_blocked_by_default() -> None:
    def large_upstream(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 128)

    pol = make_policy(max_body_bytes=64)
    async with make_client(large_upstream, pol) as client:
        resp = await client.post("/v1/chat", content=b"safe")
        assert resp.status_code == 403
        assert resp.json()["error"] == "dlp_body_too_large"


async def test_unscannable_response_blocked_by_default() -> None:
    def binary_upstream(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"\xff\xfe\x00binary\x00")

    async with make_client(binary_upstream) as client:
        resp = await client.post("/v1/chat", content=b"safe")
        assert resp.status_code == 403
        assert resp.json()["error"] == "dlp_unscannable_body"


async def test_healthz_not_proxied() -> None:
    async with make_client() as client:
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


async def test_metrics_prometheus_format() -> None:
    async with make_client() as client:
        await client.post("/v1/chat", content="가상 연락처 010-0000-0000".encode())
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert 'dlp_decisions_total{action="redact",kind="phone"}' in resp.text


async def test_block_detail_hidden_when_configured() -> None:
    pol = make_policy(expose_block_detail=False)
    async with make_client(policy=pol) as client:
        resp = await client.post("/v1/chat", content="합성 주민번호 800101-1000008".encode())
        assert resp.status_code == 403
        assert "kinds" not in resp.json()


async def test_upstream_down_returns_502() -> None:
    synthetic_secret = "SYNTH-UPSTREAM-ERROR-7Q9X"

    def failing(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"could not send {synthetic_secret}", request=request)

    async with make_client(failing) as client:
        resp = await client.post("/v1/chat", content=b"hello")
        assert resp.status_code == 502
        assert resp.json()["error"] == "upstream_unreachable"
        assert synthetic_secret not in resp.text
        assert set(resp.json()) == {"error", "message"}


async def test_audit_log_masks_values_and_has_rid(capsys) -> None:
    async with make_client() as client:
        await client.post("/v1/chat", content="합성 주민번호 800101-1000008".encode())
    out = capsys.readouterr().out
    decisions = [json.loads(line) for line in out.splitlines() if "dlp.decision" in line]
    assert decisions, "expected at least one audit decision line"
    for d in decisions:
        assert "800101-1000008" not in json.dumps(d, ensure_ascii=False)
        assert d["action"] == "block"
        assert d["rid"]


async def test_custom_block_is_not_shadowed_by_builtin_redact() -> None:
    rules = compile_custom_rules(
        [
            {
                "id": "synthetic-phone-escalation",
                "kind": "business_identifier",
                "action": "block",
                "matcher": {"type": "literal", "values": ["010-0000-0000"]},
            }
        ],
        policy_mod.VALID_ACTIONS,
    )
    pol = make_policy(
        custom_rules=rules,
        rule_actions={
            "rrn-format-only": "alert",
            "custom:synthetic-phone-escalation": "block",
        },
    )
    async with make_client(policy=pol) as client:
        resp = await client.post("/v1/chat", content="가상 연락처 010-0000-0000".encode())
        assert resp.status_code == 403


async def test_overlapping_redactions_are_merged_without_leak() -> None:
    rules = compile_custom_rules(
        [
            {
                "id": "synthetic-suffix",
                "kind": "business_identifier",
                "action": "redact",
                "matcher": {"type": "literal", "values": ["0000-0000"]},
            }
        ],
        policy_mod.VALID_ACTIONS,
    )
    pol = make_policy(
        custom_rules=rules,
        rule_actions={
            "rrn-format-only": "alert",
            "custom:synthetic-suffix": "redact",
        },
    )
    async with make_client(policy=pol) as client:
        resp = await client.post("/v1/chat", content="가상 연락처 010-0000-0000".encode())
        assert resp.status_code == 200
        assert "010-0000-0000" not in resp.json()["echo"]
        assert "[REDACTED:multiple]" in resp.json()["echo"]


async def test_protected_value_blocks_and_status_never_exposes_it(tmp_path: Path) -> None:
    protected_value = "SYNTH-ORION-ALPHA-7Q9X"
    protected = {
        "version": 1,
        "protected_values": [
            {"id": "project-code", "action": "block", "literal": protected_value}
        ],
        "allowlist": [],
    }
    protected_path = tmp_path / "protected.yaml"
    protected_path.write_text(
        yaml.safe_dump(protected, allow_unicode=True), encoding="utf-8"
    )
    loaded = policy_mod.load("configs/policy.yaml", str(protected_path))
    async with make_client(policy=loaded) as client:
        blocked = await client.post("/v1/chat", content=protected_value.encode())
        assert blocked.status_code == 403
        path_blocked = await client.get(f"/files/{protected_value}")
        assert path_blocked.status_code == 403
        query_blocked = await client.get("/search", params={"q": protected_value})
        assert query_blocked.status_code == 403
        status = await client.get("/policy/status")
        assert status.status_code == 200
        assert status.headers["cache-control"] == "no-store"
        assert status.json()["protected_values"] == 1
        assert protected_value not in status.text
        assert "project-code" not in status.text

    def leaky_upstream(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"answer": protected_value})

    async with make_client(leaky_upstream, loaded) as client:
        response_blocked = await client.post("/v1/chat", content=b"safe request")
        assert response_blocked.status_code == 403


async def test_scoped_allowlist_is_audited_without_raw_value(
    tmp_path: Path, capsys
) -> None:
    raw = "010-0000-0000"
    protected = {
        "version": 1,
        "protected_values": [],
        "allowlist": [
            {
                "id": "synthetic-demo-phone",
                "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "reason": "synthetic fixture",
                "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
                "targets": ["phone-mobile"],
                "scope": {
                    "directions": ["request", "response"],
                    "methods": ["POST"],
                    "path_prefixes": ["/demo"],
                },
            }
        ],
    }
    protected_path = tmp_path / "protected.yaml"
    protected_path.write_text(
        yaml.safe_dump(protected, allow_unicode=True), encoding="utf-8"
    )
    loaded = policy_mod.load("configs/policy.yaml", str(protected_path))
    async with make_client(policy=loaded) as client:
        allowed = await client.post("/demo/chat", content=f"가상 연락처 {raw}".encode())
        assert allowed.status_code == 200
        assert raw in allowed.json()["echo"]
        redacted = await client.post("/other/chat", content=f"가상 연락처 {raw}".encode())
        assert raw not in redacted.json()["echo"]

    audit_output = capsys.readouterr().out
    assert raw not in audit_output
    decisions = [
        json.loads(line) for line in audit_output.splitlines() if "dlp.decision" in line
    ]
    allowed_decision = next(item for item in decisions if item["action"] == "allow")
    assert allowed_decision["exception_id"] == "synthetic-demo-phone"
    assert allowed_decision["sample"] == "***"


async def test_allowlisted_rule_does_not_suppress_overlapping_custom_block(
    tmp_path: Path,
) -> None:
    raw = "010-0000-0000"
    config = yaml.safe_load(Path("configs/policy.yaml").read_text(encoding="utf-8"))
    config["custom_rules"] = [
        {
            "id": "phone-escalation",
            "kind": "business_identifier",
            "action": "block",
            "matcher": {"type": "literal", "values": [raw]},
        }
    ]
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    protected = {
        "version": 1,
        "protected_values": [],
        "allowlist": [
            {
                "id": "synthetic-demo-phone",
                "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "reason": "synthetic fixture",
                "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
                "targets": ["phone-mobile"],
                "scope": {
                    "directions": ["request"],
                    "methods": ["POST"],
                    "path_prefixes": ["/demo"],
                },
            }
        ],
    }
    protected_path = tmp_path / "protected.yaml"
    protected_path.write_text(yaml.safe_dump(protected), encoding="utf-8")
    loaded = policy_mod.load(str(policy_path), str(protected_path))
    async with make_client(policy=loaded) as client:
        resp = await client.post("/demo/chat", content=f"가상 연락처 {raw}".encode())
        assert resp.status_code == 403
