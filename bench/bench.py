"""Latency overhead benchmark: direct-to-upstream vs through the DLP proxy.

Starts the mock upstream (:19000) and the proxy (:18081) as subprocesses on
localhost, sends N identical chat requests to each, and reports mean/p50/p95
in milliseconds. Run: python bench/bench.py [N]

Local loopback isolates proxy overhead from network/port-forward noise; the
absolute numbers are a floor, not what a remote LLM call would add in total.
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
N = int(sys.argv[1]) if len(sys.argv) > 1 else 200
WARMUP = 20

UPSTREAM_PORT = 19000
PROXY_PORT = 18081

BENCH_TEXT = (
    "분기 보고서를 세 줄로 요약해줘. 회의는 내일 오후 3시입니다. "
    "고객 만족도 지표와 다음 분기 목표를 포함해줘. "
)
PAYLOAD = {
    "model": "bench",
    "messages": [
        {
            "role": "user",
            "content": BENCH_TEXT * 7,
        }
    ],
}


def wait_ready(url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise RuntimeError(f"not ready: {url}")


def _one(client: httpx.Client, url: str) -> float:
    started = time.perf_counter()
    response = client.post(url, json=PAYLOAD)
    response.raise_for_status()
    return (time.perf_counter() - started) * 1000


def measure_paired(
    client: httpx.Client, direct_url: str, proxy_url: str, n: int
) -> tuple[list[float], list[float], list[float]]:
    """Alternate request order and retain the paired overhead distribution."""
    for _ in range(WARMUP):
        _one(client, direct_url)
        _one(client, proxy_url)
    direct: list[float] = []
    proxied: list[float] = []
    overhead: list[float] = []
    for index in range(n):
        if index % 2:
            proxy_ms = _one(client, proxy_url)
            direct_ms = _one(client, direct_url)
        else:
            direct_ms = _one(client, direct_url)
            proxy_ms = _one(client, proxy_url)
        direct.append(direct_ms)
        proxied.append(proxy_ms)
        overhead.append(proxy_ms - direct_ms)
    return direct, proxied, overhead


def stats(times: list[float]) -> dict[str, float]:
    qs = statistics.quantiles(times, n=100)
    return {
        "mean": statistics.fmean(times),
        "p50": statistics.median(times),
        "p95": qs[94],
        "min": min(times),
        "max": max(times),
    }


def main() -> None:
    env = os.environ.copy()
    env["PORT"] = str(UPSTREAM_PORT)
    upstream = subprocess.Popen(
        [sys.executable, "mock_upstream/server.py"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    env2 = os.environ.copy()
    env2.update(
        {
            "DLP_PORT": str(PROXY_PORT),
            "DLP_UPSTREAM": f"http://127.0.0.1:{UPSTREAM_PORT}",
            "DLP_POLICY_PATH": str(ROOT / "configs" / "policy.yaml"),
            "DLP_LOG_LEVEL": "warning",
        }
    )
    proxy = subprocess.Popen(
        [sys.executable, "-m", "dlp_proxy"],
        cwd=ROOT,
        env=env2,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_ready(f"http://127.0.0.1:{UPSTREAM_PORT}/healthz")
        wait_ready(f"http://127.0.0.1:{PROXY_PORT}/healthz")

        with httpx.Client() as client:
            direct, proxied, overhead = measure_paired(
                client,
                f"http://127.0.0.1:{UPSTREAM_PORT}/v1/chat/completions",
                f"http://127.0.0.1:{PROXY_PORT}/v1/chat/completions",
                N,
            )

        d, p, o = stats(direct), stats(proxied), stats(overhead)
        result = {
            "measured_at": datetime.now(UTC).isoformat(),
            "environment": {
                "python": platform.python_version(),
                "os": platform.platform(),
                "transport": "localhost HTTP/1.1 keep-alive",
            },
            "runs": N,
            "warmup_runs": WARMUP,
            "request_body_bytes": len(
                httpx.Request("POST", "http://benchmark", json=PAYLOAD).content
            ),
            "direct_ms": {k: round(v, 2) for k, v in d.items()},
            "proxied_ms": {k: round(v, 2) for k, v in p.items()},
            "paired_overhead_ms": {k: round(v, 2) for k, v in o.items()},
        }
        print(json.dumps(result, indent=2))
    finally:
        proxy.terminate()
        upstream.terminate()


if __name__ == "__main__":
    main()
