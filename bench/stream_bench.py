"""Compare direct, full-buffer, and event-inspected SSE latency.

Run ``python bench/stream_bench.py 100``.  Each upstream response emits one
complete event immediately and a second after 25 ms, so time-to-first-byte
exposes the buffering cost while total time shows proxy overhead.
"""

from __future__ import annotations

import json
import os
import platform
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import yaml

ROOT = Path(__file__).resolve().parent.parent
RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 100
WARMUP = 10
DELAY_MS = 25
def _wait_ready(
    url: str, process: subprocess.Popen[bytes], timeout: float = 20.0
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"benchmark process exited with code {process.returncode}: {url}")
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.1)
    raise RuntimeError(f"not ready: {url}")


def _reserve_ports(count: int) -> list[int]:
    reservations: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            reservations.append(sock)
        return [int(sock.getsockname()[1]) for sock in reservations]
    finally:
        for sock in reservations:
            sock.close()


def _write_policy(directory: Path, mode: str, upstream_port: int) -> Path:
    policy = yaml.safe_load((ROOT / "configs" / "policy.yaml").read_text(encoding="utf-8"))
    policy["upstream"] = f"http://127.0.0.1:{upstream_port}"
    policy["scan"]["sse_mode"] = mode
    target = directory / f"policy-{mode}.yaml"
    target.write_text(yaml.safe_dump(policy, allow_unicode=True), encoding="utf-8")
    return target


def _start_proxy(
    port: int, upstream_port: int, policy_path: Path
) -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    env.update(
        {
            "DLP_PORT": str(port),
            "DLP_UPSTREAM": f"http://127.0.0.1:{upstream_port}",
            "DLP_POLICY_PATH": str(policy_path),
            "DLP_LOG_LEVEL": "warning",
        }
    )
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "dlp_proxy"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _measure_one(client: httpx.Client, url: str) -> tuple[float, float]:
    started = time.perf_counter_ns()
    first_ns: int | None = None
    body = bytearray()
    with client.stream("GET", url, timeout=5) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            if chunk and first_ns is None:
                first_ns = time.perf_counter_ns()
            body.extend(chunk)
    ended = time.perf_counter_ns()
    if first_ns is None:
        raise RuntimeError("stream returned no body")
    text = body.decode("utf-8")
    if "synthetic first event" not in text or "synthetic second event" not in text:
        raise RuntimeError(
            f"stream benchmark received an unexpected response from {url}: {text!r}"
        )
    gap = re.search(r"server_gap_ms=([0-9]+(?:\.[0-9]+)?)", text)
    if gap is None or float(gap.group(1)) < DELAY_MS * 0.8:
        raise RuntimeError(f"upstream did not preserve the delay from {url}: {text!r}")
    return (first_ns - started) / 1_000_000, (ended - started) / 1_000_000


def _summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "mean": round(statistics.fmean(ordered), 3),
        "p50": round(statistics.median(ordered), 3),
        "p95": round(ordered[max(0, int(len(ordered) * 0.95 + 0.9999) - 1)], 3),
        "min": round(ordered[0], 3),
        "max": round(ordered[-1], 3),
    }


def _terminate(processes: list[subprocess.Popen[bytes]]) -> None:
    for process in processes:
        process.terminate()
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def main() -> int:
    if RUNS < 100:
        raise ValueError("stream benchmark requires at least 100 runs")
    processes: list[subprocess.Popen[bytes]] = []
    upstream_port, buffer_port, event_port = _reserve_ports(3)
    with tempfile.TemporaryDirectory(prefix="dlp-stream-bench-") as temp:
        temp_path = Path(temp)
        buffer_policy = _write_policy(temp_path, "buffer", upstream_port)
        event_policy = _write_policy(temp_path, "event", upstream_port)
        upstream_env = os.environ.copy()
        upstream_env["PORT"] = str(upstream_port)
        processes.append(
            subprocess.Popen(  # noqa: S603
                [sys.executable, "mock_upstream/server.py"],
                cwd=ROOT,
                env=upstream_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        processes.append(_start_proxy(buffer_port, upstream_port, buffer_policy))
        processes.append(_start_proxy(event_port, upstream_port, event_policy))
        try:
            _wait_ready(f"http://127.0.0.1:{upstream_port}/healthz", processes[0])
            _wait_ready(f"http://127.0.0.1:{buffer_port}/healthz", processes[1])
            _wait_ready(f"http://127.0.0.1:{event_port}/healthz", processes[2])
            urls = {
                "direct": f"http://127.0.0.1:{upstream_port}/v1/stream?delay_ms={DELAY_MS}",
                "buffer": f"http://127.0.0.1:{buffer_port}/v1/stream?delay_ms={DELAY_MS}",
                "event": f"http://127.0.0.1:{event_port}/v1/stream?delay_ms={DELAY_MS}",
            }
            samples = {
                name: {"ttfb_ms": [], "total_ms": []} for name in urls
            }
            with httpx.Client() as client:
                for _ in range(WARMUP):
                    for url in urls.values():
                        _measure_one(client, url)
                names = tuple(urls)
                for index in range(RUNS):
                    rotated = names[index % len(names) :] + names[: index % len(names)]
                    for name in rotated:
                        ttfb, total = _measure_one(client, urls[name])
                        samples[name]["ttfb_ms"].append(ttfb)
                        samples[name]["total_ms"].append(total)
        finally:
            _terminate(processes)

    measured = {
        name: {metric: _summary(values) for metric, values in metrics.items()}
        for name, metrics in samples.items()
    }
    buffer_mean = measured["buffer"]["ttfb_ms"]["mean"]
    event_mean = measured["event"]["ttfb_ms"]["mean"]
    report = {
        "schema_version": 1,
        "measured_at": datetime.now(UTC).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "system": platform.system(),
            "machine": platform.machine(),
            "transport": "localhost HTTP/1.1 keep-alive",
        },
        "runs_per_mode": RUNS,
        "warmup_runs_per_mode": WARMUP,
        "upstream_inter_event_delay_ms": DELAY_MS,
        "payload": "two complete clean synthetic SSE events",
        "results": measured,
        "event_vs_buffer": {
            "mean_ttfb_reduction_ms": round(buffer_mean - event_mean, 3),
            "mean_ttfb_reduction_percent": round(
                100 * (buffer_mean - event_mean) / buffer_mean, 3
            ),
            "p95_ttfb_reduction_ms": round(
                measured["buffer"]["ttfb_ms"]["p95"]
                - measured["event"]["ttfb_ms"]["p95"],
                3,
            ),
        },
        "scope_note": (
            "Event mode releases each complete event after inspection; it does not provide "
            "token-fragment semantic reconstruction across events."
        ),
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
