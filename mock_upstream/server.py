"""Mock LLM/MCP upstream for local testing and benchmarks.

POST /v1/chat/completions echoes the prompt back (so response-path scanning
can be exercised); any other path echoes method/path/body.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import AsyncIterator

import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI(title="mock-upstream")
app.state.forwarded_requests = 0


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/stats")
async def stats() -> dict:
    """Expose only a count so smoke tests can prove blocked data never arrived."""
    return {"forwarded_requests": app.state.forwarded_requests}


@app.post("/v1/chat/completions")
async def chat(request: Request) -> JSONResponse:
    app.state.forwarded_requests += 1
    body = await request.body()
    try:
        payload = json.loads(body)
        content = str(payload.get("messages", [{}])[-1].get("content", ""))
    except (json.JSONDecodeError, AttributeError, IndexError):
        content = body.decode("utf-8", errors="replace")
    return JSONResponse(
        {
            "id": "mock-1",
            "object": "chat.completion",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": f"echo: {content}"}}
            ],
        }
    )


@app.get("/v1/stream")
async def stream(
    delay_ms: int = Query(default=25, ge=0, le=1000),
) -> StreamingResponse:
    """Emit two clean synthetic SSE events with a controlled inter-event gap."""
    app.state.forwarded_requests += 1

    async def events() -> AsyncIterator[bytes]:
        started = time.perf_counter()
        yield b"event: message\ndata: synthetic first event\n\n"
        await asyncio.sleep(delay_ms / 1000)
        gap_ms = (time.perf_counter() - started) * 1000
        yield (
            f"event: message\ndata: synthetic second event; server_gap_ms={gap_ms:.3f}\n\n"
        ).encode("ascii")

    return StreamingResponse(events(), media_type="text/event-stream")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def echo(request: Request, path: str) -> JSONResponse:
    app.state.forwarded_requests += 1
    body = await request.body()
    return JSONResponse(
        {
            "method": request.method,
            "path": "/" + path,
            "body": body.decode("utf-8", errors="replace"),
        }
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "9000")))
