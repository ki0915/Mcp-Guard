"""Mock LLM/MCP upstream for local testing and benchmarks.

POST /v1/chat/completions echoes the prompt back (so response-path scanning
can be exercised); any other path echoes method/path/body.
"""

from __future__ import annotations

import json
import os

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

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
