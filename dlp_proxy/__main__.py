"""Entry point: ``python -m dlp_proxy`` starts the proxy with uvicorn."""

from __future__ import annotations

import os

import uvicorn

from .app import create_app


def main() -> None:
    app = create_app()
    uvicorn.run(
        app,
        host=os.environ.get("DLP_HOST", "0.0.0.0"),
        port=int(os.environ.get("DLP_PORT", "8080")),
        log_level=os.environ.get("DLP_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
