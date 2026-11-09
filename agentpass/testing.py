"""Run a throwaway AgentPass server in a background thread (for tests and the demo)."""

from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import requests
import uvicorn

from .config import Settings
from .server import create_app
from .service import AgentPass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def running_server(data_dir: Path, policy_file: Path | None = None) -> Iterator[str]:
    settings = Settings(data_dir=Path(data_dir))
    if policy_file:
        settings.policy_file = Path(policy_file)
    service = AgentPass(settings)
    port = _free_port()
    config = uvicorn.Config(create_app(service), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if requests.get(f"{base}/health", timeout=0.5).status_code == 200:
                break
        except requests.ConnectionError:
            time.sleep(0.05)
    else:
        raise RuntimeError("AgentPass test server did not start")
    try:
        yield base
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        service.db.close()
