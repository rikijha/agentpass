"""Run the gateway:  python -m agentpass [--host 127.0.0.1] [--port 8000]"""

from __future__ import annotations

import argparse

import uvicorn

from .config import Settings
from .server import create_app
from .service import AgentPass


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentPass gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    settings = Settings()
    if settings.admin_key == "dev-admin-key":
        print("WARNING: using the default admin key. Set AGENTPASS_ADMIN_KEY for anything real.")
    app = create_app(AgentPass(settings))
    print(f"AgentPass dashboard: http://{args.host}:{args.port}/")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
