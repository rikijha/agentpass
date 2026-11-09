"""HTTP API (Starlette + uvicorn).

Admin endpoints (X-Admin-Key header) stand in for the human user.
Agent endpoints use a signed client assertion (/token) or a Bearer token (/tools).
"""

from __future__ import annotations

import hmac
import json
from typing import Optional

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from . import __version__
from .dashboard import DASHBOARD_HTML
from .service import AgentPass, AgentPassError


def create_app(service: Optional[AgentPass] = None) -> Starlette:
    svc = service or AgentPass()

    def require_admin(request: Request) -> None:
        key = request.headers.get("x-admin-key", "")
        if not hmac.compare_digest(key, svc.settings.admin_key):
            raise AgentPassError(401, "unauthorized", "missing or wrong X-Admin-Key")

    async def body(request: Request) -> dict:
        raw = await request.body()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise AgentPassError(400, "invalid_request", "body must be JSON")
        if not isinstance(data, dict):
            raise AgentPassError(400, "invalid_request", "body must be a JSON object")
        return data

    def bearer(request: Request) -> str:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise AgentPassError(401, "invalid_token", "missing Bearer token")
        return auth[7:].strip()

    # ------------------------------------------------------------- handlers
    async def health(request: Request):
        return JSONResponse({"status": "ok", "service": "agentpass", "version": __version__})

    async def jwks(request: Request):
        return JSONResponse(svc.jwks())

    async def agents_create(request: Request):
        require_admin(request)
        b = await body(request)
        res = svc.register_agent(b.get("name", ""), b.get("owner", ""), b.get("purpose", ""),
                                 b.get("public_key_pem"), b.get("tools"))
        return JSONResponse(res, status_code=201)

    async def agents_list(request: Request):
        require_admin(request)
        return JSONResponse({"agents": svc.list_agents()})

    async def tools_list(request: Request):
        require_admin(request)
        return JSONResponse({"tools": svc.available_tools()})

    async def agents_revoke(request: Request):
        require_admin(request)
        return JSONResponse(svc.revoke_agent(request.path_params["agent_id"]))

    async def delegations_create(request: Request):
        require_admin(request)
        b = await body(request)
        scopes = b.get("scopes") or []
        if isinstance(scopes, str):
            scopes = scopes.split()
        res = svc.create_delegation(b.get("agent_id", ""), b.get("user_id", ""), scopes,
                                    int(b.get("ttl_minutes", 60 * 24)))
        return JSONResponse(res, status_code=201)

    async def delegations_revoke(request: Request):
        require_admin(request)
        return JSONResponse(svc.revoke_delegation(request.path_params["delegation_id"]))

    async def token(request: Request):
        b = await body(request)
        res = svc.exchange_token(b.get("grant_type", ""), b.get("client_assertion", ""),
                                 b.get("delegation_id", ""), b.get("scope"))
        return JSONResponse(res, headers={"Cache-Control": "no-store"})

    async def tool_call(request: Request):
        b = await body(request)
        args = b.get("args") or {}
        if not isinstance(args, dict):
            raise AgentPassError(400, "invalid_request", "'args' must be an object")
        status, res = svc.call_tool(bearer(request), request.path_params["tool"], args,
                                    b.get("approval_id"))
        return JSONResponse(res, status_code=status)

    async def approvals_list(request: Request):
        require_admin(request)
        status = request.query_params.get("status", "pending")
        return JSONResponse({"approvals": svc.list_approvals(None if status == "all" else status)})

    async def approvals_approve(request: Request):
        require_admin(request)
        return JSONResponse(svc.decide_approval(request.path_params["approval_id"], True))

    async def approvals_deny(request: Request):
        require_admin(request)
        return JSONResponse(svc.decide_approval(request.path_params["approval_id"], False))

    async def audit(request: Request):
        require_admin(request)
        return JSONResponse({"events": svc.audit_log(request.query_params.get("agent_id"),
                                                     int(request.query_params.get("limit", 200)))})

    async def index(request: Request):
        return HTMLResponse(DASHBOARD_HTML)

    async def on_error(request: Request, exc: AgentPassError):
        return JSONResponse({"error": exc.error, "message": exc.message}, status_code=exc.status)

    routes = [
        Route("/", index),
        Route("/health", health),
        Route("/.well-known/jwks.json", jwks),
        Route("/agents", agents_create, methods=["POST"]),
        Route("/agents", agents_list, methods=["GET"]),
        Route("/agents/{agent_id}/revoke", agents_revoke, methods=["POST"]),
        Route("/tools", tools_list, methods=["GET"]),
        Route("/delegations", delegations_create, methods=["POST"]),
        Route("/delegations/{delegation_id}/revoke", delegations_revoke, methods=["POST"]),
        Route("/token", token, methods=["POST"]),
        Route("/tools/{tool}", tool_call, methods=["POST"]),
        Route("/approvals", approvals_list, methods=["GET"]),
        Route("/approvals/{approval_id}/approve", approvals_approve, methods=["POST"]),
        Route("/approvals/{approval_id}/deny", approvals_deny, methods=["POST"]),
        Route("/audit", audit, methods=["GET"]),
    ]
    app = Starlette(routes=routes, exception_handlers={AgentPassError: on_error})
    app.state.service = svc
    return app


