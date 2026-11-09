"""Small SDK an agent uses to talk to AgentPass.

    agent = AgentClient("http://127.0.0.1:8000", agent_id, private_key_pem)
    agent.login(delegation_id, scopes=["shop.search"])
    agent.call("shop.search", {"query": "milk"})
"""

from __future__ import annotations

import time
import uuid
from typing import Optional

import jwt
import requests

from .crypto import load_private_key

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


class AgentClient:
    def __init__(self, base_url: str, agent_id: str, private_key_pem: str, issuer: str = "agentpass"):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self._key = load_private_key(private_key_pem)
        self._issuer = issuer
        self.access_token: Optional[str] = None
        self.http = requests.Session()

    def _assertion(self) -> str:
        now = int(time.time())
        return jwt.encode(
            {"iss": self.agent_id, "sub": self.agent_id, "aud": self._issuer,
             "iat": now, "exp": now + 60, "jti": uuid.uuid4().hex},
            self._key,
            algorithm="EdDSA",
        )

    def login(self, delegation_id: str, scopes: Optional[list[str]] = None) -> dict:
        """Exchange a delegation for a short-lived access token."""
        payload = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_assertion": self._assertion(),
            "delegation_id": delegation_id,
        }
        if scopes:
            payload["scope"] = " ".join(scopes)
        r = self.http.post(f"{self.base_url}/token", json=payload, timeout=10)
        data = r.json()
        if r.status_code == 200:
            self.access_token = data["access_token"]
        return {"http_status": r.status_code, **data}

    def call(self, tool: str, args: dict, approval_id: Optional[str] = None) -> dict:
        body: dict = {"args": args}
        if approval_id:
            body["approval_id"] = approval_id
        r = self.http.post(
            f"{self.base_url}/tools/{tool}",
            json=body,
            headers={"Authorization": f"Bearer {self.access_token or ''}"},
            timeout=10,
        )
        return {"http_status": r.status_code, **r.json()}


class AdminClient:
    """What the human (or their app/WhatsApp bot) uses."""

    def __init__(self, base_url: str, admin_key: str = "dev-admin-key"):
        self.base_url = base_url.rstrip("/")
        self.http = requests.Session()
        self.http.headers["X-Admin-Key"] = admin_key

    def _req(self, method: str, path: str, **kw) -> dict:
        r = self.http.request(method, f"{self.base_url}{path}", timeout=10, **kw)
        return {"http_status": r.status_code, **r.json()}

    def register_agent(self, name: str, owner: str, purpose: str) -> dict:
        return self._req("POST", "/agents", json={"name": name, "owner": owner, "purpose": purpose})

    def delegate(self, agent_id: str, user_id: str, scopes: list[str], ttl_minutes: int = 1440) -> dict:
        return self._req("POST", "/delegations", json={
            "agent_id": agent_id, "user_id": user_id, "scopes": scopes, "ttl_minutes": ttl_minutes})

    def pending_approvals(self) -> list[dict]:
        return self._req("GET", "/approvals")["approvals"]

    def approve(self, approval_id: str) -> dict:
        return self._req("POST", f"/approvals/{approval_id}/approve")

    def deny(self, approval_id: str) -> dict:
        return self._req("POST", f"/approvals/{approval_id}/deny")

    def revoke_agent(self, agent_id: str) -> dict:
        return self._req("POST", f"/agents/{agent_id}/revoke")

    def audit(self, agent_id: Optional[str] = None, limit: int = 200) -> list[dict]:
        params = {"limit": limit}
        if agent_id:
            params["agent_id"] = agent_id
        return self._req("GET", "/audit", params=params)["events"]
