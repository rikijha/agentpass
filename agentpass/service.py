"""The AgentPass service: identity registry, token exchange, gateway and approvals.

Flow
----
1. A human registers an agent. The agent gets its own Ed25519 key pair; the
   gateway keeps only the public key.
2. The human creates a *delegation*: "agent X may act for me with scopes S
   until time T".
3. The agent proves who it is with a short signed assertion (RFC 7523
   private_key_jwt) and exchanges the delegation for a 5-minute access token
   (RFC 8693 token exchange). The token says sub=<user> and act.sub=<agent>,
   so every action is "agent X on behalf of user U".
4. Every tool call goes through the gateway: token check -> agent/delegation
   still live -> scope check -> policy (limits, budget, approval) -> tool ->
   audit log.
"""

from __future__ import annotations

import hashlib
import re
import json
import time
import uuid
from typing import Callable, Optional

import jwt

from .config import Settings
from .crypto import generate_keypair, load_or_create_issuer_key, load_public_key, public_jwk
from .db import Database
from .policy import ALLOW, DENY, NEEDS_APPROVAL, PolicyEngine, normalise_rule
from .tools import MockToolBackend, ToolBackend, ToolError

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ISSUER_KID = "agentpass-issuer-1"


class AgentPassError(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status = status
        self.error = error
        self.message = message


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _args_hash(tool: str, args: dict) -> str:
    return hashlib.sha256(f"{tool}:{json.dumps(args, sort_keys=True)}".encode()).hexdigest()


class AgentPass:
    def __init__(
        self,
        settings: Optional[Settings] = None,
        tools: Optional[ToolBackend] = None,
        clock: Callable[[], float] = time.time,
    ):
        self.settings = settings or Settings()
        self.db = Database(self.settings.db_path)
        self.policy = PolicyEngine.from_file(self.settings.policy_file)
        # Policies created from the dashboard/API override the YAML file.
        for row in self.db.all("SELECT agent_name, tools FROM agent_policies"):
            self.policy.set_agent_tools(row["agent_name"], json.loads(row["tools"]))
        self.tools: ToolBackend = tools or MockToolBackend()
        self.issuer_key = load_or_create_issuer_key(self.settings.issuer_key_path)
        self._clock = clock

    def now(self) -> int:
        return int(self._clock())

    # ------------------------------------------------------------------ agents
    def register_agent(
        self,
        name: str,
        owner: str,
        purpose: str,
        public_key_pem: Optional[str] = None,
        tools: Optional[dict] = None,
    ) -> dict:
        name, owner, purpose = (name or "").strip(), (owner or "").strip(), (purpose or "").strip()
        if not name or not owner or not purpose:
            raise AgentPassError(400, "invalid_request", "name, owner and purpose are required")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,39}", name):
            raise AgentPassError(
                400, "invalid_request",
                "name must be 2-40 chars: lowercase letters, digits, '-' or '_'",
            )
        if self.db.one("SELECT id FROM agents WHERE name = ?", (name,)):
            raise AgentPassError(409, "conflict", f"agent '{name}' already exists")
        normalised_tools: Optional[dict] = None
        if tools is not None:
            if not isinstance(tools, dict) or not tools:
                raise AgentPassError(400, "invalid_request", "pick at least one tool")
            unknown = set(tools) - set(self.tools.names())
            if unknown:
                raise AgentPassError(400, "invalid_scope", f"unknown tools: {sorted(unknown)}")
            try:
                normalised_tools = {t: normalise_rule(r) for t, r in tools.items()}
            except (TypeError, ValueError) as exc:
                raise AgentPassError(400, "invalid_request", f"bad rule: {exc}")
        elif not self.policy.allowed_tools(name):
            raise AgentPassError(
                400, "invalid_request",
                f"no policy for '{name}': pick its tools, or add it to config/policies.yaml",
            )
        private_pem = None
        if public_key_pem:
            try:
                load_public_key(public_key_pem)
            except Exception as exc:  # noqa: BLE001
                raise AgentPassError(400, "invalid_request", f"bad public key: {exc}")
        else:
            private_pem, public_key_pem = generate_keypair()
        agent_id = _new_id("agt")
        self.db.execute(
            "INSERT INTO agents (id, name, owner, purpose, public_key_pem, status, created_at)"
            " VALUES (?, ?, ?, ?, ?, 'active', ?)",
            (agent_id, name, owner, purpose, public_key_pem, self.now()),
        )
        if normalised_tools is not None:
            self.db.execute(
                "INSERT OR REPLACE INTO agent_policies (agent_name, tools, updated_at) VALUES (?, ?, ?)",
                (name, json.dumps(normalised_tools, sort_keys=True), self.now()),
            )
            self.policy.set_agent_tools(name, normalised_tools)
        agent = self.get_agent(agent_id)
        self.db.audit(self.now(), "agent.register", "ok", f"owner={owner}", agent=agent)
        result = {
            "agent_id": agent_id,
            "name": name,
            "allowed_tools": sorted(self.policy.allowed_tools(name)),
        }
        if private_pem:
            # Returned exactly once. The gateway never stores agent private keys.
            result["private_key_pem"] = private_pem
        return result

    def get_agent(self, agent_id: str) -> Optional[dict]:
        return self.db.one("SELECT * FROM agents WHERE id = ?", (agent_id,))

    def list_agents(self) -> list[dict]:
        rows = self.db.all(
            "SELECT id, name, owner, purpose, status, created_at FROM agents ORDER BY created_at"
        )
        for r in rows:
            r["allowed_tools"] = sorted(self.policy.allowed_tools(r["name"]))
            r["rules"] = self.policy.rules_for(r["name"])
            r["delegations"] = self.db.all(
                "SELECT id, user_id, scopes, expires_at, revoked FROM delegations"
                " WHERE agent_id = ? ORDER BY created_at DESC", (r["id"],)
            )
        return rows

    def available_tools(self) -> list[str]:
        return self.tools.names()

    def revoke_agent(self, agent_id: str) -> dict:
        """Kill switch: the agent's tokens stop working on their very next use."""
        agent = self._require_agent(agent_id)
        self.db.execute("UPDATE agents SET status = 'revoked' WHERE id = ?", (agent_id,))
        self.db.execute("UPDATE delegations SET revoked = 1 WHERE agent_id = ?", (agent_id,))
        self.db.execute(
            "UPDATE approvals SET status = 'denied', decided_at = ? WHERE agent_id = ? AND status = 'pending'",
            (self.now(), agent_id),
        )
        self.db.audit(self.now(), "agent.revoke", "ok", "kill switch", agent=agent)
        return {"agent_id": agent_id, "status": "revoked"}

    def _require_agent(self, agent_id: str) -> dict:
        agent = self.get_agent(agent_id)
        if not agent:
            raise AgentPassError(404, "not_found", f"agent '{agent_id}' not found")
        return agent

    # ------------------------------------------------------------- delegations
    def create_delegation(
        self, agent_id: str, user_id: str, scopes: list[str], ttl_minutes: int = 60 * 24
    ) -> dict:
        agent = self._require_agent(agent_id)
        if agent["status"] != "active":
            raise AgentPassError(400, "invalid_request", "agent is not active")
        if not scopes:
            raise AgentPassError(400, "invalid_request", "at least one scope is required")
        unknown = set(scopes) - set(self.tools.names())
        if unknown:
            raise AgentPassError(400, "invalid_scope", f"unknown tools: {sorted(unknown)}")
        not_in_policy = set(scopes) - self.policy.allowed_tools(agent["name"])
        if not_in_policy:
            raise AgentPassError(
                400,
                "invalid_scope",
                f"policy does not allow {sorted(not_in_policy)} for '{agent['name']}'",
            )
        delegation_id = _new_id("dlg")
        expires_at = self.now() + int(ttl_minutes) * 60
        self.db.execute(
            "INSERT INTO delegations (id, user_id, agent_id, scopes, expires_at, revoked, created_at)"
            " VALUES (?, ?, ?, ?, ?, 0, ?)",
            (delegation_id, user_id, agent_id, " ".join(sorted(scopes)), expires_at, self.now()),
        )
        self.db.audit(
            self.now(), "delegation.create", "ok", " ".join(sorted(scopes)), agent=agent, user_id=user_id
        )
        return {
            "delegation_id": delegation_id,
            "agent_id": agent_id,
            "user_id": user_id,
            "scopes": sorted(scopes),
            "expires_at": expires_at,
        }

    def revoke_delegation(self, delegation_id: str) -> dict:
        d = self.db.one("SELECT * FROM delegations WHERE id = ?", (delegation_id,))
        if not d:
            raise AgentPassError(404, "not_found", "delegation not found")
        self.db.execute("UPDATE delegations SET revoked = 1 WHERE id = ?", (delegation_id,))
        self.db.audit(
            self.now(), "delegation.revoke", "ok", "", agent=self.get_agent(d["agent_id"]), user_id=d["user_id"]
        )
        return {"delegation_id": delegation_id, "revoked": True}

    # ---------------------------------------------------------- token exchange
    def exchange_token(
        self, grant_type: str, client_assertion: str, delegation_id: str, scope: Optional[str] = None
    ) -> dict:
        if grant_type != TOKEN_EXCHANGE_GRANT:
            raise AgentPassError(400, "unsupported_grant_type", f"use {TOKEN_EXCHANGE_GRANT}")
        agent = self._verify_client_assertion(client_assertion)

        d = self.db.one("SELECT * FROM delegations WHERE id = ?", (delegation_id,))
        if not d or d["agent_id"] != agent["id"]:
            self.db.audit(self.now(), "token.exchange", "deny", "delegation not found for agent", agent=agent)
            raise AgentPassError(400, "invalid_grant", "delegation not found for this agent")
        if d["revoked"] or d["expires_at"] <= self.now():
            self.db.audit(self.now(), "token.exchange", "deny", "delegation revoked or expired", agent=agent)
            raise AgentPassError(400, "invalid_grant", "delegation is revoked or expired")

        granted = set(d["scopes"].split())
        requested = set(scope.split()) if scope else granted
        if not requested <= granted:
            self.db.audit(
                self.now(), "token.exchange", "deny",
                f"scope escalation attempt: {sorted(requested - granted)}", agent=agent, user_id=d["user_id"],
            )
            raise AgentPassError(400, "invalid_scope", f"not delegated: {sorted(requested - granted)}")

        now = self.now()
        exp = min(now + self.settings.access_token_ttl_seconds, d["expires_at"])
        claims = {
            "iss": self.settings.issuer,
            "aud": self.settings.token_audience,
            "sub": d["user_id"],                 # who the agent acts for
            "act": {"sub": agent["id"], "name": agent["name"]},  # who is acting
            "scope": " ".join(sorted(requested)),
            "did": d["id"],
            "iat": now,
            "nbf": now,
            "exp": exp,
            "jti": uuid.uuid4().hex,
        }
        token = jwt.encode(claims, self.issuer_key, algorithm="EdDSA", headers={"kid": ISSUER_KID})
        self.db.audit(now, "token.exchange", "ok", claims["scope"], agent=agent, user_id=d["user_id"])
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": exp - now,
            "scope": claims["scope"],
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }

    def _verify_client_assertion(self, assertion: str) -> dict:
        """RFC 7523: the agent signs a short JWT with its own private key."""
        try:
            unverified = jwt.decode(assertion, options={"verify_signature": False})
        except jwt.PyJWTError:
            raise AgentPassError(401, "invalid_client", "malformed client assertion")
        agent_id = unverified.get("iss")
        agent = self.get_agent(agent_id) if agent_id else None
        if not agent:
            raise AgentPassError(401, "invalid_client", "unknown agent")
        if agent["status"] != "active":
            self.db.audit(self.now(), "token.exchange", "deny", "agent revoked", agent=agent)
            raise AgentPassError(401, "invalid_client", "agent is revoked")
        try:
            claims = jwt.decode(
                assertion,
                load_public_key(agent["public_key_pem"]),
                algorithms=["EdDSA"],
                audience=self.settings.issuer,
                options={"require": ["iss", "sub", "aud", "exp", "iat", "jti"]},
                leeway=5,
            )
        except jwt.PyJWTError as exc:
            self.db.audit(self.now(), "token.exchange", "deny", f"bad assertion: {exc}", agent=agent)
            raise AgentPassError(401, "invalid_client", f"assertion rejected: {exc}")
        if claims["sub"] != agent_id:
            raise AgentPassError(401, "invalid_client", "assertion sub must equal iss")
        if claims["exp"] - claims["iat"] > self.settings.max_assertion_age_seconds:
            raise AgentPassError(401, "invalid_client", "assertion lifetime too long")
        # Replay protection: each assertion can be used once.
        self.db.execute("DELETE FROM used_assertions WHERE expires_at < ?", (self.now(),))
        if self.db.one("SELECT jti FROM used_assertions WHERE jti = ?", (claims["jti"],)):
            self.db.audit(self.now(), "token.exchange", "deny", "assertion replay", agent=agent)
            raise AgentPassError(401, "invalid_client", "assertion already used")
        self.db.execute(
            "INSERT INTO used_assertions (jti, expires_at) VALUES (?, ?)", (claims["jti"], claims["exp"])
        )
        return agent

    # ----------------------------------------------------------------- gateway
    def authenticate(self, bearer_token: str) -> tuple[dict, dict]:
        """Verify an access token AND that the agent and delegation are still live."""
        try:
            claims = jwt.decode(
                bearer_token,
                self.issuer_key.public_key(),
                algorithms=["EdDSA"],
                audience=self.settings.token_audience,
                issuer=self.settings.issuer,
                options={"require": ["exp", "sub", "act", "scope", "did"]},
            )
        except jwt.ExpiredSignatureError:
            raise AgentPassError(401, "invalid_token", "token expired")
        except jwt.PyJWTError as exc:
            raise AgentPassError(401, "invalid_token", f"invalid token: {exc}")
        agent = self.get_agent(claims["act"]["sub"])
        if not agent or agent["status"] != "active":
            self.db.audit(self.now(), "tool.call", "deny", "agent revoked", agent=agent, user_id=claims["sub"])
            raise AgentPassError(401, "invalid_token", "agent is revoked")
        d = self.db.one("SELECT * FROM delegations WHERE id = ?", (claims["did"],))
        if not d or d["revoked"] or d["expires_at"] <= self.now():
            self.db.audit(self.now(), "tool.call", "deny", "delegation revoked", agent=agent, user_id=claims["sub"])
            raise AgentPassError(401, "invalid_token", "delegation is revoked or expired")
        return claims, agent

    def call_tool(
        self, bearer_token: str, tool: str, args: dict, approval_id: Optional[str] = None
    ) -> tuple[int, dict]:
        claims, agent = self.authenticate(bearer_token)
        user_id = claims["sub"]
        detail = {"tool": tool, "args": args}

        if tool not in claims["scope"].split():
            self.db.audit(self.now(), f"tool:{tool}", DENY, "not in token scope", agent=agent,
                          user_id=user_id, detail=detail)
            raise AgentPassError(403, "insufficient_scope", f"token does not cover '{tool}'")

        decision = self.policy.evaluate(
            agent["name"], tool, args, spent_in_period=lambda days: self._spent(agent["id"], tool, days)
        )

        if decision.outcome == DENY:
            self.db.audit(self.now(), f"tool:{tool}", DENY, decision.reason, agent=agent,
                          user_id=user_id, detail=detail)
            raise AgentPassError(403, "policy_denied", decision.reason)

        if decision.outcome == NEEDS_APPROVAL:
            if not approval_id:
                approval = self._create_approval(agent, user_id, tool, args, decision.reason)
                self.db.audit(self.now(), f"tool:{tool}", NEEDS_APPROVAL, decision.reason, agent=agent,
                              user_id=user_id, detail={**detail, "approval_id": approval["id"]})
                return 202, {
                    "status": "pending_approval",
                    "approval_id": approval["id"],
                    "reason": decision.reason,
                    "message": "A human must approve this call. Retry with the same args and approval_id.",
                }
            self._consume_approval(approval_id, agent, tool, args)
            decision_label, reason = "allow_approved", f"approved by human ({approval_id})"
        else:
            decision_label, reason = ALLOW, decision.reason

        try:
            result = self.tools.call(tool, args)
        except ToolError as exc:
            self.db.audit(self.now(), f"tool:{tool}", "error", str(exc), agent=agent, user_id=user_id, detail=detail)
            raise AgentPassError(400, "tool_error", str(exc))

        if "amount" in args:
            try:
                self.db.execute(
                    "INSERT INTO spend (agent_id, tool, amount, ts) VALUES (?, ?, ?, ?)",
                    (agent["id"], tool, float(args["amount"]), self.now()),
                )
            except (TypeError, ValueError):
                pass
        self.db.audit(self.now(), f"tool:{tool}", decision_label, reason, agent=agent, user_id=user_id, detail=detail)
        return 200, {"status": "ok", "decision": decision_label, "result": result}

    def _spent(self, agent_id: str, tool: str, days: int) -> float:
        since = self.now() - days * 86400
        row = self.db.one(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM spend WHERE agent_id = ? AND tool = ? AND ts >= ?",
            (agent_id, tool, since),
        )
        return float(row["total"]) if row else 0.0

    # --------------------------------------------------------------- approvals
    def _create_approval(self, agent: dict, user_id: str, tool: str, args: dict, reason: str) -> dict:
        approval_id = _new_id("apr")
        self.db.execute(
            "INSERT INTO approvals (id, agent_id, user_id, tool, args, args_hash, reason, status, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
            (approval_id, agent["id"], user_id, tool, json.dumps(args, sort_keys=True),
             _args_hash(tool, args), reason, self.now()),
        )
        return {"id": approval_id}

    def _consume_approval(self, approval_id: str, agent: dict, tool: str, args: dict) -> None:
        a = self.db.one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        if not a or a["agent_id"] != agent["id"]:
            raise AgentPassError(403, "approval_invalid", "approval not found for this agent")
        if a["args_hash"] != _args_hash(tool, args):
            # Stops an agent getting "₹100" approved and then sending "₹10,000".
            self.db.audit(self.now(), f"tool:{tool}", DENY, "args differ from approved request",
                          agent=agent, user_id=a["user_id"], detail={"approval_id": approval_id})
            raise AgentPassError(403, "approval_invalid", "arguments differ from what was approved")
        if a["status"] == "pending":
            raise AgentPassError(403, "approval_pending", "still waiting for a human")
        if a["status"] != "approved":
            raise AgentPassError(403, "approval_invalid", f"approval is {a['status']}")
        self.db.execute("UPDATE approvals SET status = 'used' WHERE id = ?", (approval_id,))

    def list_approvals(self, status: Optional[str] = "pending") -> list[dict]:
        sql = ("SELECT a.*, g.name AS agent_name FROM approvals a JOIN agents g ON g.id = a.agent_id")
        params: tuple = ()
        if status:
            sql += " WHERE a.status = ?"
            params = (status,)
        rows = self.db.all(sql + " ORDER BY a.created_at", params)
        for r in rows:
            r["args"] = json.loads(r["args"])
            r.pop("args_hash", None)
        return rows

    def decide_approval(self, approval_id: str, approve: bool) -> dict:
        a = self.db.one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        if not a:
            raise AgentPassError(404, "not_found", "approval not found")
        if a["status"] != "pending":
            raise AgentPassError(409, "conflict", f"approval is already {a['status']}")
        status = "approved" if approve else "denied"
        self.db.execute(
            "UPDATE approvals SET status = ?, decided_at = ? WHERE id = ?", (status, self.now(), approval_id)
        )
        self.db.audit(self.now(), f"approval:{a['tool']}", status, "", agent=self.get_agent(a["agent_id"]),
                      user_id=a["user_id"], detail={"approval_id": approval_id})
        return {"approval_id": approval_id, "status": status}

    # ------------------------------------------------------------------- audit
    def audit_log(self, agent_id: Optional[str] = None, limit: int = 200) -> list[dict]:
        sql, params = "SELECT * FROM audit", []
        if agent_id:
            sql += " WHERE agent_id = ?"
            params.append(agent_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))
        rows = self.db.all(sql, params)
        for r in rows:
            r["detail"] = json.loads(r["detail"] or "{}")
        return rows

    def jwks(self) -> dict:
        return {"keys": [public_jwk(self.issuer_key, ISSUER_KID)]}
