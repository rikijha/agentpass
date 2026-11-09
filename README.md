# AgentPass

**Identity, permissions and audit for AI agents.**

Most AI agents today run with their owner's full credentials. If a grocery agent holds your Gmail token and your card, a single prompt injection can do anything you can do. AgentPass puts a gateway between agents and their tools so that every agent:

- has **its own identity**: an Ed25519 key pair; the gateway stores only the public key
- acts **on behalf of a user**, with **narrow, short-lived tokens** (5 minutes, RFC 8693-style `act` claim)
- is held to a **policy** of allowed tools, per-call limits and rolling budgets
- **pauses for a human** on risky actions, and an approval can't be reused with different arguments
- leaves an **audit trail** of every decision, recorded under the agent's name
- can be shut off instantly with a **kill switch**, including tokens it already holds

```
 ┌──────────────┐  signed assertion   ┌──────────────────────────────┐
 │ grocery-agent│ ──────────────────▶ │  /token  (token exchange)    │
 │  (own key)   │ ◀── 5-min token ─── │                              │
 │              │                     │  /tools/{tool}               │      ┌────────────┐
 │              │ ── tool call ─────▶ │   1. verify token signature  │ ───▶ │ tool       │
 └──────────────┘                     │   2. agent + delegation live?│      │ backends   │
                                      │   3. tool in token scope?    │      │ (mock now, │
 ┌──────────────┐  approve / revoke   │   4. policy: limits, budget  │      │  MCP next) │
 │  human user  │ ──────────────────▶ │   5. human approval if needed│      └────────────┘
 │ (dashboard)  │ ◀── audit log ───── │   6. audit log               │
 └──────────────┘                     └──────────────────────────────┘
```

## Quick start (macOS / Linux)

```bash
./setup.sh          # creates .venv, installs dependencies, runs tests
./run.sh demo       # end-to-end demo in the terminal
./run.sh server     # gateway + live dashboard at http://127.0.0.1:8000/
```

Requires Python 3.10 or newer (`brew install python@3.12` if needed).

## Dashboard

`./run.sh server` serves a dashboard at http://127.0.0.1:8000/ where you can:

- **Add an agent:** name, owner, purpose; pick its tools and set limits (max per call, approval threshold, rolling budget, always ask). You can also grant access to a user in the same step. The agent's private key is shown once, with a download button and a ready-to-paste Python snippet.
- Approve or deny pending actions
- Revoke an agent (kill switch)
- Watch the live audit log

Policies created in the dashboard are stored in the database and take priority over `config/policies.yaml`.

## What the demo shows

Two agents act for one user: `grocery-agent` (search and checkout) and `email-agent` (read and send).

| Step | Result |
|---|---|
| Grocery agent searches, places a ₹885 order | allowed |
| ₹2,000 order (above ₹1,500 threshold) | **paused** for human approval |
| Agent changes the amount after approval | **blocked**: args differ from what was approved |
| Retry with the approved args | allowed (approval used once) |
| ₹4,000 order | **denied**: over the ₹3,000 per-order cap |
| ₹2,500 more | **denied**: would exceed ₹5,000 / 7-day budget |
| Grocery agent reads email | **denied**: not in its token scope |
| Email agent requests `shop.checkout` scope | **denied**: scope escalation |
| Email agent sends mail | **paused**: sending always needs approval |
| User revokes grocery agent | its still-valid token is rejected at once |

## Policies

`config/policies.yaml`: anything not listed is denied.

```yaml
agents:
  grocery-agent:
    tools:
      shop.search: {}
      shop.checkout:
        max_amount: 3000
        budget: { amount: 5000, period_days: 7 }
        require_approval_above: 1500
  email-agent:
    tools:
      gmail.read: {}
      gmail.send:
        require_approval: true
```

## API

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | `/agents` | admin | register agent (optional `tools` rules) → id + private key (returned once) |
| GET | `/tools` | admin | available tools |
| GET | `/agents` | admin | list agents |
| POST | `/agents/{id}/revoke` | admin | kill switch |
| POST | `/delegations` | admin | user grants an agent scopes for a time window |
| POST | `/delegations/{id}/revoke` | admin | withdraw a grant |
| POST | `/token` | agent | signed assertion + delegation → 5-min access token |
| POST | `/tools/{tool}` | agent | gated tool call (`{"args": {...}, "approval_id": "..."}`) |
| GET | `/approvals` | admin | pending approvals |
| POST | `/approvals/{id}/approve` / `deny` | admin | human decision |
| GET | `/audit` | admin | audit log |
| GET | `/.well-known/jwks.json` | public | gateway's public signing key |

Admin calls use the `X-Admin-Key` header (default `dev-admin-key`; set `AGENTPASS_ADMIN_KEY`).

### Using it from an agent

```python
from agentpass.client import AgentClient

agent = AgentClient("http://127.0.0.1:8000", agent_id, private_key_pem)
agent.login(delegation_id, scopes=["shop.search"])
agent.call("shop.search", {"query": "rice"})
```

## Security design

- **Agent authentication:** RFC 7523 `private_key_jwt`. The agent signs a JWT that lives at most 120s, with a single-use `jti` that blocks replay.
- **Access tokens:** EdDSA-signed JWTs with `sub` = user and `act.sub` = agent, scope-limited, valid for 5 minutes. Each one is also checked against the live agent and delegation state, so revocation takes effect immediately.
- **Least privilege:** delegated scopes ⊆ policy-allowed tools, and requested scopes ⊆ delegated scopes.
- **Approvals:** bound to the SHA-256 of `tool + args`, usable once, and cancelled if the agent is revoked.

## Project layout

```
agentpass/
  service.py   core logic: registry, token exchange, gateway, approvals, audit
  policy.py    policy engine (pure, unit-tested)
  server.py    HTTP API (Starlette)
  dashboard.py admin dashboard (single page)
  client.py    AgentClient / AdminClient SDK
  tools.py     mock tool backends behind a ToolBackend interface
  crypto.py    Ed25519 keys, JWKS
  db.py        SQLite storage
config/policies.yaml
examples/demo.py
tests/         28 tests: policy unit tests + end-to-end gateway tests
```

## Roadmap

1. ✅ Identity, delegated tokens, policy, approvals, audit, kill switch
2. **MCP gateway:** proxy real MCP servers, so `ToolBackend` becomes an MCP client
3. **WhatsApp approvals:** approve or deny from your phone, plus spending alerts
4. **Real tools:** Gmail API + a grocery API for the personal agent app
5. OPA/Cedar policies, OpenTelemetry traces, Postgres

## Publish to GitHub

```bash
./scripts/publish_github.sh            # creates github.com/<you>/agentpass and pushes
```

MIT licensed.
