"""End-to-end tests against a real server running in a background thread."""

import time
import uuid

import jwt
import pytest

from agentpass.client import AdminClient, AgentClient
from agentpass.crypto import generate_keypair, load_private_key
from agentpass.testing import running_server


@pytest.fixture()
def base(tmp_path):
    with running_server(tmp_path) as url:
        yield url


@pytest.fixture()
def admin(base):
    return AdminClient(base)


def make_agent(base, admin, name, scopes):
    reg = admin.register_agent(name, owner="riki", purpose="test")
    assert reg["http_status"] == 201
    dlg = admin.delegate(reg["agent_id"], "riki", scopes)
    assert dlg["http_status"] == 201
    client = AgentClient(base, reg["agent_id"], reg["private_key_pem"])
    assert client.login(dlg["delegation_id"])["http_status"] == 200
    return reg, dlg, client


def test_health_and_jwks(base):
    import requests
    assert requests.get(f"{base}/health").json()["status"] == "ok"
    keys = requests.get(f"{base}/.well-known/jwks.json").json()["keys"]
    assert keys[0]["crv"] == "Ed25519"


def test_admin_key_required(base):
    bad = AdminClient(base, admin_key="wrong")
    assert bad.register_agent("x", "y", "z")["http_status"] == 401


def test_access_token_carries_user_and_agent(base, admin):
    reg, _, client = make_agent(base, admin, "grocery-agent", ["shop.search"])
    claims = jwt.decode(client.access_token, options={"verify_signature": False})
    assert claims["sub"] == "riki"
    assert claims["act"]["sub"] == reg["agent_id"]
    assert claims["scope"] == "shop.search"
    assert claims["exp"] - claims["iat"] <= 300


def test_delegation_cannot_exceed_policy(base, admin):
    reg = admin.register_agent("grocery-agent", owner="riki", purpose="test")
    res = admin.delegate(reg["agent_id"], "riki", ["gmail.read"])
    assert res["http_status"] == 400 and res["error"] == "invalid_scope"


def test_scope_escalation_blocked(base, admin):
    _, dlg, client = make_agent(base, admin, "grocery-agent", ["shop.search"])
    res = client.login(dlg["delegation_id"], scopes=["shop.search", "shop.checkout"])
    assert res["http_status"] == 400 and res["error"] == "invalid_scope"


def test_tool_outside_token_scope_is_forbidden(base, admin):
    _, _, client = make_agent(base, admin, "grocery-agent", ["shop.search"])
    res = client.call("shop.checkout", {"items": ["X"], "amount": 10})
    assert res["http_status"] == 403 and res["error"] == "insufficient_scope"


def test_wrong_key_cannot_impersonate_agent(base, admin):
    reg, dlg, _ = make_agent(base, admin, "grocery-agent", ["shop.search"])
    attacker_key, _ = generate_keypair()
    impostor = AgentClient(base, reg["agent_id"], attacker_key)
    res = impostor.login(dlg["delegation_id"])
    assert res["http_status"] == 401 and res["error"] == "invalid_client"


def test_assertion_replay_blocked(base, admin):
    import requests
    reg, dlg, _ = make_agent(base, admin, "grocery-agent", ["shop.search"])
    now = int(time.time())
    assertion = jwt.encode(
        {"iss": reg["agent_id"], "sub": reg["agent_id"], "aud": "agentpass",
         "iat": now, "exp": now + 60, "jti": uuid.uuid4().hex},
        load_private_key(reg["private_key_pem"]), algorithm="EdDSA")
    body = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_assertion": assertion, "delegation_id": dlg["delegation_id"]}
    assert requests.post(f"{base}/token", json=body).status_code == 200
    second = requests.post(f"{base}/token", json=body)
    assert second.status_code == 401 and "already used" in second.json()["message"]


def test_forged_token_rejected(base, admin):
    _, _, client = make_agent(base, admin, "grocery-agent", ["shop.search"])
    other_key, _ = generate_keypair()
    claims = jwt.decode(client.access_token, options={"verify_signature": False})
    client.access_token = jwt.encode(claims, load_private_key(other_key), algorithm="EdDSA")
    assert client.call("shop.search", {})["http_status"] == 401


def test_approval_flow_and_arg_tampering(base, admin):
    _, _, client = make_agent(base, admin, "grocery-agent", ["shop.checkout"])
    order = {"items": ["GHEE-1L"], "amount": 2000}
    pending = client.call("shop.checkout", order)
    assert pending["http_status"] == 202
    apr = pending["approval_id"]

    assert client.call("shop.checkout", order, approval_id=apr)["error"] == "approval_pending"
    admin.approve(apr)
    tampered = client.call("shop.checkout", {**order, "amount": 2999}, approval_id=apr)
    assert tampered["http_status"] == 403
    ok = client.call("shop.checkout", order, approval_id=apr)
    assert ok["http_status"] == 200 and ok["decision"] == "allow_approved"
    # one approval = one use
    assert client.call("shop.checkout", order, approval_id=apr)["http_status"] == 403


def test_denied_approval(base, admin):
    _, _, client = make_agent(base, admin, "email-agent", ["gmail.send"])
    mail = {"to": "a@b.com", "subject": "hi", "body": "hello"}
    apr = client.call("gmail.send", mail)["approval_id"]
    admin.deny(apr)
    assert client.call("gmail.send", mail, approval_id=apr)["http_status"] == 403


def test_budget_enforced_across_calls(base, admin):
    _, _, client = make_agent(base, admin, "grocery-agent", ["shop.checkout"])
    for _ in range(3):
        assert client.call("shop.checkout", {"items": ["A"], "amount": 1400})["http_status"] == 200
    res = client.call("shop.checkout", {"items": ["A"], "amount": 1400})  # 5600 > 5000
    assert res["http_status"] == 403 and "budget" in res["message"]


def test_kill_switch_invalidates_live_token(base, admin):
    reg, dlg, client = make_agent(base, admin, "grocery-agent", ["shop.search"])
    assert client.call("shop.search", {})["http_status"] == 200
    admin.revoke_agent(reg["agent_id"])
    assert client.call("shop.search", {})["http_status"] == 401
    assert client.login(dlg["delegation_id"])["http_status"] == 401


def test_revoked_delegation_invalidates_token(base, admin):
    import requests
    _, dlg, client = make_agent(base, admin, "grocery-agent", ["shop.search"])
    requests.post(f"{base}/delegations/{dlg['delegation_id']}/revoke",
                  headers={"X-Admin-Key": "dev-admin-key"})
    assert client.call("shop.search", {})["http_status"] == 401


def test_every_decision_is_audited(base, admin):
    reg, _, client = make_agent(base, admin, "grocery-agent", ["shop.search"])
    client.call("shop.search", {"query": "milk"})
    client.call("shop.checkout", {"amount": 1})
    actions = [(e["action"], e["decision"]) for e in admin.audit(agent_id=reg["agent_id"])]
    assert ("tool:shop.search", "allow") in actions
    assert ("tool:shop.checkout", "deny") in actions
    assert ("token.exchange", "ok") in actions


def test_create_agent_with_custom_tools_and_limits(base, admin):
    res = admin._req("POST", "/agents", json={
        "name": "pharmacy-agent", "owner": "riki", "purpose": "monthly medicines",
        "tools": {"shop.search": {}, "shop.checkout": {"max_amount": "800", "require_approval_above": 500}},
    })
    assert res["http_status"] == 201
    assert res["allowed_tools"] == ["shop.checkout", "shop.search"]
    dlg = admin.delegate(res["agent_id"], "riki", ["shop.search", "shop.checkout"])
    client = AgentClient(base, res["agent_id"], res["private_key_pem"])
    client.login(dlg["delegation_id"])
    assert client.call("shop.checkout", {"items": ["A"], "amount": 400})["http_status"] == 200
    assert client.call("shop.checkout", {"items": ["A"], "amount": 600})["http_status"] == 202
    assert client.call("shop.checkout", {"items": ["A"], "amount": 900})["http_status"] == 403
    agents = {a["name"]: a for a in admin._req("GET", "/agents")["agents"]}
    assert agents["pharmacy-agent"]["rules"]["shop.checkout"]["max_amount"] == 800


def test_custom_policy_survives_restart(tmp_path):
    with running_server(tmp_path) as url:
        AdminClient(url)._req("POST", "/agents", json={
            "name": "notes-agent", "owner": "riki", "purpose": "x", "tools": {"gmail.read": {}}})
    with running_server(tmp_path) as url:
        agents = AdminClient(url)._req("GET", "/agents")["agents"]
        assert agents[0]["allowed_tools"] == ["gmail.read"]


def test_create_agent_validation(base, admin):
    def make(**body):
        return admin._req("POST", "/agents", json={"owner": "riki", "purpose": "x", **body})
    assert make(name="Bad Name!", tools={"gmail.read": {}})["http_status"] == 400
    assert make(name="no-tools", tools={})["http_status"] == 400
    assert make(name="no-policy")["http_status"] == 400          # not in YAML, no tools given
    assert make(name="bad-tool", tools={"bank.transfer": {}})["http_status"] == 400
    assert make(name="bad-rule", tools={"shop.checkout": {"max_amount": -1}})["http_status"] == 400
    assert make(name="ok-agent", tools={"gmail.read": {}})["http_status"] == 201
    assert make(name="ok-agent", tools={"gmail.read": {}})["http_status"] == 409


def test_tools_endpoint_and_dashboard(base, admin):
    import requests
    assert "shop.checkout" in admin._req("GET", "/tools")["tools"]
    page = requests.get(base).text
    assert "Add agent" in page and "createAgent" in page
