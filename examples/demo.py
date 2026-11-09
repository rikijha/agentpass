"""End-to-end demo: a grocery agent and an email agent acting for one user.

Run:  python examples/demo.py              (starts its own throwaway server)
      python examples/demo.py --url http://127.0.0.1:8000   (use a running server)
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from contextlib import nullcontext
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentpass.client import AdminClient, AgentClient  # noqa: E402
from agentpass.testing import running_server  # noqa: E402

GREEN, RED, YELLOW, BOLD, DIM, END = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"


def step(title: str) -> None:
    print(f"\n{BOLD}▶ {title}{END}")


def show(res: dict) -> dict:
    code = res.get("http_status")
    colour = GREEN if code == 200 or code == 201 else YELLOW if code == 202 else RED
    summary = res.get("message") or res.get("reason") or res.get("status") or ""
    if res.get("access_token"):
        summary = f"token issued: scope='{res['scope']}', expires in {res['expires_in']}s"
    if res.get("decision"):
        summary = f"{res['decision']}  {res.get('result')}"
    print(f"  {colour}{code}{END} {summary}")
    return res


def run(base: str, admin_key: str) -> None:
    admin = AdminClient(base, admin_key)
    user = "riki"

    step("Register two agents (each gets its own Ed25519 identity)")
    grocery = admin.register_agent("grocery-agent", owner=user, purpose="weekly groceries")
    email = admin.register_agent("email-agent", owner=user, purpose="triage my inbox")
    if grocery["http_status"] != 201 or email["http_status"] != 201:
        sys.exit(f"Registration failed (are these agents already registered on this server?): {grocery} {email}")
    print(f"  grocery-agent = {grocery['agent_id']}   email-agent = {email['agent_id']}")

    step("User delegates narrow permissions to each agent")
    g_dlg = admin.delegate(grocery["agent_id"], user, ["shop.search", "shop.checkout"])
    e_dlg = admin.delegate(email["agent_id"], user, ["gmail.read", "gmail.send"])
    print(f"  grocery: {g_dlg['scopes']}   email: {e_dlg['scopes']}")

    g = AgentClient(base, grocery["agent_id"], grocery["private_key_pem"])
    e = AgentClient(base, email["agent_id"], email["private_key_pem"])

    step("Agents prove identity (signed assertion) and get 5-minute tokens")
    show(g.login(g_dlg["delegation_id"]))
    show(e.login(e_dlg["delegation_id"]))

    step("grocery-agent searches for rice")
    show(g.call("shop.search", {"query": "rice"}))

    step("grocery-agent places a ₹885 order (under approval threshold)")
    show(g.call("shop.checkout", {"items": ["ATTA-5KG", "RICE-5KG"], "amount": 885}))

    step("grocery-agent tries a ₹2,000 order (needs human approval)")
    big_order = {"items": ["GHEE-1L", "RICE-5KG", "DAL-1KG", "ATTA-5KG"], "amount": 2000}
    pending = show(g.call("shop.checkout", big_order))

    step("Agent tries to swap in a bigger amount on the same approval")
    admin.approve(pending["approval_id"])
    print(f"  {DIM}(user approved {pending['approval_id']} for ₹2,000){END}")
    show(g.call("shop.checkout", {**big_order, "amount": 2900}, approval_id=pending["approval_id"]))

    step("Agent retries with the approved args")
    show(g.call("shop.checkout", big_order, approval_id=pending["approval_id"]))

    step("grocery-agent tries a ₹4,000 order (over per-order limit)")
    show(g.call("shop.checkout", {"items": ["GHEE-1L"], "amount": 4000}))

    step("grocery-agent tries ₹2,500 more (would break the ₹5,000 weekly budget)")
    show(g.call("shop.checkout", {"items": ["GHEE-1L"], "amount": 2500}))

    step("grocery-agent tries to read email (not delegated to it)")
    show(g.call("gmail.read", {}))

    step("email-agent asks for a scope it was never given")
    show(e.login(e_dlg["delegation_id"], scopes=["gmail.read", "shop.checkout"]))
    e.login(e_dlg["delegation_id"])

    step("email-agent reads unread mail")
    show(e.call("gmail.read", {"unread_only": True}))

    step("email-agent drafts a reply (sending always needs approval)")
    show(e.call("gmail.send", {"to": "hr@example.com", "subject": "Re: Interview", "body": "Confirmed, thanks!"}))

    step("Kill switch: user revokes grocery-agent; its still-valid token stops working")
    admin.revoke_agent(grocery["agent_id"])
    show(g.call("shop.search", {"query": "milk"}))

    step("Audit log (newest first)")
    for ev in admin.audit(limit=40):
        d = ev["decision"]
        colour = GREEN if d in ("ok", "allow", "allow_approved", "approved") else YELLOW if d == "needs_approval" else RED
        print(f"  {(ev['agent_name'] or '-'):14} {ev['action']:22} {colour}{d:15}{END} {DIM}{ev['reason']}{END}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--url", help="use an already-running AgentPass server")
    p.add_argument("--admin-key", default="dev-admin-key")
    a = p.parse_args()
    tmp = tempfile.TemporaryDirectory() if not a.url else None
    ctx = nullcontext(a.url) if a.url else running_server(Path(tmp.name))
    with ctx as base:
        print(f"{BOLD}AgentPass demo{END} against {base}")
        run(base, a.admin_key)
    if tmp:
        tmp.cleanup()
    print(f"\n{GREEN}Demo finished.{END}")


if __name__ == "__main__":
    main()
