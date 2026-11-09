"""Tool backends the gateway forwards allowed calls to.

These are mock tools so the project runs with no external accounts. The
gateway only depends on the ``ToolBackend`` interface, so a real backend
(an MCP client session, the Gmail API, a grocery API) can be dropped in later.
"""

from __future__ import annotations

import uuid
from typing import Callable, Dict, Protocol


class ToolError(Exception):
    pass


class ToolBackend(Protocol):
    def call(self, tool: str, args: dict) -> dict: ...

    def names(self) -> list[str]: ...


_CATALOG = [
    {"sku": "MILK-1L", "name": "Amul Taaza milk 1L", "price": 68},
    {"sku": "ATTA-5KG", "name": "Aashirvaad atta 5kg", "price": 295},
    {"sku": "RICE-5KG", "name": "India Gate basmati rice 5kg", "price": 720},
    {"sku": "DAL-1KG", "name": "Toor dal 1kg", "price": 165},
    {"sku": "GHEE-1L", "name": "Amul ghee 1L", "price": 630},
]

_INBOX = [
    {"id": "m1", "from": "hr@example.com", "subject": "Interview slot confirmed", "unread": True},
    {"id": "m2", "from": "bank@example.com", "subject": "Your statement is ready", "unread": True},
    {"id": "m3", "from": "friend@example.com", "subject": "Dinner on Saturday?", "unread": False},
]


def _shop_search(args: dict) -> dict:
    q = str(args.get("query", "")).lower()
    return {"results": [i for i in _CATALOG if q in i["name"].lower() or not q]}


def _shop_checkout(args: dict) -> dict:
    items = args.get("items") or []
    if not items:
        raise ToolError("checkout needs at least one item")
    return {"order_id": f"ord_{uuid.uuid4().hex[:10]}", "items": items, "amount": args["amount"], "status": "placed"}


def _gmail_read(args: dict) -> dict:
    unread_only = bool(args.get("unread_only", False))
    return {"messages": [m for m in _INBOX if m["unread"] or not unread_only]}


def _gmail_send(args: dict) -> dict:
    for k in ("to", "subject", "body"):
        if not args.get(k):
            raise ToolError(f"gmail.send needs '{k}'")
    return {"sent": True, "message_id": f"msg_{uuid.uuid4().hex[:10]}", "to": args["to"]}


class MockToolBackend:
    def __init__(self) -> None:
        self._tools: Dict[str, Callable[[dict], dict]] = {
            "shop.search": _shop_search,
            "shop.checkout": _shop_checkout,
            "gmail.read": _gmail_read,
            "gmail.send": _gmail_send,
        }

    def names(self) -> list[str]:
        return sorted(self._tools)

    def call(self, tool: str, args: dict) -> dict:
        fn = self._tools.get(tool)
        if fn is None:
            raise ToolError(f"unknown tool '{tool}'")
        return fn(args)
