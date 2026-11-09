"""Policy engine: what each agent may do, how much it may spend, and what needs a human.

Policies live in a YAML file keyed by agent name. Anything not listed is denied.

Supported rules per tool:
    max_amount:              hard cap per call (args["amount"])
    budget:                  {amount: N, period_days: D} rolling spend cap
    require_approval:        true -> every call needs a human
    require_approval_above:  N -> calls with amount > N need a human
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import yaml

ALLOW = "allow"
DENY = "deny"
NEEDS_APPROVAL = "needs_approval"


@dataclass
class Decision:
    outcome: str  # allow | deny | needs_approval
    reason: str

    @property
    def allowed(self) -> bool:
        return self.outcome == ALLOW


RULE_KEYS = {"max_amount", "budget", "require_approval", "require_approval_above"}


def normalise_rule(rule: Optional[dict]) -> dict:
    """Validate one tool rule coming from the API; drop empty values."""
    rule = rule or {}
    if not isinstance(rule, dict):
        raise ValueError("each tool rule must be an object")
    unknown = set(rule) - RULE_KEYS
    if unknown:
        raise ValueError(f"unknown rule fields: {sorted(unknown)}")
    out: dict = {}
    for key in ("max_amount", "require_approval_above"):
        val = rule.get(key)
        if val not in (None, ""):
            num = float(val)
            if num <= 0:
                raise ValueError(f"{key} must be positive")
            out[key] = num
    if rule.get("require_approval"):
        out["require_approval"] = True
    budget = rule.get("budget")
    if budget:
        if not isinstance(budget, dict) or budget.get("amount") in (None, ""):
            raise ValueError("budget needs an amount")
        amount, days = float(budget["amount"]), int(budget.get("period_days") or 7)
        if amount <= 0 or days <= 0:
            raise ValueError("budget amount and period_days must be positive")
        out["budget"] = {"amount": amount, "period_days": days}
    return out


class PolicyEngine:
    def __init__(self, policies: dict):
        self.agents: dict = (policies or {}).get("agents") or {}

    @classmethod
    def from_file(cls, path: Path) -> "PolicyEngine":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh) or {})

    def set_agent_tools(self, agent_name: str, tools: dict) -> None:
        """Set (or replace) one agent's rules at runtime, e.g. from the dashboard."""
        self.agents[agent_name] = {"tools": tools}

    def rules_for(self, agent_name: str) -> dict:
        return dict(((self.agents.get(agent_name) or {}).get("tools") or {}))

    def allowed_tools(self, agent_name: str) -> set[str]:
        return set(((self.agents.get(agent_name) or {}).get("tools") or {}).keys())

    def evaluate(
        self,
        agent_name: str,
        tool: str,
        args: dict,
        spent_in_period: Callable[[int], float],
    ) -> Decision:
        """Decide on one tool call.

        ``spent_in_period(days)`` returns how much this agent already spent on
        this tool in the last ``days`` days (injected so the engine stays pure).
        """
        agent_policy = self.agents.get(agent_name)
        if agent_policy is None:
            return Decision(DENY, f"no policy for agent '{agent_name}' (default deny)")
        tools = agent_policy.get("tools") or {}
        if tool not in tools:
            return Decision(DENY, f"tool '{tool}' is not allowed for '{agent_name}'")
        rule = tools[tool] or {}

        amount: Optional[float] = None
        if any(k in rule for k in ("max_amount", "budget", "require_approval_above")):
            try:
                amount = float(args.get("amount"))
            except (TypeError, ValueError):
                return Decision(DENY, "this tool requires a numeric 'amount' argument")
            if amount <= 0:
                return Decision(DENY, "amount must be positive")

        if "max_amount" in rule and amount > float(rule["max_amount"]):
            return Decision(DENY, f"amount {amount:g} exceeds per-call limit {rule['max_amount']}")

        budget = rule.get("budget")
        if budget:
            days = int(budget.get("period_days", 7))
            limit = float(budget["amount"])
            already = spent_in_period(days)
            if already + amount > limit:
                return Decision(
                    DENY,
                    f"budget exceeded: {already:g} spent + {amount:g} > {limit:g} per {days} days",
                )

        if rule.get("require_approval"):
            return Decision(NEEDS_APPROVAL, f"'{tool}' always requires human approval")
        threshold = rule.get("require_approval_above")
        if threshold is not None and amount > float(threshold):
            return Decision(NEEDS_APPROVAL, f"amount {amount:g} is above approval threshold {threshold}")

        return Decision(ALLOW, "allowed by policy")
