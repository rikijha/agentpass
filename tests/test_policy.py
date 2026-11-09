from agentpass.policy import ALLOW, DENY, NEEDS_APPROVAL, PolicyEngine

POLICY = PolicyEngine({
    "agents": {
        "shopper": {
            "tools": {
                "shop.search": {},
                "shop.checkout": {
                    "max_amount": 3000,
                    "budget": {"amount": 5000, "period_days": 7},
                    "require_approval_above": 1500,
                },
            }
        },
        "mailer": {"tools": {"gmail.send": {"require_approval": True}}},
    }
})


def nothing_spent(days):
    return 0.0


def test_unknown_agent_is_denied():
    assert POLICY.evaluate("stranger", "shop.search", {}, nothing_spent).outcome == DENY


def test_unlisted_tool_is_denied():
    assert POLICY.evaluate("shopper", "gmail.read", {}, nothing_spent).outcome == DENY


def test_simple_allow():
    assert POLICY.evaluate("shopper", "shop.search", {"query": "milk"}, nothing_spent).outcome == ALLOW


def test_small_checkout_allowed():
    assert POLICY.evaluate("shopper", "shop.checkout", {"amount": 900}, nothing_spent).outcome == ALLOW


def test_checkout_above_threshold_needs_approval():
    d = POLICY.evaluate("shopper", "shop.checkout", {"amount": 2000}, nothing_spent)
    assert d.outcome == NEEDS_APPROVAL


def test_checkout_over_max_is_denied():
    d = POLICY.evaluate("shopper", "shop.checkout", {"amount": 3500}, nothing_spent)
    assert d.outcome == DENY and "per-call limit" in d.reason


def test_budget_counts_previous_spend():
    d = POLICY.evaluate("shopper", "shop.checkout", {"amount": 1000}, lambda days: 4500)
    assert d.outcome == DENY and "budget" in d.reason


def test_amount_required_and_positive():
    assert POLICY.evaluate("shopper", "shop.checkout", {}, nothing_spent).outcome == DENY
    assert POLICY.evaluate("shopper", "shop.checkout", {"amount": "abc"}, nothing_spent).outcome == DENY
    assert POLICY.evaluate("shopper", "shop.checkout", {"amount": -5}, nothing_spent).outcome == DENY


def test_always_requires_approval():
    assert POLICY.evaluate("mailer", "gmail.send", {}, nothing_spent).outcome == NEEDS_APPROVAL
