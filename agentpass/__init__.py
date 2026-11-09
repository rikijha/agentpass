"""AgentPass: an identity, permission and audit gateway for AI agents.

Every agent gets its own identity (an Ed25519 key pair), receives short-lived
delegated tokens from a human user (RFC 8693-style "on behalf of" tokens with
an ``act`` claim), and every tool call it makes is checked against policy,
optionally paused for human approval, and written to an audit log.
"""

__version__ = "0.1.0"
