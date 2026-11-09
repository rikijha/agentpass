"""SQLite storage. One small thread-safe wrapper; no ORM needed for an MVP."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    owner TEXT NOT NULL,
    purpose TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS delegations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    scopes TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS used_assertions (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS spend (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    amount REAL NOT NULL,
    ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    args TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    decided_at INTEGER
);
CREATE TABLE IF NOT EXISTS agent_policies (
    agent_name TEXT PRIMARY KEY,
    tools TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    agent_id TEXT,
    agent_name TEXT,
    user_id TEXT,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    detail TEXT
);
"""


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        with self._lock:
            self._conn.execute(sql, tuple(params))
            self._conn.commit()

    def one(self, sql: str, params: Iterable[Any] = ()) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(sql, tuple(params)).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(r) for r in rows]

    def audit(
        self,
        ts: int,
        action: str,
        decision: str,
        reason: str = "",
        agent: Optional[dict] = None,
        user_id: Optional[str] = None,
        detail: Optional[dict] = None,
    ) -> None:
        self.execute(
            "INSERT INTO audit (ts, agent_id, agent_name, user_id, action, decision, reason, detail)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ts,
                agent["id"] if agent else None,
                agent["name"] if agent else None,
                user_id,
                action,
                decision,
                reason,
                json.dumps(detail or {}, sort_keys=True),
            ),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
