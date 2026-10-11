"""Verifier-owned challenges with SQLite transactional single-use claims.

The verifier, not the collector, generates and stores nonces. Challenge
consumption occurs only after external authentication and report checks.
"""

import secrets
import sqlite3
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Challenge:
    nonce: str
    principal: str
    execution_id: str
    expires_at: int


class ChallengeStore:
    def __init__(self, path: str):
        self.path = path
        with sqlite3.connect(path, timeout=10) as db:
            db.execute('CREATE TABLE IF NOT EXISTS challenges (nonce TEXT PRIMARY KEY, principal TEXT NOT NULL, execution_id TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)')

    def issue(self, *, principal: str, execution_id: str, now: int | None = None, ttl: int = 120) -> Challenge:
        if not isinstance(principal, str) or not principal or not isinstance(execution_id, str) or not execution_id or not 1 <= ttl <= 300:
            raise ValueError('invalid challenge parameters')
        issued = int(time.time()) if now is None else now
        challenge = Challenge(secrets.token_urlsafe(32), principal, execution_id, issued + ttl)
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute('INSERT INTO challenges (nonce,principal,execution_id,expires_at) VALUES (?,?,?,?)', (challenge.nonce, challenge.principal, challenge.execution_id, challenge.expires_at))
        return challenge

    def consume(self, *, nonce: str, principal: str, execution_id: str, now: int | None = None) -> bool:
        instant = int(time.time()) if now is None else now
        with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
            db.execute('BEGIN IMMEDIATE')
            cursor = db.execute('UPDATE challenges SET consumed=1 WHERE nonce=? AND principal=? AND execution_id=? AND expires_at>? AND consumed=0', (nonce, principal, execution_id, instant))
            db.execute('COMMIT')
            return cursor.rowcount == 1
