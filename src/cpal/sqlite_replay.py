"""SQLite replay ledger for a single host/shared database file.

Not suitable for independent hosts with separate files or a network filesystem.
"""

import sqlite3
from pathlib import Path


class SQLiteReplayLedger:
    def __init__(self, path: str):
        if path == ':memory:':
            raise ValueError('Replay ledger must be durable')
        self.path = str(Path(path))
        with self._connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS consumed_nonces (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)')

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute('PRAGMA busy_timeout=10000')
        return db

    def consume(self, nonce: str, expires_at: int, now: int) -> bool:
        if not isinstance(nonce, str) or not nonce or type(expires_at) is not int or type(now) is not int or expires_at <= now:
            return False
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                # No deletion here: permanent nonce uniqueness avoids accepting a reused nonce after expiry.
                result = db.execute('INSERT OR IGNORE INTO consumed_nonces(nonce, expires_at) VALUES (?, ?)', (nonce, expires_at))
                db.execute('COMMIT')
                return result.rowcount == 1
            except BaseException:
                db.execute('ROLLBACK')
                raise
