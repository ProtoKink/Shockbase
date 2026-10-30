"""SQLite persistence for the local owner."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
from pathlib import Path


class Store:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS owner (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL,
                password_plain TEXT,
                decided INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self._conn.commit()

    def ensure_owner(self) -> str | None:
        """Return the generated password until the owner keeps or replaces it."""
        with self._lock:
            row = self._conn.execute(
                "SELECT password_plain, decided FROM owner WHERE id = 1"
            ).fetchone()
            if row is None:
                password = secrets.token_urlsafe(12)
                self._conn.execute(
                    """
                    INSERT INTO owner (id, password_hash, password_plain, decided)
                    VALUES (1, ?, ?, 0)
                    """,
                    (_hash_password(password), password),
                )
                self._conn.commit()
                return password
            if row["decided"]:
                return None
            plain = row["password_plain"]
            if plain is None:
                return None
            return str(plain)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
    )
    return f"{salt.hex()}:{digest.hex()}"
