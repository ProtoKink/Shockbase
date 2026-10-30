"""SQLite persistence for the owner, shockers, share codes, and operate logs.

The owner password is stored as a scrypt hash. The generated plaintext is kept
only until the owner keeps that password or replaces it.

Shocker rows are names and the local pause flag, keyed by shocker id. A hub
poll inserts ids it has not seen before and leaves every other row in place.

A share code has one shocker list and one permission set. Duration caps are
milliseconds: app durations are converted to milliseconds, then compared to
the cap. 1000 is one second. The ceiling is 15 seconds (15000).

Logs record every operate attempt, including rejects. ``list_logs`` does not
consult ``can_log``; the app route does.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MIN_INTENSITY = 0
MAX_INTENSITY = 100
MIN_DURATION_MS = 10
MAX_DURATION_MS = 15_000

_MAX_NAME_LEN = 100
_MAX_PASSWORD_LEN = 256
_MAX_LOG_TEXT = 256
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64
_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{1,16}$")


def default_shocker_name(shocker_id: int) -> str:
    """Name used until the owner renames this shocker."""
    return f"Shocker {shocker_id}"


def default_permissions() -> Permissions:
    """Shock, vibrate, and beep enabled at the full range. Log access off."""
    return Permissions(
        shock=IntensityLimit(True, MAX_INTENSITY, MAX_DURATION_MS),
        vibrate=IntensityLimit(True, MAX_INTENSITY, MAX_DURATION_MS),
        beep=DurationLimit(True, MAX_DURATION_MS),
        should_log=False,
    )


@dataclass(frozen=True)
class Owner:
    """Owner password state.

    ``pending_password`` is the generated plaintext while the owner has not
    kept or replaced it, and ``None`` after that choice.
    """

    decided: bool
    pending_password: str | None


@dataclass(frozen=True)
class Shocker:
    """Local shocker record.

    ``paused`` is the owner's pause flag. Firmware pause comes from the hub.
    """

    id: int
    name: str
    paused: bool


@dataclass(frozen=True)
class IntensityLimit:
    """Shock or vibrate permission.

    ``max_duration_ms`` is compared after the request duration is converted to
    milliseconds.
    """

    enabled: bool
    max_intensity: int
    max_duration_ms: int

    def __post_init__(self) -> None:
        _require_bool(self.enabled, "enabled")
        _require_range(
            self.max_intensity,
            "max_intensity",
            MIN_INTENSITY,
            MAX_INTENSITY,
        )
        _require_range(
            self.max_duration_ms,
            "max_duration_ms",
            MIN_DURATION_MS,
            MAX_DURATION_MS,
        )


@dataclass(frozen=True)
class DurationLimit:
    """Beep permission. Beep has no intensity."""

    enabled: bool
    max_duration_ms: int

    def __post_init__(self) -> None:
        _require_bool(self.enabled, "enabled")
        _require_range(
            self.max_duration_ms,
            "max_duration_ms",
            MIN_DURATION_MS,
            MAX_DURATION_MS,
        )


@dataclass(frozen=True)
class Permissions:
    """The one permission set shared by every shocker on a code."""

    shock: IntensityLimit
    vibrate: IntensityLimit
    beep: DurationLimit
    should_log: bool

    def __post_init__(self) -> None:
        if not isinstance(self.shock, IntensityLimit):
            raise ValueError("shock must be an IntensityLimit")
        if not isinstance(self.vibrate, IntensityLimit):
            raise ValueError("vibrate must be an IntensityLimit")
        if not isinstance(self.beep, DurationLimit):
            raise ValueError("beep must be a DurationLimit")
        _require_bool(self.should_log, "should_log")


@dataclass(frozen=True)
class Code:
    """A share code.

    ``shocker_ids`` is empty when the code can authenticate but cannot operate.
    ``revoked`` codes are hidden from app lookup.
    """

    code: str
    shocker_ids: tuple[int, ...]
    permissions: Permissions
    revoked: bool


@dataclass(frozen=True)
class LogEntry:
    """One operate attempt.

    ``code`` is ``None`` for owner operations. ``duration_ms`` is the duration
    the caller stored, in milliseconds when the request was normalized.
    ``op`` is ``"0"``, ``"1"``, ``"2"``, or ``"end"``.
    """

    id: int
    time: str
    code: str | None
    shocker_id: int | None
    sender: str | None
    op: str | None
    intensity: int | None
    duration_ms: int | None
    success: bool
    response: str


class Store:
    """SQLite database at ``data/shockbase.db`` (or a test path)."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self.path,
            timeout=5.0,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.execute("PRAGMA journal_mode = WAL").fetchone()
        self._create_schema()
        self._conn.commit()

    def ensure_owner(self) -> str | None:
        """Return the generated password until the owner keeps or replaces it.

        Creates the owner on first call. Returns ``None`` once that choice is
        made. A leftover plaintext from after that choice is deleted.
        """
        with self._lock:
            row = self._fetch_owner()
            if row is None:
                password = secrets.token_urlsafe(12)
                with self._tx():
                    self._conn.execute(
                        """
                        INSERT INTO owner (id, password_hash, password_plain, decided)
                        VALUES (1, ?, ?, 0)
                        """,
                        (_hash_password(password), password),
                    )
                return password
            if row["decided"]:
                return None
            plain = row["password_plain"]
            if plain is None:
                return None
            return str(plain)

    def owner(self) -> Owner:
        """Password state for the login page. Raises ``KeyError`` before the first boot row exists."""
        with self._lock:
            row = self._fetch_owner()
            if row is None:
                raise KeyError("owner")
            return _owner_from_row(row)

    def verify_password(self, password: str) -> bool:
        """Compare ``password`` to the scrypt hash. Missing owner is a mismatch."""
        if (
            not isinstance(password, str)
            or password == ""
            or len(password) > _MAX_PASSWORD_LEN
        ):
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT password_hash FROM owner WHERE id = 1"
            ).fetchone()
            if row is None:
                return False
            return _verify_password(password, str(row["password_hash"]))

    def keep_password(self) -> None:
        """Accept the generated password: mark it decided and delete the plaintext."""
        with self._lock:
            self._require_owner()
            with self._tx():
                self._conn.execute(
                    """
                    UPDATE owner
                    SET decided = 1, password_plain = NULL
                    WHERE id = 1
                    """
                )

    def change_password(self, password: str) -> None:
        """Replace the hash, mark it decided, and delete any stored plaintext."""
        _check_password_choice(password)
        with self._lock:
            self._require_owner()
            with self._tx():
                self._conn.execute(
                    """
                    UPDATE owner
                    SET password_hash = ?, password_plain = NULL, decided = 1
                    WHERE id = 1
                    """,
                    (_hash_password(password),),
                )

    def ensure_shockers(self, shocker_ids: Iterable[int]) -> list[Shocker]:
        """Insert ids the hub reported that are not already stored.

        Existing names and pause flags are left alone. Ids absent from
        ``shocker_ids`` stay in the database. Returns every stored shocker,
        ordered by id.
        """
        ids = [_shocker_id(shocker_id) for shocker_id in shocker_ids]
        with self._lock:
            with self._tx():
                for shocker_id in ids:
                    self._conn.execute(
                        """
                        INSERT OR IGNORE INTO shockers (id, name, paused)
                        VALUES (?, ?, 0)
                        """,
                        (shocker_id, default_shocker_name(shocker_id)),
                    )
            return self._list_shockers()

    def list_shockers(self) -> list[Shocker]:
        """Every stored shocker, ordered by id."""
        with self._lock:
            return self._list_shockers()

    def get_shocker(self, shocker_id: int) -> Shocker | None:
        """The stored shocker, or ``None`` when this id has never been seen."""
        shocker_id = _shocker_id(shocker_id)
        with self._lock:
            return self._get_shocker(shocker_id)

    def rename_shocker(self, shocker_id: int, name: str) -> Shocker:
        """Set the local name. Raises ``KeyError`` when the id is not stored."""
        shocker_id = _shocker_id(shocker_id)
        name = _shocker_name(name)
        with self._lock:
            with self._tx():
                updated = self._conn.execute(
                    "UPDATE shockers SET name = ? WHERE id = ?",
                    (name, shocker_id),
                )
                if updated.rowcount == 0:
                    raise KeyError(shocker_id)
            shocker = self._get_shocker(shocker_id)
            assert shocker is not None
            return shocker

    def set_paused(self, shocker_id: int, paused: bool) -> Shocker:
        """Set the local pause flag. Raises ``KeyError`` when the id is not stored."""
        shocker_id = _shocker_id(shocker_id)
        _require_bool(paused, "paused")
        with self._lock:
            with self._tx():
                updated = self._conn.execute(
                    "UPDATE shockers SET paused = ? WHERE id = ?",
                    (int(paused), shocker_id),
                )
                if updated.rowcount == 0:
                    raise KeyError(shocker_id)
            shocker = self._get_shocker(shocker_id)
            assert shocker is not None
            return shocker

    def create_code(
        self,
        *,
        code: str | None = None,
        shocker_ids: Iterable[int] = (),
        permissions: Permissions | None = None,
    ) -> Code:
        """Create a share code.

        Omit ``code`` to generate one. The shocker list starts empty unless
        ``shocker_ids`` is set. Permissions default to the full operate range
        with ``can_log`` off. Raises ``ValueError`` when ``code`` is already
        stored, including when that row is revoked.
        """
        perms = default_permissions() if permissions is None else permissions
        if not isinstance(perms, Permissions):
            raise ValueError("permissions must be a Permissions")
        ids = _id_set(shocker_ids)
        explicit = None if code is None else _require_code_text(code)
        with self._lock:
            key = self._generate_code() if explicit is None else explicit
            if self._code_exists(key):
                raise ValueError("code already exists")
            with self._tx():
                self._insert_code(key, perms)
                self._replace_members(key, ids)
            loaded = self._load_code(key, active_only=False)
            assert loaded is not None
            return loaded

    def revoke_code(self, code: str) -> Code:
        """Invalidate a code for app lookup. The row, list, and permissions stay."""
        key = _require_code_text(code)
        with self._lock:
            with self._tx():
                updated = self._conn.execute(
                    "UPDATE codes SET revoked = 1 WHERE code = ?",
                    (key,),
                )
                if updated.rowcount == 0:
                    raise KeyError(key)
            loaded = self._load_code(key, active_only=False)
            assert loaded is not None
            return loaded

    def active_code(self, code: object) -> Code | None:
        """The code apps may use.

        ``None`` when ``code`` is empty, unknown, or revoked.
        """
        key = _query_code(code)
        if key is None:
            return None
        with self._lock:
            return self._load_code(key, active_only=True)

    def find_code(self, code: object) -> Code | None:
        """Owner lookup. Includes revoked codes. ``None`` when nothing matches."""
        key = _query_code(code)
        if key is None:
            return None
        with self._lock:
            return self._load_code(key, active_only=False)

    def list_codes(self, *, include_revoked: bool = True) -> list[Code]:
        """Share codes ordered by the code string."""
        with self._lock:
            sql = "SELECT * FROM codes"
            if not include_revoked:
                sql += " WHERE revoked = 0"
            sql += " ORDER BY code"
            rows = self._conn.execute(sql).fetchall()
            return self._codes_from_rows(rows)

    def set_code_shockers(self, code: str, shocker_ids: Iterable[int]) -> Code:
        """Replace the shocker list. Does not delete shocker rows."""
        key = _require_code_text(code)
        ids = _id_set(shocker_ids)
        with self._lock:
            self._require_code(key)
            with self._tx():
                self._replace_members(key, ids)
            loaded = self._load_code(key, active_only=False)
            assert loaded is not None
            return loaded

    def add_code_shocker(self, code: str, shocker_id: int) -> Code:
        """Add one id to the code. The shocker row does not have to exist yet."""
        key = _require_code_text(code)
        shocker_id = _shocker_id(shocker_id)
        with self._lock:
            self._require_code(key)
            with self._tx():
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO code_shockers (code, shocker_id)
                    VALUES (?, ?)
                    """,
                    (key, shocker_id),
                )
            loaded = self._load_code(key, active_only=False)
            assert loaded is not None
            return loaded

    def remove_code_shocker(self, code: str, shocker_id: int) -> Code:
        """Drop one id from the code. The shocker row stays."""
        key = _require_code_text(code)
        shocker_id = _shocker_id(shocker_id)
        with self._lock:
            self._require_code(key)
            with self._tx():
                self._conn.execute(
                    """
                    DELETE FROM code_shockers
                    WHERE code = ? AND shocker_id = ?
                    """,
                    (key, shocker_id),
                )
            loaded = self._load_code(key, active_only=False)
            assert loaded is not None
            return loaded

    def set_permissions(self, code: str, permissions: Permissions) -> Code:
        """Replace the code's permission set."""
        key = _require_code_text(code)
        if not isinstance(permissions, Permissions):
            raise ValueError("permissions must be a Permissions")
        with self._lock:
            self._require_code(key)
            with self._tx():
                self._conn.execute(
                    """
                    UPDATE codes SET
                        shock_enabled = ?,
                        shock_max_intensity = ?,
                        shock_max_duration_ms = ?,
                        vibrate_enabled = ?,
                        vibrate_max_intensity = ?,
                        vibrate_max_duration_ms = ?,
                        beep_enabled = ?,
                        beep_max_duration_ms = ?,
                        can_log = ?
                    WHERE code = ?
                    """,
                    (*_permission_values(permissions), key),
                )
            loaded = self._load_code(key, active_only=False)
            assert loaded is not None
            return loaded

    def add_log(
        self,
        *,
        response: str,
        success: bool,
        code: str | None = None,
        shocker_id: int | None = None,
        sender: str | None = None,
        op: int | str | None = None,
        intensity: int | None = None,
        duration_ms: int | None = None,
        time: str | None = None,
    ) -> LogEntry:
        """Append an operate attempt.

        ``code`` is stored even when it does not match a share code, so
        rejects are visible to the owner. ``None`` marks an owner operation.
        """
        if not isinstance(response, str):
            raise ValueError("response must be a string")
        _require_bool(success, "success")
        logged_code = _log_text(code, "code")
        logged_sender = _log_text(sender, "sender")
        logged_op = _log_op(op)
        logged_shocker = _optional_int(shocker_id, "shocker_id")
        logged_intensity = _optional_int(intensity, "intensity")
        logged_duration = _optional_int(duration_ms, "duration_ms")
        logged_at = _log_time(time)
        with self._lock:
            with self._tx():
                cursor = self._conn.execute(
                    """
                    INSERT INTO logs (
                        logged_at, code, shocker_id, sender, op,
                        intensity, duration_ms, success, response
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        logged_at,
                        logged_code,
                        logged_shocker,
                        logged_sender,
                        logged_op,
                        logged_intensity,
                        logged_duration,
                        int(success),
                        response,
                    ),
                )
                log_id = cursor.lastrowid
                row = self._conn.execute(
                    "SELECT * FROM logs WHERE id = ?",
                    (log_id,),
                ).fetchone()
            assert row is not None
            return _log_from_row(row)

    def list_logs(
        self,
        *,
        code: str | None = None,
        limit: int | None = None,
    ) -> list[LogEntry]:
        """Operate log, newest first.

        Pass ``code`` to keep only that code's rows. Owner rows (no code) are
        included only when ``code`` is omitted. This does not check ``can_log``.
        """
        if limit is not None and (
            isinstance(limit, bool) or not isinstance(limit, int) or limit < 0
        ):
            raise ValueError("limit must be a non-negative integer")
        where = ""
        args: list[object] = []
        if code is not None:
            if not isinstance(code, str):
                raise ValueError("code must be a string")
            key = code.strip()
            if key == "":
                return []
            where = " WHERE code = ?"
            args.append(key)
        sql = f"SELECT * FROM logs{where} ORDER BY id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [_log_from_row(row) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _create_schema(self) -> None:
        self._conn.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS owner (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL,
                password_plain TEXT,
                decided INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS shockers (
                id INTEGER PRIMARY KEY CHECK (id >= 0),
                name TEXT NOT NULL CHECK (length(name) > 0),
                paused INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1))
            );

            CREATE TABLE IF NOT EXISTS codes (
                code TEXT PRIMARY KEY CHECK (length(code) > 0),
                revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
                shock_enabled INTEGER NOT NULL CHECK (shock_enabled IN (0, 1)),
                shock_max_intensity INTEGER NOT NULL
                    CHECK (shock_max_intensity BETWEEN {MIN_INTENSITY} AND {MAX_INTENSITY}),
                shock_max_duration_ms INTEGER NOT NULL
                    CHECK (
                        shock_max_duration_ms BETWEEN {MIN_DURATION_MS} AND {MAX_DURATION_MS}
                    ),
                vibrate_enabled INTEGER NOT NULL CHECK (vibrate_enabled IN (0, 1)),
                vibrate_max_intensity INTEGER NOT NULL
                    CHECK (
                        vibrate_max_intensity BETWEEN {MIN_INTENSITY} AND {MAX_INTENSITY}
                    ),
                vibrate_max_duration_ms INTEGER NOT NULL
                    CHECK (
                        vibrate_max_duration_ms BETWEEN {MIN_DURATION_MS} AND {MAX_DURATION_MS}
                    ),
                beep_enabled INTEGER NOT NULL CHECK (beep_enabled IN (0, 1)),
                beep_max_duration_ms INTEGER NOT NULL
                    CHECK (
                        beep_max_duration_ms BETWEEN {MIN_DURATION_MS} AND {MAX_DURATION_MS}
                    ),
                can_log INTEGER NOT NULL CHECK (can_log IN (0, 1))
            );

            CREATE TABLE IF NOT EXISTS code_shockers (
                code TEXT NOT NULL REFERENCES codes (code) ON DELETE CASCADE,
                shocker_id INTEGER NOT NULL CHECK (shocker_id >= 0),
                PRIMARY KEY (code, shocker_id)
            );

            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                logged_at TEXT NOT NULL,
                code TEXT,
                shocker_id INTEGER,
                sender TEXT,
                op TEXT,
                intensity INTEGER,
                duration_ms INTEGER,
                success INTEGER NOT NULL CHECK (success IN (0, 1)),
                response TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS logs_code_idx ON logs (code);
            """
        )

    @contextmanager
    def _tx(self) -> Iterator[None]:
        try:
            yield
        except Exception:
            self._conn.rollback()
            raise
        else:
            self._conn.commit()

    def _fetch_owner(self) -> sqlite3.Row | None:
        row = self._conn.execute("SELECT * FROM owner WHERE id = 1").fetchone()
        if row is None:
            return None
        if row["decided"] and row["password_plain"] is not None:
            self._conn.execute(
                "UPDATE owner SET password_plain = NULL WHERE id = 1"
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM owner WHERE id = 1").fetchone()
        return row

    def _require_owner(self) -> None:
        row = self._conn.execute("SELECT id FROM owner WHERE id = 1").fetchone()
        if row is None:
            raise KeyError("owner")

    def _list_shockers(self) -> list[Shocker]:
        rows = self._conn.execute(
            "SELECT * FROM shockers ORDER BY id"
        ).fetchall()
        return [_shocker_from_row(row) for row in rows]

    def _get_shocker(self, shocker_id: int) -> Shocker | None:
        row = self._conn.execute(
            "SELECT * FROM shockers WHERE id = ?",
            (shocker_id,),
        ).fetchone()
        if row is None:
            return None
        return _shocker_from_row(row)

    def _generate_code(self) -> str:
        for _ in range(8):
            candidate = secrets.token_hex(8)
            if not self._code_exists(candidate):
                return candidate
        raise RuntimeError("could not generate a unique code")

    def _code_exists(self, code: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM codes WHERE code = ?",
            (code,),
        ).fetchone()
        return row is not None

    def _require_code(self, code: str) -> None:
        if not self._code_exists(code):
            raise KeyError(code)

    def _insert_code(self, code: str, permissions: Permissions) -> None:
        self._conn.execute(
            """
            INSERT INTO codes (
                code, revoked,
                shock_enabled, shock_max_intensity, shock_max_duration_ms,
                vibrate_enabled, vibrate_max_intensity, vibrate_max_duration_ms,
                beep_enabled, beep_max_duration_ms,
                should_log
            )
            VALUES (?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (code, *_permission_values(permissions)),
        )

    def _replace_members(self, code: str, shocker_ids: set[int]) -> None:
        self._conn.execute("DELETE FROM code_shockers WHERE code = ?", (code,))
        self._conn.executemany(
            "INSERT INTO code_shockers (code, shocker_id) VALUES (?, ?)",
            [(code, shocker_id) for shocker_id in sorted(shocker_ids)],
        )

    def _load_code(self, code: str, *, active_only: bool) -> Code | None:
        sql = "SELECT * FROM codes WHERE code = ?"
        if active_only:
            sql += " AND revoked = 0"
        row = self._conn.execute(sql, (code,)).fetchone()
        if row is None:
            return None
        return self._codes_from_rows([row])[0]

    def _codes_from_rows(self, rows: list[sqlite3.Row]) -> list[Code]:
        if not rows:
            return []
        keys = [str(row["code"]) for row in rows]
        members: dict[str, list[int]] = {key: [] for key in keys}
        placeholders = ",".join("?" * len(keys))
        membership = self._conn.execute(
            f"""
            SELECT code, shocker_id FROM code_shockers
            WHERE code IN ({placeholders})
            ORDER BY shocker_id
            """,
            keys,
        ).fetchall()
        for item in membership:
            members[str(item["code"])].append(int(item["shocker_id"]))
        return [
            Code(
                code=str(row["code"]),
                shocker_ids=tuple(members[str(row["code"])]),
                permissions=_permissions_from_row(row),
                revoked=bool(row["revoked"]),
            )
            for row in rows
        ]


def _owner_from_row(row: sqlite3.Row) -> Owner:
    decided = bool(row["decided"])
    pending = row["password_plain"]
    if decided or pending is None:
        return Owner(decided=decided, pending_password=None)
    return Owner(decided=False, pending_password=str(pending))


def _shocker_from_row(row: sqlite3.Row) -> Shocker:
    return Shocker(
        id=int(row["id"]),
        name=str(row["name"]),
        paused=bool(row["paused"]),
    )


def _permissions_from_row(row: sqlite3.Row) -> Permissions:
    return Permissions(
        shock=IntensityLimit(
            enabled=bool(row["shock_enabled"]),
            max_intensity=int(row["shock_max_intensity"]),
            max_duration_ms=int(row["shock_max_duration_ms"]),
        ),
        vibrate=IntensityLimit(
            enabled=bool(row["vibrate_enabled"]),
            max_intensity=int(row["vibrate_max_intensity"]),
            max_duration_ms=int(row["vibrate_max_duration_ms"]),
        ),
        beep=DurationLimit(
            enabled=bool(row["beep_enabled"]),
            max_duration_ms=int(row["beep_max_duration_ms"]),
        ),
        should_log=bool(row["should_log"]),
    )


def _permission_values(permissions: Permissions) -> tuple[int, ...]:
    return (
        int(permissions.shock.enabled),
        permissions.shock.max_intensity,
        permissions.shock.max_duration_ms,
        int(permissions.vibrate.enabled),
        permissions.vibrate.max_intensity,
        permissions.vibrate.max_duration_ms,
        int(permissions.beep.enabled),
        permissions.beep.max_duration_ms,
        int(permissions.should_log),
    )


def _log_from_row(row: sqlite3.Row) -> LogEntry:
    return LogEntry(
        id=int(row["id"]),
        time=str(row["logged_at"]),
        code=None if row["code"] is None else str(row["code"]),
        shocker_id=None if row["shocker_id"] is None else int(row["shocker_id"]),
        sender=None if row["sender"] is None else str(row["sender"]),
        op=None if row["op"] is None else str(row["op"]),
        intensity=None if row["intensity"] is None else int(row["intensity"]),
        duration_ms=None if row["duration_ms"] is None else int(row["duration_ms"]),
        success=bool(row["success"]),
        response=str(row["response"]),
    )


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"{salt.hex()}:{digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    salt_hex, separator, digest_hex = stored.partition(":")
    if separator == "" or len(salt_hex) != 32 or len(digest_hex) != _SCRYPT_DKLEN * 2:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    digest = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return hmac.compare_digest(digest, expected)


def _check_password_choice(password: object) -> None:
    if not isinstance(password, str):
        raise ValueError("password must be a string")
    if password.strip() == "":
        raise ValueError("password must not be empty")
    if len(password) > _MAX_PASSWORD_LEN:
        raise ValueError("password is too long")


def _require_bool(value: object, label: str) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a bool")


def _require_range(value: object, label: str, low: int, high: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if not low <= value <= high:
        raise ValueError(f"{label} must be between {low} and {high}")


def _shocker_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("shocker id must be an integer")
    if value < 0:
        raise ValueError("shocker id must be >= 0")
    return value


def _id_set(values: Iterable[int]) -> set[int]:
    return {_shocker_id(value) for value in values}


def _shocker_name(name: object) -> str:
    if not isinstance(name, str):
        raise ValueError("name must be a string")
    cleaned = name.strip()
    if cleaned == "":
        raise ValueError("name must not be empty")
    if len(cleaned) > _MAX_NAME_LEN:
        raise ValueError("name is too long")
    return cleaned


def _require_code_text(code: object) -> str:
    if not isinstance(code, str):
        raise ValueError("code must be a string")
    cleaned = code.strip()
    if _CODE_RE.fullmatch(cleaned) is None:
        raise ValueError(
            "code must be 1-64 characters of letters, digits, '_' or '-'"
        )
    return cleaned


def _query_code(code: object) -> str | None:
    """Normalize an app-supplied code. JSON may send it as a string or an int."""
    if isinstance(code, bool):
        return None
    if isinstance(code, int):
        code = str(code)
    if not isinstance(code, str):
        return None
    cleaned = code.strip()
    if _CODE_RE.fullmatch(cleaned) is None:
        return None
    return cleaned


def _optional_int(value: object, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _log_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    cleaned = value.strip()
    if cleaned == "":
        return None
    if len(cleaned) > _MAX_LOG_TEXT:
        cleaned = cleaned[:_MAX_LOG_TEXT]
    return cleaned


def _log_op(op: object) -> str | None:
    if op is None:
        return None
    if isinstance(op, bool):
        raise ValueError("op must be an int or str")
    if isinstance(op, int):
        return str(op)
    if isinstance(op, str):
        cleaned = op.strip()
        return cleaned or None
    raise ValueError("op must be an int or str")


def _log_time(value: object) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError("time must be a non-empty string")
    return value.strip()
