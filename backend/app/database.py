"""SQLite persistence and simple migrations for NetSecure Cloud."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_db_time(value: datetime | None = None) -> str:
    return (value or utcnow()).isoformat()


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);

                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
                    check_type TEXT NOT NULL DEFAULT 'tcp' CHECK(check_type IN ('tcp')),
                    created_by INTEGER NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    UNIQUE(host, port, check_type)
                );

                CREATE TABLE IF NOT EXISTS check_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    status TEXT NOT NULL CHECK(status IN ('online', 'offline')),
                    response_ms REAL,
                    error_message TEXT,
                    checked_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_results_target_checked
                    ON check_results(target_id, checked_at DESC);

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    ip_address TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
                """
            )

    def has_users(self) -> bool:
        with self.connect() as connection:
            return connection.execute("SELECT EXISTS(SELECT 1 FROM users)").fetchone()[0] == 1

    def create_user(self, username: str, password_hash: str) -> dict:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, as_db_time()),
            )
            return {"id": cursor.lastrowid, "username": username}

    def find_user_by_username(self, username: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            return dict(row) if row else None

    def create_session(self, user_id: int, token: str, session_hours: int) -> None:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires_at = utcnow() + timedelta(hours=session_hours)
        with self.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (as_db_time(),))
            connection.execute(
                "INSERT INTO sessions(user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (user_id, token_hash, as_db_time(expires_at), as_db_time()),
            )

    def delete_session(self, token: str | None) -> None:
        if not token:
            return
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def find_session_user(self, token: str | None) -> dict | None:
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT users.id, users.username
                FROM sessions JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash, as_db_time()),
            ).fetchone()
            return dict(row) if row else None

    def add_target(self, *, name: str, host: str, port: int, check_type: str, user_id: int) -> dict:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO targets(name, host, port, check_type, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, host, port, check_type, user_id, as_db_time()),
            )
            row = connection.execute("SELECT * FROM targets WHERE id = ?", (cursor.lastrowid,)).fetchone()
            return dict(row)

    def get_target(self, target_id: int) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
            return dict(row) if row else None

    def delete_target(self, target_id: int) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            return cursor.rowcount == 1

    def list_targets_with_latest_result(self) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT targets.*,
                    result.status AS latest_status,
                    result.response_ms AS latest_response_ms,
                    result.checked_at AS latest_checked_at,
                    result.error_message AS latest_error
                FROM targets
                LEFT JOIN check_results AS result ON result.id = (
                    SELECT id FROM check_results
                    WHERE target_id = targets.id
                    ORDER BY checked_at DESC, id DESC LIMIT 1
                )
                ORDER BY targets.name COLLATE NOCASE, targets.id
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def add_check_result(
        self,
        *,
        target_id: int,
        status: str,
        response_ms: float | None,
        error_message: str | None,
    ) -> dict:
        checked_at = as_db_time()
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO check_results(target_id, status, response_ms, error_message, checked_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (target_id, status, response_ms, error_message, checked_at),
            )
            row = connection.execute("SELECT * FROM check_results WHERE id = ?", (cursor.lastrowid,)).fetchone()
            return dict(row)

    def list_history(self, target_id: int, limit: int) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, target_id, status, response_ms, error_message, checked_at
                FROM check_results WHERE target_id = ?
                ORDER BY checked_at DESC, id DESC LIMIT ?
                """,
                (target_id, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def audit(self, *, action: str, detail: str, user_id: int | None, ip_address: str | None) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_logs(user_id, action, detail, ip_address, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, action, detail[:500], ip_address, as_db_time()),
            )
