"""Capa de acceso a datos SQLite."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent / "instance" / "breb_pay.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                private_key_pem TEXT NOT NULL,
                public_key_pem TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 1000000.0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS breb_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_value TEXT NOT NULL UNIQUE,
                key_type TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                is_primary INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                sender_breb TEXT,
                receiver_breb TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                signature_b64 TEXT NOT NULL,
                encrypted_key TEXT NOT NULL,
                nonce TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'completed',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS favorites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                breb_value TEXT NOT NULL,
                alias TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(user_id, breb_value),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS payment_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester_id INTEGER NOT NULL,
                payer_id INTEGER NOT NULL,
                payer_breb TEXT NOT NULL,
                requester_breb TEXT,
                amount REAL NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                paid_tx_id INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                resolved_at TEXT,
                FOREIGN KEY (requester_id) REFERENCES users(id),
                FOREIGN KEY (payer_id) REFERENCES users(id),
                FOREIGN KEY (paid_tx_id) REFERENCES transactions(id)
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                link TEXT,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        _ensure_column(conn, "breb_keys", "is_primary", "is_primary INTEGER NOT NULL DEFAULT 0")
        # Primarias por defecto: primera llave activa de cada usuario sin primaria
        conn.execute(
            """
            UPDATE breb_keys
            SET is_primary = 1
            WHERE id IN (
                SELECT MIN(id) FROM breb_keys WHERE is_active = 1
                GROUP BY user_id
                HAVING SUM(is_primary) = 0
            )
            """
        )
        conn.commit()


def fetch_one(query: str, params: tuple = ()) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(query, params).fetchone()
        return dict(row) if row else None


def fetch_all(query: str, params: tuple = ()) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def execute(query: str, params: tuple = ()) -> int:
    with get_connection() as conn:
        cur = conn.execute(query, params)
        conn.commit()
        return cur.lastrowid
