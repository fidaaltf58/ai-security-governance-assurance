"""SQLite data-access layer.

A thin wrapper over the stdlib ``sqlite3`` module: no ORM, so the SQL is
explicit and reviewable. Connections return ``sqlite3.Row`` for dict-like
access and have foreign keys enabled.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .config import get_settings

_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def connect(db_path: str | None = None) -> sqlite3.Connection:
    """Open a connection with row factory and foreign-key enforcement on."""
    path = db_path or get_settings().db_path
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create all tables from ``schema.sql`` (idempotent)."""
    conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.commit()


def query(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    """Run a SELECT and return all rows."""
    return conn.execute(sql, params).fetchall()


def query_one(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> sqlite3.Row | None:
    """Run a SELECT and return the first row or ``None``."""
    return conn.execute(sql, params).fetchone()


def execute(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> int:
    """Run an INSERT/UPDATE/DELETE, commit, and return lastrowid."""
    cur = conn.execute(sql, params)
    conn.commit()
    return cur.lastrowid
