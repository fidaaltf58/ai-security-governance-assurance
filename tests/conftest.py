"""Shared test fixtures.

Each test gets an isolated, seeded SQLite database in a temp directory, and a
FastAPI TestClient whose connection dependency is overridden to use it — so
tests never touch the real ``data/governance.db``.
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import db, main, seed


@pytest.fixture
def conn(tmp_path) -> sqlite3.Connection:
    path = tmp_path / "test.db"
    c = db.connect(str(path))
    db.init_db(c)
    seed.seed_demo(c)
    yield c
    c.close()


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "api.db"

    def _override():
        c = db.connect(str(path))
        db.init_db(c)
        seed.seed_demo(c)
        try:
            yield c
        finally:
            c.close()

    main.app.dependency_overrides[main.get_conn] = _override
    with TestClient(main.app) as test_client:
        yield test_client
    main.app.dependency_overrides.clear()
