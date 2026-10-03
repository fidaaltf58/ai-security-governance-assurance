"""Application configuration, read from environment variables.

Defaults are safe for local/dev use. Nothing here is a secret; ``.env.example``
documents the full set. Settings are cached so the whole app shares one object.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    db_path: str
    app_name: str
    environment: str


@lru_cache
def get_settings() -> Settings:
    return Settings(
        db_path=os.environ.get("AIGOV_DB_PATH", "data/governance.db"),
        app_name=os.environ.get("AIGOV_APP_NAME", "AI Security Governance & Assurance"),
        environment=os.environ.get("AIGOV_ENV", "development"),
    )
