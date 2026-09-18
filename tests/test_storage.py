"""SQLite stands in for PostgreSQL in unit tests. It is not a supported deployment."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from sentinel.config.settings import get_settings
from sentinel.storage.session import make_engine


def test_sqlite_engine_roundtrip(tmp_path: Path) -> None:
    url = f"sqlite+pysqlite:///{tmp_path}/sentinel.db"
    engine = make_engine(url)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar_one() == 1
    finally:
        engine.dispose()


def test_alembic_upgrade_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url = f"sqlite+pysqlite:///{tmp_path}/migrated.db"
    monkeypatch.setenv("SENTINEL_DATABASE_URL", url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.upgrade(config, "head")
    engine = make_engine(url)
    try:
        with engine.connect() as connection:
            version = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            names = set(
                connection.execute(
                    text("SELECT name FROM sqlite_master WHERE type = 'table'")
                ).scalars()
            )
            assert version == "0003_investigations"
            assert "alerts" in names
            assert "investigations" in names
    finally:
        engine.dispose()
