"""Shared fixtures. The settings cache is cleared so tests do not leak env vars."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from sentinel.api.app import app
from sentinel.config.settings import get_settings


@pytest.fixture(autouse=True)
def _reset_settings() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_process_metrics() -> Iterator[None]:
    """Investigation counters are process-global. Each test starts from zero."""
    from sentinel.observability.metrics import reset_metrics

    reset_metrics()
    yield
    reset_metrics()


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """HTTP client bound to a migrated SQLite file. This is not the PostgreSQL test."""
    url = f"sqlite+pysqlite:///{tmp_path}/sentinel.db"
    monkeypatch.setenv("SENTINEL_DATABASE_URL", url)
    get_settings.cache_clear()
    command.upgrade(Config("alembic.ini"), "head")
    with TestClient(app) as test_client:
        yield test_client
