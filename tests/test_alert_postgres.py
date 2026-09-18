"""PostgreSQL-backed alert persistence.

Unit tests use SQLite. This test is the path that must run in CI.

Set ``SENTINEL_TEST_DATABASE_URL`` to a ``postgresql+psycopg`` URL. GitHub
Actions does that and starts Postgres. If the variable is missing in GitHub
Actions, the test fails. On a developer machine without the variable it skips
with this reason, on purpose, because there is nothing to connect to. It does
not skip when the variable is set.
"""

import os
import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from tests.support import alert_payload

from sentinel.api.app import app
from sentinel.config.settings import get_settings
from sentinel.storage.session import make_engine

_SKIP_REASON = (
    "SENTINEL_TEST_DATABASE_URL is unset, so the PostgreSQL alert test is not "
    "running on this machine. GitHub Actions sets the variable and must not skip."
)


def postgres_url() -> str:
    url = os.environ.get("SENTINEL_TEST_DATABASE_URL", "").strip()
    if url:
        if not url.startswith("postgresql"):
            pytest.fail("SENTINEL_TEST_DATABASE_URL must be a postgresql SQLAlchemy URL")
        return url
    if os.environ.get("GITHUB_ACTIONS") == "true":
        pytest.fail(
            "SENTINEL_TEST_DATABASE_URL is unset in GitHub Actions; "
            "refusing to skip the PostgreSQL alert test"
        )
    pytest.skip(_SKIP_REASON)


@pytest.fixture
def postgres_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    url = postgres_url()
    monkeypatch.setenv("SENTINEL_DATABASE_URL", url)
    get_settings.cache_clear()
    command.upgrade(Config("alembic.ini"), "head")
    engine = make_engine(url)
    try:
        assert engine.dialect.name == "postgresql"
    finally:
        engine.dispose()
    with TestClient(app) as client:
        yield client


def test_postgres_persists_and_replays_an_alert(postgres_client: TestClient) -> None:
    alert_id = f"pg-{uuid.uuid4().hex}"
    url = get_settings().database_url
    engine = make_engine(url)
    try:
        created = postgres_client.post(
            "/alerts",
            json={
                "source": "generic_json",
                "payload": alert_payload(alert_id=alert_id, title="postgres copy"),
            },
        )
        assert created.status_code == 201
        assert created.json()["idempotent_replay"] is False

        replay = postgres_client.post(
            "/alerts",
            json={
                "source": "generic_json",
                "payload": alert_payload(alert_id=alert_id, title="should not replace"),
            },
        )
        assert replay.status_code == 200
        assert replay.json()["alert"]["title"] == "postgres copy"

        loaded = postgres_client.get(f"/alerts/{alert_id}")
        assert loaded.status_code == 200
        assert loaded.json()["alert"]["alert_id"] == alert_id
        assert loaded.json()["alert"]["title"] == "postgres copy"

        with engine.connect() as connection:
            row = connection.execute(
                text("SELECT source FROM alerts WHERE alert_id = :alert_id"),
                {"alert_id": alert_id},
            ).one()
        assert row.source == "unit-test"
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM alerts WHERE alert_id = :alert_id"),
                {"alert_id": alert_id},
            )
        engine.dispose()
