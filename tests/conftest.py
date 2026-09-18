"""Shared fixtures. The settings cache is cleared so tests do not leak env vars."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from sentinel.api.app import app
from sentinel.config.settings import get_settings


@pytest.fixture(autouse=True)
def _reset_settings() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
