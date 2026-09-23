"""demo_mode fixture catalog. These tests do not open a socket."""

from tests.support import NOW
from tests.test_reporting import _ip

from sentinel.agents.reporting import classification_from_evidence
from sentinel.schemas.reports import Classification
from sentinel.services.providers.fixtures import (
    HASH_FIXTURES,
    IP_FIXTURES,
    hash_fixture,
    ip_fixture,
)
from sentinel.tools.policy import reliability_for_provider


def test_unknown_documentation_address_is_not_in_the_fixture_table() -> None:
    assert ip_fixture("203.0.113.99") is None
    assert "203.0.113.77" not in IP_FIXTURES
    assert "203.0.113.40" not in IP_FIXTURES
    assert "203.0.113.50" not in IP_FIXTURES


def test_eval_and_demo_indicators_are_listed() -> None:
    assert ip_fixture("203.0.113.44") is not None
    assert ip_fixture("203.0.113.10") is not None
    assert ip_fixture("198.51.100.23") is not None
    assert ip_fixture("192.0.2.50") is not None
    assert hash_fixture("ab" * 32) is not None
    assert "0123456789abcdef" * 4 in HASH_FIXTURES


def test_fixture_malicious_ip_is_suspicious_because_mocks_are_low_reliability() -> None:
    row = _ip("ev-1", "mock:abuseipdb", malicious=True, ip="203.0.113.44")
    assert row.reliability is reliability_for_provider("mock:abuseipdb")
    assert classification_from_evidence([row]) is Classification.SUSPICIOUS


def test_fixture_clean_ip_can_be_benign_when_the_boolean_is_stored() -> None:
    row = _ip("ev-1", "mock:abuseipdb", malicious=False, ip="203.0.113.10")
    assert classification_from_evidence([row]) is Classification.BENIGN


def test_unknown_mock_ip_stays_inconclusive() -> None:
    row = _ip("ev-1", "mock:abuseipdb", malicious=None, ip="203.0.113.99")
    assert row.timestamp == NOW
    assert classification_from_evidence([row]) is Classification.INCONCLUSIVE
