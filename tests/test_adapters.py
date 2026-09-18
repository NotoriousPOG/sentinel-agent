"""Source adapter interfaces. Vendor classes must keep failing closed."""

import pytest
from pydantic import ValidationError

from sentinel.errors import NotImplementedCapability
from sentinel.schemas.wazuh import WazuhAlertEnvelope
from sentinel.services.sources import WazuhAdapter, iter_source_adapters


def _wazuh_payload() -> dict[str, object]:
    return {
        "timestamp": "2026-09-18T12:00:00.000+0000",
        "rule": {"level": 10, "description": "sshd: brute force", "id": "5712"},
        "agent": {"id": "001", "name": "web-1"},
        "full_log": "Sep 18 12:00:00 web-1 sshd[1]: Failed password",
        "id": "1695000000.1",
        "decoder": {"name": "sshd"},
    }


def test_only_generic_json_is_implemented() -> None:
    implemented = [adapter.name for adapter in iter_source_adapters() if adapter.implemented]
    assert implemented == ["generic_json"]


def test_wazuh_envelope_accepts_minimal_shape_and_keeps_unknown_keys() -> None:
    envelope = WazuhAlertEnvelope.model_validate(_wazuh_payload())
    assert envelope.rule.id == "5712"
    assert envelope.model_extra is not None
    assert "decoder" in envelope.model_extra


def test_wazuh_adapter_does_not_normalize() -> None:
    with pytest.raises(NotImplementedCapability, match="milestone 2"):
        WazuhAdapter().normalize(_wazuh_payload())


def test_wazuh_adapter_rejects_a_payload_without_a_rule() -> None:
    with pytest.raises(ValidationError):
        WazuhAdapter().normalize(
            {"timestamp": "2026-09-18T12:00:00.000+0000", "agent": {"id": "1", "name": "n"}}
        )


def test_vendor_interfaces_are_unimplemented() -> None:
    for adapter in iter_source_adapters():
        if adapter.name in {"generic_json", "wazuh"}:
            continue
        with pytest.raises(NotImplementedCapability, match="not scheduled"):
            adapter.normalize({"anything": True})
