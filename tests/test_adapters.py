"""Source adapter interfaces. Vendor classes must keep failing closed."""

from sentinel.schemas.wazuh import WazuhAlertEnvelope
from sentinel.services.sources import iter_source_adapters


def _wazuh_payload() -> dict[str, object]:
    return {
        "timestamp": "2026-09-18T12:00:00.000+0000",
        "rule": {"level": 10, "description": "sshd: brute force", "id": "5712"},
        "agent": {"id": "001", "name": "web-1"},
        "full_log": "Sep 18 12:00:00 web-1 sshd[1]: Failed password",
        "id": "1695000000.1",
        "decoder": {"name": "sshd"},
        "unmapped_vendor_key": {"kept": True},
    }


def test_generic_json_and_wazuh_are_implemented() -> None:
    implemented = [adapter.name for adapter in iter_source_adapters() if adapter.implemented]
    assert implemented == [
        "generic_json",
        "wazuh",
        "crowdstrike_falcon",
        "aws_guardduty",
        "microsoft_defender",
        "elastic",
        "splunk",
    ]


def test_wazuh_envelope_accepts_minimal_shape_and_keeps_unknown_keys() -> None:
    envelope = WazuhAlertEnvelope.model_validate(_wazuh_payload())
    assert envelope.rule.id == "5712"
    assert envelope.decoder is not None
    assert envelope.decoder.name == "sshd"
    assert envelope.model_extra is not None
    assert envelope.model_extra["unmapped_vendor_key"] == {"kept": True}


def test_vendor_payloads_fail_closed_without_required_fields() -> None:
    from sentinel.errors import AlertValidationError

    for adapter in iter_source_adapters():
        if adapter.name in {"generic_json", "wazuh"}:
            continue
        try:
            adapter.normalize({})
        except AlertValidationError:
            continue
        except TypeError:
            continue
        raise AssertionError(f"{adapter.name} accepted an empty payload")
