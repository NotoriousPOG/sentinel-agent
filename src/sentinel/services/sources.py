"""Source adapters.

``GenericJsonAdapter`` checks the normalized shape and returns it. That is
schema validation, not ingestion: nothing is stored.

``WazuhAdapter`` checks a minimal envelope, then refuses to map it. Vendor
products below are importable interfaces and do not parse payloads.
"""

from collections.abc import Mapping
from typing import Protocol

from sentinel.errors import NotImplementedCapability
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.wazuh import WazuhAlertEnvelope


class SourceAdapter(Protocol):
    name: str
    implemented: bool

    def normalize(self, payload: object) -> NormalizedAlert:
        """Return a normalized alert or raise. Must not perform I/O."""
        ...


class GenericJsonAdapter:
    """Identity adapter for documents that are already ``NormalizedAlert`` objects."""

    name = "generic_json"
    implemented = True

    def normalize(self, payload: object) -> NormalizedAlert:
        if not isinstance(payload, dict):
            raise TypeError("generic JSON alert must be a JSON object")
        return NormalizedAlert.model_validate(payload)


class WazuhAdapter:
    """Typed Wazuh boundary. Normalization is milestone 2."""

    name = "wazuh"
    implemented = False

    def normalize(self, payload: object) -> NormalizedAlert:
        if not isinstance(payload, Mapping):
            raise TypeError("Wazuh alert must be a JSON object")
        WazuhAlertEnvelope.model_validate(dict(payload))
        raise NotImplementedCapability("Wazuh alert normalization", milestone=2)


class _UnimplementedVendorAdapter:
    name: str
    product: str
    implemented = False

    def normalize(self, payload: object) -> NormalizedAlert:
        _ = payload
        raise NotImplementedCapability(
            f"{self.product} source adapter",
            milestone=None,
        )


class CrowdStrikeFalconAdapter(_UnimplementedVendorAdapter):
    """UNIMPLEMENTED interface. Not a CrowdStrike integration."""

    name = "crowdstrike_falcon"
    product = "CrowdStrike Falcon"


class GuardDutyAdapter(_UnimplementedVendorAdapter):
    """UNIMPLEMENTED interface. Not an AWS GuardDuty integration."""

    name = "aws_guardduty"
    product = "AWS GuardDuty"


class DefenderAdapter(_UnimplementedVendorAdapter):
    """UNIMPLEMENTED interface. Not a Microsoft Defender integration."""

    name = "microsoft_defender"
    product = "Microsoft Defender"


class ElasticAdapter(_UnimplementedVendorAdapter):
    """UNIMPLEMENTED interface. Not an Elastic integration."""

    name = "elastic"
    product = "Elastic"


class SplunkAdapter(_UnimplementedVendorAdapter):
    """UNIMPLEMENTED interface. Not a Splunk integration."""

    name = "splunk"
    product = "Splunk"


def iter_source_adapters() -> tuple[SourceAdapter, ...]:
    """Every adapter this package is willing to name. Only generic JSON runs."""
    return (
        GenericJsonAdapter(),
        WazuhAdapter(),
        CrowdStrikeFalconAdapter(),
        GuardDutyAdapter(),
        DefenderAdapter(),
        ElasticAdapter(),
        SplunkAdapter(),
    )
