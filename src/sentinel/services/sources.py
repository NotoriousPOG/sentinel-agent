"""Source adapters.

``GenericJsonAdapter`` maps a JSON object onto ``NormalizedAlert``. Unknown
keys are kept on ``raw_event`` or ``metadata`` and are not first-class fields.

``WazuhAdapter`` maps Wazuh's documented alert JSON. It does not call a manager.

``GuardDutyAdapter`` maps one documented GuardDuty finding object. It does
not call AWS. That mapper is not a full GuardDuty integration. The other
vendor products below are importable interfaces and do not parse payloads.
"""

import copy
from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import ValidationError

from sentinel.errors import AlertValidationError, NotImplementedCapability
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.services.guardduty import normalize_guardduty
from sentinel.services.validation import issues_from_validation
from sentinel.services.wazuh import normalize_wazuh

_KNOWN_ALERT_FIELDS = frozenset(NormalizedAlert.model_fields)


class SourceAdapter(Protocol):
    name: str
    implemented: bool

    def normalize(self, payload: object) -> NormalizedAlert:
        """Return a normalized alert or raise. Must not perform I/O."""
        ...


class GenericJsonAdapter:
    """Map a JSON object. Extra keys are preserved, not promoted."""

    name = "generic_json"
    implemented = True

    def normalize(self, payload: object) -> NormalizedAlert:
        if not isinstance(payload, dict):
            raise TypeError("generic JSON alert must be a JSON object")
        known = {key: value for key, value in payload.items() if key in _KNOWN_ALERT_FIELDS}
        unknown = {key: value for key, value in payload.items() if key not in _KNOWN_ALERT_FIELDS}
        if unknown and "raw_event" not in payload:
            known["raw_event"] = copy.deepcopy(payload)
        if unknown:
            metadata = known.get("metadata")
            if metadata is None:
                metadata = {}
            if isinstance(metadata, dict):
                merged: dict[str, Any] = copy.deepcopy(metadata)
                unmapped_raw = merged.get("unmapped_fields")
                unmapped = dict(unmapped_raw) if isinstance(unmapped_raw, dict) else {}
                for key, value in unknown.items():
                    unmapped.setdefault(key, copy.deepcopy(value))
                merged["unmapped_fields"] = unmapped
                known["metadata"] = merged
        try:
            return NormalizedAlert.model_validate(known)
        except ValidationError as exc:
            raise AlertValidationError(issues_from_validation(exc)) from exc


class WazuhAdapter:
    """Map a documented Wazuh alert. No manager connection."""

    name = "wazuh"
    implemented = True

    def normalize(self, payload: object) -> NormalizedAlert:
        if not isinstance(payload, Mapping):
            raise TypeError("Wazuh alert must be a JSON object")
        return normalize_wazuh(payload)


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


class GuardDutyAdapter:
    """Map one documented finding object. Not an AWS GuardDuty integration.

    The payload is the GetFindings finding, not an EventBridge envelope and
    not a detector listing. Missing required finding fields fail closed.
    CrowdStrike, Defender, Elastic, and Splunk are still unimplemented.
    """

    name = "aws_guardduty"
    implemented = True

    def normalize(self, payload: object) -> NormalizedAlert:
        if not isinstance(payload, Mapping):
            raise TypeError("GuardDuty finding must be a JSON object")
        return normalize_guardduty(payload)


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
    """Every adapter this package is willing to name."""
    return (
        GenericJsonAdapter(),
        WazuhAdapter(),
        CrowdStrikeFalconAdapter(),
        GuardDutyAdapter(),
        DefenderAdapter(),
        ElasticAdapter(),
        SplunkAdapter(),
    )
