"""Source adapters.

``GenericJsonAdapter`` maps a JSON object onto ``NormalizedAlert``. Unknown
keys are kept on ``raw_event`` or ``metadata`` and are not first-class fields.

``WazuhAdapter`` maps Wazuh's documented alert JSON. It does not call a manager.

``GuardDutyAdapter``, ``CrowdStrikeFalconAdapter``, ``DefenderAdapter``,
``ElasticAdapter``, and ``SplunkAdapter`` each map one documented object.
None of them call the vendor. They are not product integrations.
"""

import copy
from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import ValidationError

from sentinel.errors import AlertValidationError
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.services.crowdstrike import normalize_crowdstrike
from sentinel.services.defender import normalize_defender
from sentinel.services.elastic_alert import normalize_elastic
from sentinel.services.guardduty import normalize_guardduty
from sentinel.services.splunk import normalize_splunk
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


class CrowdStrikeFalconAdapter:
    """Map one detection summary. Not a CrowdStrike API client."""

    name = "crowdstrike_falcon"
    implemented = True

    def normalize(self, payload: object) -> NormalizedAlert:
        if not isinstance(payload, Mapping):
            raise TypeError("CrowdStrike detection must be a JSON object")
        return normalize_crowdstrike(payload)


class GuardDutyAdapter:
    """Map one documented finding object. Not an AWS GuardDuty integration.

    The payload is the GetFindings finding, not an EventBridge envelope and
    not a detector listing. Missing required finding fields fail closed.
    """

    name = "aws_guardduty"
    implemented = True

    def normalize(self, payload: object) -> NormalizedAlert:
        if not isinstance(payload, Mapping):
            raise TypeError("GuardDuty finding must be a JSON object")
        return normalize_guardduty(payload)


class DefenderAdapter:
    """Map one Defender for Endpoint alert. Not a Microsoft API client."""

    name = "microsoft_defender"
    implemented = True

    def normalize(self, payload: object) -> NormalizedAlert:
        if not isinstance(payload, Mapping):
            raise TypeError("Defender alert must be a JSON object")
        return normalize_defender(payload)


class ElasticAdapter:
    """Map one Elastic Security alert hit. Not an Elasticsearch client."""

    name = "elastic"
    implemented = True

    def normalize(self, payload: object) -> NormalizedAlert:
        if not isinstance(payload, Mapping):
            raise TypeError("Elastic alert must be a JSON object")
        return normalize_elastic(payload)


class SplunkAdapter:
    """Map one Splunk notable event. Not a Splunk search client."""

    name = "splunk"
    implemented = True

    def normalize(self, payload: object) -> NormalizedAlert:
        if not isinstance(payload, Mapping):
            raise TypeError("Splunk notable must be a JSON object")
        return normalize_splunk(payload)


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
