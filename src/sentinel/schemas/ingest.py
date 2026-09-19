"""Alert ingest request and the stored-alert response.

``source`` selects an adapter. It is not copied onto ``NormalizedAlert.source``.
The payload stays untrusted until that adapter maps it.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.timestamps import require_aware


class AlertIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["generic_json", "wazuh", "aws_guardduty"] = "generic_json"
    payload: dict[str, Any]


class StoredAlert(BaseModel):
    """An alert as reloaded from storage. ``alert`` is the normalized document."""

    model_config = ConfigDict(extra="forbid")

    received_at: datetime
    alert: NormalizedAlert

    @field_validator("received_at")
    @classmethod
    def _received_at(cls, value: datetime) -> datetime:
        return require_aware(value)


class AlertIngestResponse(StoredAlert):
    """POST result. ``idempotent_replay`` is true when ``alert_id`` was already stored."""

    idempotent_replay: bool
