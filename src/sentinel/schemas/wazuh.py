"""Minimal Wazuh alert envelope.

This is the inbound shape, not a ``NormalizedAlert``. Mapping fields across is
milestone 2. ``extra="allow"`` keeps vendor keys on the envelope so a later
mapper can read them; those keys are untrusted data.
"""

from pydantic import BaseModel, ConfigDict, Field


class WazuhRule(BaseModel):
    model_config = ConfigDict(extra="ignore")

    level: int = Field(ge=0, le=15)
    description: str = Field(min_length=1)
    id: str = Field(min_length=1)


class WazuhAgent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)


class WazuhAlertEnvelope(BaseModel):
    """Smallest Wazuh alert this codebase is willing to name.

    Rule levels follow Wazuh's 0-15 scale. ``full_log`` and any unknown keys
    are not interpreted here.
    """

    model_config = ConfigDict(extra="allow")

    timestamp: str = Field(min_length=1)
    rule: WazuhRule
    agent: WazuhAgent
    id: str | None = None
    full_log: str | None = None
