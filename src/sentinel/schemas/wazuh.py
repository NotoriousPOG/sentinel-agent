"""Wazuh alert envelope.

Field names come from Wazuh's documented alert JSON, not from a guessed
vendor schema. The logtest ``output`` object is documented at
https://documentation.wazuh.com/current/user-manual/ruleset/testing.html
and an older JSON object (numeric ``rule.id``, offset-less timestamp) at
https://documentation.wazuh.com/current/user-manual/ruleset/decoders/dynamic-fields.html

``data`` only types the static decoder fields this mapper reads. The full
static list (srcuser, dstuser, user, srcip, dstip, srcport, dstport, protocol,
system_name, id, url, action, status, data, extra_data) is documented at
https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html
Other keys stay on the model as extras and on ``raw_event`` after mapping.
They are untrusted data.
"""

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WazuhRule(BaseModel):
    """Rule fragment. ``id`` is a string in the logtest example and an int in the 2017 example."""

    model_config = ConfigDict(extra="ignore")

    level: int = Field(ge=0, le=15)
    description: str = Field(min_length=1)
    id: str = Field(min_length=1)

    @field_validator("id", mode="before")
    @classmethod
    def _coerce_id(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("rule id must be a string or an integer")
        if isinstance(value, int):
            return str(value)
        return value


class WazuhAgent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)


class WazuhManager(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str | None = None


class WazuhPredecoder(BaseModel):
    """Syslog pre-decoder fields from the documented logtest output."""

    model_config = ConfigDict(extra="allow")

    program_name: str | None = None
    timestamp: str | None = None
    hostname: str | None = None


class WazuhDecoder(BaseModel):
    model_config = ConfigDict(extra="allow")

    parent: str | None = None
    name: str | None = None


class WazuhData(BaseModel):
    """Static decoder fields the mapper is willing to read. Dynamic keys stay extra."""

    model_config = ConfigDict(extra="allow")

    srcip: str | None = None
    dstip: str | None = None
    srcuser: str | None = None
    dstuser: str | None = None
    user: str | None = None
    url: str | None = None


class WazuhAlertEnvelope(BaseModel):
    """Documented Wazuh alert object. Unknown keys are kept and not interpreted."""

    model_config = ConfigDict(extra="allow")

    timestamp: str = Field(min_length=1)
    rule: WazuhRule
    agent: WazuhAgent
    id: str | None = None
    full_log: str | None = None
    manager: WazuhManager | None = None
    predecoder: WazuhPredecoder | None = None
    decoder: WazuhDecoder | None = None
    data: WazuhData | None = None
    location: str | None = None
