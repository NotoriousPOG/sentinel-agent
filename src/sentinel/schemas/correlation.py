"""Links between evidence rows. Rows are not merged."""

from pydantic import BaseModel, ConfigDict, Field

from sentinel.schemas.evidence import Evidence
from sentinel.schemas.reports import IndicatorType

type JsonScalar = str | int | float | bool | None


class LinkedIndicator(BaseModel):
    """One indicator and the evidence rows that mention it. Not a combined result."""

    model_config = ConfigDict(extra="forbid")

    type: IndicatorType
    value: str = Field(min_length=1, max_length=2048)
    evidence_ids: list[str] = Field(min_length=1)


class FieldObservation(BaseModel):
    """One provider's stored value. Not an average."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=128)
    value: JsonScalar


class Contradiction(BaseModel):
    """Two or more stored values for one field. Both rows stay on the investigation."""

    model_config = ConfigDict(extra="forbid")

    type: IndicatorType
    value: str = Field(min_length=1, max_length=2048)
    field: str = Field(min_length=1, max_length=64)
    observations: list[FieldObservation] = Field(min_length=2)


class CorrelationResult(BaseModel):
    """Correlated view of already collected rows."""

    model_config = ConfigDict(extra="forbid")

    evidence: list[Evidence]
    indicators: list[LinkedIndicator]
    contradictions: list[Contradiction]
