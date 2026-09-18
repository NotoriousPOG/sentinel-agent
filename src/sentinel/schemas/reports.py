"""Strict incident report. Citations must resolve inside the same document."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinel.schemas.alerts import AlertSeverity
from sentinel.schemas.confidence import ConfidenceAssessment
from sentinel.schemas.evidence import Evidence
from sentinel.schemas.patterns import normalize_technique_id
from sentinel.schemas.timestamps import require_aware


class Classification(StrEnum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CVE = "cve"
    HOSTNAME = "hostname"
    USER = "user"
    PROCESS = "process"


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: IndicatorType
    value: str = Field(min_length=1, max_length=2048)
    evidence_ids: list[str] = Field(min_length=1)


class MitreTechniqueRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str = Field(min_length=1, max_length=256)
    tactic: str = Field(min_length=1, max_length=128)
    evidence_ids: list[str] = Field(min_length=1)

    @field_validator("technique_id")
    @classmethod
    def _technique_id(cls, value: str) -> str:
        return normalize_technique_id(value)


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    description: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[str] = Field(min_length=1)

    @field_validator("timestamp")
    @classmethod
    def _timestamp(cls, value: datetime) -> datetime:
        return require_aware(value)


class RecommendedAction(BaseModel):
    """A recommendation. Nothing in this repository executes it.

    ``requires_human_approval`` cannot be false. Non-destructive actions are
    included: "read only" is how unattended changes get described.
    """

    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=1000)
    destructive: bool
    requires_human_approval: Literal[True] = True


ShortText = Annotated[str, Field(min_length=1, max_length=500)]


class IncidentReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: str = Field(min_length=1, max_length=128)
    alert_id: str = Field(min_length=1, max_length=256)
    classification: Classification
    severity: AlertSeverity
    confidence: ConfidenceAssessment
    executive_summary: str = Field(min_length=1, max_length=4000)
    affected_assets: list[ShortText] = Field(max_length=100)
    indicators: list[Indicator] = Field(max_length=100)
    evidence: list[Evidence] = Field(max_length=200)
    mitre_attack: list[MitreTechniqueRef] = Field(max_length=50)
    timeline: list[TimelineEvent] = Field(max_length=200)
    recommended_actions: list[RecommendedAction] = Field(max_length=50)
    analyst_notes: str = Field(default="", max_length=4000)
    limitations: list[ShortText] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def _grounded(self) -> Self:
        if self.classification is not Classification.INCONCLUSIVE and not self.evidence:
            raise ValueError(f"{self.classification.value} reports require evidence")
        ids = [item.evidence_id for item in self.evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence_id values must be unique")
        known = set(ids)
        cited: list[str] = []
        for indicator in self.indicators:
            cited.extend(indicator.evidence_ids)
        for technique in self.mitre_attack:
            cited.extend(technique.evidence_ids)
        for event in self.timeline:
            cited.extend(event.evidence_ids)
        for factor in self.confidence.factors:
            cited.extend(factor.evidence_ids)
        missing = sorted({item for item in cited if item not in known})
        if missing:
            raise ValueError(f"citations do not match evidence: {missing}")
        return self
