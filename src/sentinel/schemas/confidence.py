"""Explainable confidence. The score is arithmetic over a fixed weight table.

``weighted_evidence_v1`` is not a probability. A model may not supply a
different total: validation recomputes it. ``score_confidence`` sets the
booleans from evidence. This schema only checks the arithmetic and citations.
"""

from collections.abc import Sequence
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ConfidenceFactorName(StrEnum):
    EVIDENCE_COVERAGE = "evidence_coverage"
    SOURCE_RELIABILITY = "source_reliability"
    CORROBORATION = "corroboration"
    CONTRADICTION_PENALTY = "contradiction_penalty"
    DATA_COMPLETENESS = "data_completeness"


# Policy weights. Changing them requires a new method literal.
FACTOR_WEIGHTS: dict[ConfidenceFactorName, int] = {
    ConfidenceFactorName.EVIDENCE_COVERAGE: 30,
    ConfidenceFactorName.SOURCE_RELIABILITY: 25,
    ConfidenceFactorName.CORROBORATION: 20,
    ConfidenceFactorName.CONTRADICTION_PENALTY: 15,
    ConfidenceFactorName.DATA_COMPLETENESS: 10,
}


class ConfidenceFactor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: ConfidenceFactorName
    weight: int = Field(ge=0, le=100)
    satisfied: bool
    evidence_ids: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _policy(self) -> Self:
        expected = FACTOR_WEIGHTS[self.name]
        if self.weight != expected:
            raise ValueError(f"weight for {self.name.value} must be {expected}, not {self.weight}")
        missing_citation = not self.evidence_ids
        if self.name is ConfidenceFactorName.DATA_COMPLETENESS:
            return self
        contradiction_unproven = (
            self.name is ConfidenceFactorName.CONTRADICTION_PENALTY
            and not self.satisfied
            and missing_citation
        )
        if contradiction_unproven:
            raise ValueError("an unsatisfied contradiction penalty must cite evidence")
        positive_without_citation = (
            self.name is not ConfidenceFactorName.CONTRADICTION_PENALTY
            and self.satisfied
            and missing_citation
        )
        if positive_without_citation:
            raise ValueError(f"satisfied factor {self.name.value} must cite evidence")
        return self


def compute_confidence_score(factors: Sequence[ConfidenceFactor]) -> int:
    """Sum the weights of satisfied factors. Unsatisfied factors add zero."""
    return sum(factor.weight for factor in factors if factor.satisfied)


class ConfidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["weighted_evidence_v1"]
    score: int = Field(ge=0, le=100)
    factors: list[ConfidenceFactor] = Field(min_length=5, max_length=5)

    @model_validator(mode="after")
    def _score_matches(self) -> Self:
        names = [factor.name for factor in self.factors]
        if set(names) != set(FACTOR_WEIGHTS) or len(names) != len(set(names)):
            raise ValueError("confidence factors must be exactly the weighted_evidence_v1 set")
        expected = compute_confidence_score(self.factors)
        if self.score != expected:
            raise ValueError(f"score {self.score} does not match factor total {expected}")
        return self
