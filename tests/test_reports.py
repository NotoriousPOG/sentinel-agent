"""Reports, confidence arithmetic, and analyst review."""

import pytest
from pydantic import ValidationError
from tests.support import NOW

from sentinel.schemas.alerts import AlertSeverity
from sentinel.schemas.confidence import (
    FACTOR_WEIGHTS,
    ConfidenceAssessment,
    ConfidenceFactor,
    ConfidenceFactorName,
)
from sentinel.schemas.evidence import Evidence, EvidenceReliability
from sentinel.schemas.reports import (
    Classification,
    IncidentReport,
    Indicator,
    IndicatorType,
    RecommendedAction,
    TimelineEvent,
)
from sentinel.schemas.review import AnalystReview


def _evidence() -> Evidence:
    return Evidence(
        evidence_id="ev-1",
        source="unit-test",
        tool="lookup_ip",
        query={"ip": "203.0.113.10"},
        result={"reported_malicious": None},
        timestamp=NOW,
        reliability=EvidenceReliability.HIGH,
    )


def _assessment(
    overrides: dict[ConfidenceFactorName, bool] | None = None,
    *,
    score: int | None = None,
) -> ConfidenceAssessment:
    flags = {name: True for name in ConfidenceFactorName}
    if overrides:
        flags.update(overrides)
    factors: list[ConfidenceFactor] = []
    for name, weight in FACTOR_WEIGHTS.items():
        if name is ConfidenceFactorName.CONTRADICTION_PENALTY:
            cite = not flags[name]
        elif name is ConfidenceFactorName.DATA_COMPLETENESS:
            cite = False
        else:
            cite = flags[name]
        factors.append(
            ConfidenceFactor(
                name=name,
                weight=weight,
                satisfied=flags[name],
                evidence_ids=["ev-1"] if cite else [],
                rationale=name.value,
            )
        )
    total = sum(weight for name, weight in FACTOR_WEIGHTS.items() if flags[name])
    return ConfidenceAssessment(
        method="weighted_evidence_v1",
        score=total if score is None else score,
        factors=factors,
    )


def _report(**overrides: object) -> IncidentReport:
    payload: dict[str, object] = {
        "investigation_id": "inv-1",
        "alert_id": "alert-1",
        "classification": Classification.SUSPICIOUS,
        "severity": AlertSeverity.HIGH,
        "confidence": _assessment(),
        "executive_summary": "One source flagged the address. Not independently confirmed.",
        "affected_assets": ["web-1"],
        "indicators": [
            Indicator(type=IndicatorType.IP, value="203.0.113.10", evidence_ids=["ev-1"])
        ],
        "evidence": [_evidence()],
        "mitre_attack": [],
        "timeline": [
            TimelineEvent(
                timestamp=NOW,
                description="Alert observed",
                evidence_ids=["ev-1"],
            )
        ],
        "recommended_actions": [],
        "limitations": ["Single source; no packet capture."],
    }
    payload.update(overrides)
    return IncidentReport.model_validate(payload)


def test_report_accepts_grounded_document() -> None:
    report = _report()
    assert report.confidence.score == 100
    assert report.confidence.method == "weighted_evidence_v1"


def test_invented_confidence_score_is_rejected() -> None:
    with pytest.raises(ValidationError, match="does not match factor total"):
        _assessment(score=95)


def test_custom_weight_is_rejected() -> None:
    with pytest.raises(ValidationError, match="weight"):
        ConfidenceFactor(
            name=ConfidenceFactorName.CORROBORATION,
            weight=99,
            satisfied=False,
            rationale="model tried to choose the weight",
        )


def test_dangling_citation_is_rejected() -> None:
    with pytest.raises(ValidationError, match="citations do not match"):
        _report(
            indicators=[
                Indicator(type=IndicatorType.IP, value="203.0.113.10", evidence_ids=["missing"])
            ]
        )


def test_classification_without_evidence_is_rejected() -> None:
    with pytest.raises(ValidationError, match="require evidence"):
        _report(classification=Classification.MALICIOUS, evidence=[])


def test_limitations_are_required() -> None:
    with pytest.raises(ValidationError):
        _report(limitations=[])


def test_recommendation_cannot_waive_approval() -> None:
    with pytest.raises(ValidationError):
        RecommendedAction.model_validate(
            {
                "action_id": "isolate-host",
                "description": "Isolate web-1",
                "destructive": True,
                "requires_human_approval": False,
            }
        )
    action = RecommendedAction(
        action_id="note",
        description="Record the finding",
        destructive=False,
    )
    assert action.requires_human_approval is True


def test_review_rejects_execution_flag() -> None:
    with pytest.raises(ValidationError):
        AnalystReview.model_validate(
            {
                "investigation_id": "inv-1",
                "conclusion": "approve",
                "notes": "conclusion only",
                "execute": True,
            }
        )


def test_review_accepts_split_decisions() -> None:
    review = AnalystReview(
        investigation_id="inv-1",
        conclusion="approve",
        notes="The evidence supports the classification.",
        remediation="reject",
    )
    assert review.remediation is not None
    assert review.remediation.value == "reject"
