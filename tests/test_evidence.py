"""Correlation and verification. Fakes only: no network, no model, no API keys."""

from datetime import datetime

import pytest
from tests.support import NOW, alert_payload

from sentinel.agents.transitions import new_investigation, transition
from sentinel.config.settings import Settings
from sentinel.evidence.correlate import correlate
from sentinel.evidence.verify import apply_verification, verify_report
from sentinel.schemas.alerts import AlertSeverity, NormalizedAlert
from sentinel.schemas.confidence import (
    FACTOR_WEIGHTS,
    ConfidenceAssessment,
    ConfidenceFactor,
    ConfidenceFactorName,
)
from sentinel.schemas.correlation import Contradiction
from sentinel.schemas.evidence import Evidence, EvidenceReliability
from sentinel.schemas.investigation import InvestigationState, InvestigationStatus
from sentinel.schemas.reports import (
    Classification,
    IncidentReport,
    Indicator,
    IndicatorType,
    TimelineEvent,
)
from sentinel.schemas.verification import (
    FailedLookup,
    Statement,
    VerificationIssue,
    VerificationResult,
)
from sentinel.tools.policy import reliability_for_provider

HASH = "ab" * 32
OTHER_HASH = "cd" * 32


def _codes(result: VerificationResult) -> set[str]:
    return {issue.code for issue in result.issues}


def _alert(**overrides: object) -> NormalizedAlert:
    return NormalizedAlert.model_validate(alert_payload(**overrides))


def _confidence() -> ConfidenceAssessment:
    """Schema arithmetic only. This is not scored from live evidence."""
    factors: list[ConfidenceFactor] = []
    for name, weight in FACTOR_WEIGHTS.items():
        factors.append(
            ConfidenceFactor(
                name=name,
                weight=weight,
                satisfied=name is ConfidenceFactorName.CONTRADICTION_PENALTY,
                evidence_ids=[],
                rationale=name.value,
            )
        )
    return ConfidenceAssessment(method="weighted_evidence_v1", score=15, factors=factors)


def _report(
    evidence: list[Evidence] | None = None,
    *,
    classification: Classification = Classification.INCONCLUSIVE,
    executive_summary: str = "No verdict was reached.",
    analyst_notes: str = "",
    indicators: list[Indicator] | None = None,
    timeline: list[TimelineEvent] | None = None,
) -> IncidentReport:
    return IncidentReport(
        investigation_id="inv-1",
        alert_id="alert-1",
        classification=classification,
        severity=AlertSeverity.MEDIUM,
        confidence=_confidence(),
        executive_summary=executive_summary,
        affected_assets=[],
        indicators=list(indicators or []),
        evidence=list(evidence or []),
        mitre_attack=[],
        timeline=list(timeline or []),
        recommended_actions=[],
        limitations=["No packet capture."],
        analyst_notes=analyst_notes,
    )


def _ip_evidence(
    evidence_id: str,
    *,
    source: str,
    ip: str = "203.0.113.10",
    reported_malicious: bool | None = None,
    reliability: EvidenceReliability | None = None,
    raw: dict[str, object] | None = None,
) -> Evidence:
    chosen = reliability_for_provider(source) if reliability is None else reliability
    return Evidence(
        evidence_id=evidence_id,
        source=source,
        tool="lookup_ip",
        query={"ip": ip},
        result={
            "ip": ip,
            "provider": source,
            "categories": [],
            "reported_malicious": reported_malicious,
            "reference_ids": [],
            "raw": {} if raw is None else raw,
        },
        timestamp=NOW,
        reliability=chosen,
    )


def _hash_evidence(
    evidence_id: str,
    *,
    source: str,
    malicious_count: int | None,
    harmless_count: int | None = None,
    file_hash: str = HASH,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        source=source,
        tool="lookup_hash",
        query={"file_hash": file_hash, "algorithm": "sha256"},
        result={
            "file_hash": file_hash,
            "algorithm": "sha256",
            "provider": source,
            "malicious_count": malicious_count,
            "harmless_count": harmless_count,
            "undetected_count": None,
            "raw": {"reliability": "high"},
        },
        timestamp=NOW,
        reliability=reliability_for_provider(source),
    )


def _verifying(max_retries: int) -> InvestigationState:
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        max_retries=max_retries,
        max_tool_calls=2,
        token_budget=100,
    )
    state = new_investigation(
        investigation_id="inv-1",
        alert_id="alert-1",
        now=NOW,
        settings=settings,
    )
    state = transition(state, InvestigationStatus.VALIDATING, now=NOW)
    return transition(state, InvestigationStatus.INVESTIGATING, now=NOW)


def _rejected() -> VerificationResult:
    return VerificationResult(
        accepted=False,
        issues=[
            VerificationIssue(
                code="unknown_indicator",
                detail="ip 198.51.100.23 is absent from the alert and the evidence",
            )
        ],
        contradictions=[],
    )


def test_two_provider_results_stay_separate_rows() -> None:
    first = _ip_evidence("ev-a", source="abuseipdb", reported_malicious=True)
    second = _ip_evidence("ev-b", source="mock:other", reported_malicious=False)
    linked = correlate([first, second])

    assert [item.evidence_id for item in linked.evidence] == ["ev-a", "ev-b"]
    assert linked.evidence[0].result["provider"] == "abuseipdb"
    assert linked.evidence[1].result["provider"] == "mock:other"
    assert linked.evidence[0].result != linked.evidence[1].result
    assert len(linked.indicators) == 1
    indicator = linked.indicators[0]
    assert indicator.type is IndicatorType.IP
    assert indicator.value == "203.0.113.10"
    assert indicator.evidence_ids == ["ev-a", "ev-b"]
    assert "result" not in indicator.model_dump()
    assert len(linked.contradictions) == 1
    observations = linked.contradictions[0].observations
    assert [(item.evidence_id, item.value) for item in observations] == [
        ("ev-a", True),
        ("ev-b", False),
    ]
    assert first.reliability is EvidenceReliability.MEDIUM
    assert second.reliability is EvidenceReliability.LOW
    true_claim = "ip|203.0.113.10|reported_malicious|true"
    false_claim = "ip|203.0.113.10|reported_malicious|false"
    assert true_claim in linked.evidence[0].supports
    assert false_claim in linked.evidence[0].contradicts
    assert false_claim in linked.evidence[1].supports
    assert true_claim in linked.evidence[1].contradicts


def test_unknown_verdict_does_not_contradict_or_drop_a_row() -> None:
    unknown = _ip_evidence("ev-u", source="dns", reported_malicious=None)
    flagged = _ip_evidence("ev-f", source="abuseipdb", reported_malicious=True)
    linked = correlate([unknown, flagged])

    assert [item.evidence_id for item in linked.evidence] == ["ev-u", "ev-f"]
    assert linked.contradictions == []
    assert linked.evidence[0].supports == []
    assert linked.evidence[0].contradicts == []
    assert linked.indicators[0].evidence_ids == ["ev-u", "ev-f"]


def test_raw_does_not_create_an_indicator_or_a_verdict() -> None:
    row = _ip_evidence(
        "ev-1",
        source="abuseipdb",
        reported_malicious=None,
        raw={"ip": "198.51.100.8", "reported_malicious": False, "reliability": "high"},
    )
    linked = correlate([row])

    assert [item.value for item in linked.indicators] == ["203.0.113.10"]
    assert linked.contradictions == []
    assert linked.evidence[0].supports == []
    assert linked.evidence[0].reliability is EvidenceReliability.MEDIUM
    assert "198.51.100.8" in str(linked.evidence[0].result["raw"])


def test_rows_without_an_indicator_are_kept() -> None:
    ip_row = _ip_evidence("ev-ip", source="abuseipdb")
    mitre = Evidence(
        evidence_id="ev-mitre",
        source="mitre-attack",
        tool="search_mitre",
        query={"query": "PowerShell", "technique_id": None},
        result={"query": "PowerShell", "provider": "mitre-attack", "techniques": []},
        timestamp=NOW,
        reliability=reliability_for_provider("mitre-attack"),
    )
    linked = correlate([ip_row, mitre])

    assert [item.evidence_id for item in linked.evidence] == ["ev-ip", "ev-mitre"]
    assert len(linked.indicators) == 1
    assert linked.indicators[0].evidence_ids == ["ev-ip"]


def test_conflicting_counts_are_not_averaged() -> None:
    low = _hash_evidence("h1", source="virustotal", malicious_count=0)
    high = _hash_evidence("h2", source="mock:virustotal", malicious_count=4)
    linked = correlate([low, high])

    assert [item.evidence_id for item in linked.evidence] == ["h1", "h2"]
    assert len(linked.indicators) == 1
    assert linked.indicators[0].evidence_ids == ["h1", "h2"]
    assert len(linked.contradictions) == 1
    assert [item.value for item in linked.contradictions[0].observations] == [0, 4]
    assert "average" not in Contradiction.model_fields
    assert "score" not in VerificationResult.model_fields


def test_summary_ip_absent_from_alert_and_evidence_fails() -> None:
    report = _report([], executive_summary="Connection from 198.51.100.23.")
    outcome = verify_report(report, alert=_alert(), evidence=[])

    assert outcome.accepted is False
    assert "unknown_indicator" in _codes(outcome)
    assert any("198.51.100.23" in issue.detail for issue in outcome.issues)


@pytest.mark.parametrize(
    "summary",
    [
        "See CVE-2020-1234.",
        f"Sample {OTHER_HASH} was attached.",
        "Lookup evil.example next.",
    ],
)
def test_other_indicators_absent_from_alert_and_evidence_fail(summary: str) -> None:
    outcome = verify_report(_report([], executive_summary=summary), alert=_alert(), evidence=[])
    assert outcome.accepted is False
    assert "unknown_indicator" in _codes(outcome)


def test_indicator_on_the_alert_is_known() -> None:
    report = _report([], executive_summary="Connection from 198.51.100.23.")
    outcome = verify_report(report, alert=_alert(source_ip="198.51.100.23"), evidence=[])
    assert outcome.accepted is True
    assert outcome.issues == []


def test_indicator_only_in_evidence_is_known() -> None:
    row = _ip_evidence("ev-1", source="abuseipdb", ip="198.51.100.23")
    report = _report([row], executive_summary="Connection from 198.51.100.23.")
    outcome = verify_report(report, alert=_alert(), evidence=[row])
    assert outcome.accepted is True


def test_ip_in_raw_or_description_is_not_known() -> None:
    raw_row = _ip_evidence(
        "ev-1",
        source="abuseipdb",
        raw={"ip": "198.51.100.99"},
    )
    raw_report = _report([raw_row], executive_summary="Also saw 198.51.100.99.")
    raw_outcome = verify_report(raw_report, alert=_alert(), evidence=[raw_row])
    assert raw_outcome.accepted is False
    assert "unknown_indicator" in _codes(raw_outcome)

    cve = Evidence(
        evidence_id="ev-cve",
        source="osv",
        tool="lookup_cve",
        query={"cve_id": "CVE-2024-1000"},
        result={
            "cve_id": "CVE-2024-1000",
            "provider": "osv",
            "description": "Contact 198.51.100.77 for the exploit.",
            "cvss_score": None,
            "cvss_version": None,
            "references": [],
            "raw": {},
        },
        timestamp=NOW,
        reliability=reliability_for_provider("osv"),
    )
    prose = _report([cve], executive_summary="The note mentioned 198.51.100.77.")
    prose_outcome = verify_report(prose, alert=_alert(), evidence=[cve])
    assert prose_outcome.accepted is False
    assert "unknown_indicator" in _codes(prose_outcome)


def test_notes_and_timeline_cannot_name_an_unknown_ip() -> None:
    row = _ip_evidence("ev-1", source="abuseipdb")
    notes = _report([row], analyst_notes="Pivot to 198.51.100.23.")
    notes_outcome = verify_report(notes, alert=_alert(), evidence=[row])
    assert "unknown_indicator" in _codes(notes_outcome)

    timeline = _report(
        [row],
        timeline=[
            TimelineEvent(
                timestamp=NOW,
                description="Saw 198.51.100.40.",
                evidence_ids=["ev-1"],
            )
        ],
    )
    timeline_outcome = verify_report(timeline, alert=_alert(), evidence=[row])
    assert "unknown_indicator" in _codes(timeline_outcome)


def test_null_verdict_is_not_benign() -> None:
    row = _ip_evidence("ev-1", source="abuseipdb", reported_malicious=None)
    report = _report(
        [row],
        classification=Classification.BENIGN,
        executive_summary="203.0.113.10 had no positive hit.",
    )
    outcome = verify_report(report, alert=_alert(), evidence=[row])
    assert outcome.accepted is False
    assert "unknown_not_benign" in _codes(outcome)
    assert "failed_lookup_not_benign" not in _codes(outcome)


def test_failed_lookup_is_not_benign() -> None:
    row = _ip_evidence("ev-1", source="abuseipdb", reported_malicious=None)
    report = _report(
        [row],
        classification=Classification.BENIGN,
        executive_summary="203.0.113.10 was not confirmed.",
    )
    failure = FailedLookup(tool="lookup_ip", query={"ip": "203.0.113.10"}, reason="timeout")
    outcome = verify_report(report, alert=_alert(), evidence=[row], failed_lookups=[failure])
    assert outcome.accepted is False
    assert "failed_lookup_not_benign" in _codes(outcome)
    assert correlate([row]).evidence[0].evidence_id == "ev-1"
    assert len(correlate([row]).evidence) == 1


def test_failed_lookup_leaves_inconclusive_unknown() -> None:
    row = _ip_evidence("ev-1", source="abuseipdb", reported_malicious=None)
    report = _report([row], executive_summary="203.0.113.10 stayed unknown after a timeout.")
    failure = FailedLookup(tool="lookup_ip", query={"ip": "203.0.113.10"}, reason="timeout")
    outcome = verify_report(report, alert=_alert(), evidence=[row], failed_lookups=[failure])
    assert outcome.accepted is True


def test_zero_malicious_count_is_not_benign_without_a_harmless_count() -> None:
    row = _hash_evidence("ev-h", source="virustotal", malicious_count=0, harmless_count=None)
    report = _report(
        [row],
        classification=Classification.BENIGN,
        executive_summary=f"Hash {HASH} had no malicious hits.",
    )
    outcome = verify_report(report, alert=_alert(), evidence=[row])
    assert "unknown_not_benign" in _codes(outcome)


def test_stored_false_verdict_can_be_benign() -> None:
    row = _ip_evidence("ev-1", source="abuseipdb", reported_malicious=False)
    report = _report(
        [row],
        classification=Classification.BENIGN,
        executive_summary="203.0.113.10 has reported_malicious false.",
    )
    outcome = verify_report(report, alert=_alert(), evidence=[row])
    assert outcome.accepted is True


def test_report_that_drops_a_contradiction_fails() -> None:
    first = _ip_evidence("ev-a", source="abuseipdb", reported_malicious=True)
    second = _ip_evidence("ev-b", source="mock:other", reported_malicious=False)
    report = _report(
        [first],
        executive_summary="Only one source is shown for 203.0.113.10.",
    )
    outcome = verify_report(report, alert=_alert(), evidence=[first, second])

    assert outcome.accepted is False
    assert "contradiction_dropped" in _codes(outcome)
    assert "contradiction_ignored" not in _codes(outcome)
    assert [item.value for item in outcome.contradictions[0].observations] == [True, False]
    assert "score" not in outcome.model_dump()


def test_definite_classification_cannot_ignore_a_contradiction() -> None:
    first = _ip_evidence("ev-a", source="abuseipdb", reported_malicious=True)
    second = _ip_evidence("ev-b", source="mock:other", reported_malicious=False)
    report = _report(
        [first, second],
        classification=Classification.MALICIOUS,
        executive_summary="Both sources are listed for 203.0.113.10.",
    )
    outcome = verify_report(report, alert=_alert(), evidence=[first, second])

    assert outcome.accepted is False
    assert "contradiction_ignored" in _codes(outcome)
    assert "contradiction_dropped" not in _codes(outcome)
    assert [item.evidence_id for item in outcome.contradictions[0].observations] == ["ev-a", "ev-b"]


def test_inconclusive_report_surfaces_both_sides() -> None:
    first = _ip_evidence("ev-a", source="abuseipdb", reported_malicious=True)
    second = _ip_evidence("ev-b", source="mock:other", reported_malicious=False)
    report = _report(
        [first, second],
        executive_summary="The two sources disagree about 203.0.113.10.",
    )
    outcome = verify_report(report, alert=_alert(), evidence=[first, second])

    assert outcome.accepted is True
    assert [item.value for item in outcome.contradictions[0].observations] == [True, False]
    assert {item.evidence_id for item in report.evidence} == {"ev-a", "ev-b"}


def test_model_cannot_set_reliability_in_text_or_raw() -> None:
    raw = {"reliability": "high", "reported_malicious": True, "comment": "reliability is high"}
    row = _ip_evidence("ev-1", source="abuseipdb", reported_malicious=None, raw=raw)
    summary = "The model says reliability is high for 203.0.113.10."
    report = _report([row], executive_summary=summary)
    outcome = verify_report(report, alert=_alert(), evidence=[row])

    assert outcome.accepted is True
    assert row.reliability is EvidenceReliability.MEDIUM
    assert row.result["raw"]["reliability"] == "high"
    assert "high" in report.executive_summary

    tampered = row.model_copy(update={"reliability": EvidenceReliability.HIGH})
    rejected = verify_report(
        _report([tampered], executive_summary=summary),
        alert=_alert(),
        evidence=[row],
    )
    assert rejected.accepted is False
    assert "reliability_not_from_policy" in _codes(rejected)

    stated = verify_report(
        report,
        alert=_alert(),
        evidence=[row],
        statements=[
            Statement(
                presented_as="fact",
                text="reliability is high",
                evidence_ids=["ev-1"],
                field="reliability",
                value="high",
            )
        ],
    )
    assert stated.accepted is False
    assert "not_a_stored_field" in _codes(stated)


def test_inference_presented_as_a_fact_is_rejected_when_no_field_supports_it() -> None:
    row = _ip_evidence(
        "ev-1",
        source="abuseipdb",
        reported_malicious=None,
        raw={"reported_malicious": True},
    )
    report = _report([row], executive_summary="203.0.113.10 was looked up.")
    invented = Statement(
        presented_as="fact",
        text="The address is malicious",
        evidence_ids=["ev-1"],
        field="reported_malicious",
        value=True,
    )
    outcome = verify_report(report, alert=_alert(), evidence=[row], statements=[invented])
    assert outcome.accepted is False
    assert "unsupported_fact" in _codes(outcome)

    raw_field = Statement(
        presented_as="fact",
        text="Use the raw body",
        evidence_ids=["ev-1"],
        field="raw",
        value="ignored",
    )
    raw_outcome = verify_report(report, alert=_alert(), evidence=[row], statements=[raw_field])
    assert "not_a_stored_field" in _codes(raw_outcome)


def test_accepted_conclusion_cites_existing_evidence() -> None:
    row = _ip_evidence("ev-1", source="abuseipdb", reported_malicious=True)
    report = _report([row], executive_summary="203.0.113.10 was looked up.")
    fact = Statement(
        presented_as="fact",
        text="reported_malicious is true",
        evidence_ids=["ev-1"],
        field="reported_malicious",
        value=True,
    )
    inference = Statement(
        presented_as="inference",
        text="This may be a scan",
        evidence_ids=["ev-1"],
    )
    outcome = verify_report(
        report,
        alert=_alert(),
        evidence=[row],
        statements=[fact, inference],
    )
    assert outcome.accepted is True

    missing = Statement(
        presented_as="inference",
        text="This may be a scan",
        evidence_ids=["missing"],
    )
    rejected = verify_report(report, alert=_alert(), evidence=[row], statements=[missing])
    assert rejected.accepted is False
    assert "dangling_citation" in _codes(rejected)

    invented = _report([row])
    dangling = verify_report(invented, alert=_alert(), evidence=[])
    assert "dangling_citation" in _codes(dangling)


def test_hostname_indicator_must_be_on_the_alert_or_evidence() -> None:
    row = _ip_evidence("ev-1", source="abuseipdb")
    report = _report(
        [row],
        indicators=[Indicator(type=IndicatorType.HOSTNAME, value="db-1", evidence_ids=["ev-1"])],
    )
    outcome = verify_report(report, alert=_alert(), evidence=[row])
    assert outcome.accepted is False
    assert "unknown_indicator" in _codes(outcome)


def test_accepted_verification_stays_verifying() -> None:
    state = transition(_verifying(2), InvestigationStatus.VERIFYING, now=NOW)
    result = VerificationResult(accepted=True, issues=[], contradictions=[])
    updated = apply_verification(state, result, now=NOW)

    assert updated.status is InvestigationStatus.VERIFYING
    assert updated.status not in {
        InvestigationStatus.AWAITING_REVIEW,
        InvestigationStatus.COMPLETE,
        InvestigationStatus.INVESTIGATING,
    }
    assert updated.retries == 0
    assert updated.verification is not None
    assert updated.verification.accepted is True
    assert updated.error is None


def test_rejected_verification_stays_verifying_while_retries_remain() -> None:
    state = transition(_verifying(2), InvestigationStatus.VERIFYING, now=NOW)
    updated = apply_verification(state, _rejected(), now=NOW)

    assert updated.status is InvestigationStatus.VERIFYING
    assert updated.retries == state.retries
    assert updated.retries <= updated.max_retries
    assert updated.error == "verification failed: unknown_indicator"
    assert updated.error is not None
    assert "198.51.100.23" not in updated.error
    assert updated.verification is not None
    assert updated.verification.accepted is False


def test_rejected_verification_fails_when_retries_are_exhausted() -> None:
    state = _verifying(2)
    for _ in range(2):
        state = transition(state, InvestigationStatus.VERIFYING, now=NOW)
        state = transition(state, InvestigationStatus.INVESTIGATING, now=NOW)
    state = transition(state, InvestigationStatus.VERIFYING, now=NOW)
    assert state.retries == state.max_retries

    updated = apply_verification(
        state, _rejected(), now=datetime(2026, 9, 18, 12, 5, tzinfo=NOW.tzinfo)
    )

    assert updated.status is InvestigationStatus.FAILED
    assert updated.retries == 2
    assert updated.retries <= updated.max_retries
    assert updated.status not in {
        InvestigationStatus.AWAITING_REVIEW,
        InvestigationStatus.COMPLETE,
        InvestigationStatus.INVESTIGATING,
    }
    assert updated.error == "verification failed: unknown_indicator"
    assert updated.verification is not None


def test_verification_does_not_apply_outside_verifying() -> None:
    state = _verifying(0)
    with pytest.raises(ValueError, match="VERIFYING"):
        apply_verification(state, _rejected(), now=NOW)
