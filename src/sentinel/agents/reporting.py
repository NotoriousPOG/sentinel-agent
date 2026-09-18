"""Build a verified incident report. This module does not enter ``COMPLETE``.

Grounded fields come from stored evidence. The model may supply only the
narrative. ``verify_report`` runs before anything is stored. A failure stores
nothing.
"""

from collections.abc import Sequence
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinel.agents.budgets import assert_can_spend_tokens, is_past_deadline
from sentinel.agents.prompts import repair_message, report_messages
from sentinel.agents.transitions import transition
from sentinel.errors import (
    BudgetExhausted,
    LlmTransportError,
    ModelOutputInvalid,
    ReportNotFound,
    ReportRejected,
)
from sentinel.evidence.correlate import correlate
from sentinel.evidence.score import lookup_coverage_met, score_confidence
from sentinel.evidence.verify import _supports_benign, _supports_malicious, verify_report
from sentinel.schemas.alerts import AlertSeverity, NormalizedAlert
from sentinel.schemas.evidence import Evidence, EvidenceReliability
from sentinel.schemas.investigation import (
    InvestigationState,
    InvestigationStatus,
    ModelOutputRecord,
)
from sentinel.schemas.reports import (
    Classification,
    IncidentReport,
    Indicator,
    MitreTechniqueRef,
    TimelineEvent,
)
from sentinel.schemas.verification import VerificationResult
from sentinel.services.clock import Clock
from sentinel.services.llm import LlmMessage, LlmProvider
from sentinel.services.providers.mitre import official_technique, technique_ids_in_result

_SCHEMA_FAILURE = "report output failed schema validation"


class ReportNarrative(BaseModel):
    """Narrative fields only. Confidence, MITRE, and evidence are not fields here."""

    model_config = ConfigDict(extra="forbid")

    executive_summary: str = Field(min_length=1, max_length=4000)
    analyst_notes: str = Field(default="", max_length=4000)


def classification_from_evidence(evidence: Sequence[Evidence]) -> Classification:
    """Choose a classification the verifier can accept. Do not invent a verdict."""
    malicious = [item for item in evidence if _supports_malicious(item)]
    benign = [item for item in evidence if _supports_benign(item)]
    if correlate(evidence).contradictions or (malicious and benign):
        return Classification.INCONCLUSIVE
    if malicious:
        weak = all(
            item.reliability in {EvidenceReliability.LOW, EvidenceReliability.UNKNOWN}
            for item in malicious
        )
        if weak:
            return Classification.SUSPICIOUS
        return Classification.MALICIOUS
    if benign:
        return Classification.BENIGN
    return Classification.INCONCLUSIVE


def mitre_refs(evidence: Sequence[Evidence]) -> list[MitreTechniqueRef]:
    """Techniques cited by ``search_mitre`` rows and present in the local subset.

    An id in a result that is not in the subset fails. It is not copied onto
    the report under another name. No ``search_mitre`` row means an empty list.
    """
    order: list[str] = []
    cited: dict[str, list[str]] = {}
    for item in evidence:
        if item.tool != "search_mitre":
            continue
        for technique_id in sorted(technique_ids_in_result(item.result)):
            official = official_technique(technique_id)
            if official is None:
                raise ReportRejected(f"unknown technique id {technique_id}")
            bucket = cited.setdefault(technique_id, [])
            if technique_id not in order:
                order.append(technique_id)
            if item.evidence_id not in bucket:
                bucket.append(item.evidence_id)
    refs: list[MitreTechniqueRef] = []
    for technique_id in order:
        official = official_technique(technique_id)
        if official is None:
            raise ReportRejected(f"unknown technique id {technique_id}")
        refs.append(
            MitreTechniqueRef(
                technique_id=official.technique_id,
                technique_name=official.name,
                tactic=official.tactic,
                evidence_ids=cited[technique_id],
            )
        )
    return refs


def assemble_report(
    *,
    investigation_id: str,
    alert: NormalizedAlert,
    evidence: Sequence[Evidence],
    narrative: ReportNarrative,
) -> IncidentReport:
    """Join evidence-derived fields with narrative text. Does not call a model."""
    linked = correlate(evidence)
    classification = classification_from_evidence(evidence)
    rows = list(linked.evidence)
    return IncidentReport(
        investigation_id=investigation_id,
        alert_id=alert.alert_id,
        classification=classification,
        severity=alert.severity or AlertSeverity.INFORMATIONAL,
        confidence=score_confidence(
            alert=alert,
            evidence=evidence,
            classification=classification,
        ),
        executive_summary=narrative.executive_summary,
        analyst_notes=narrative.analyst_notes,
        affected_assets=_assets(alert),
        indicators=[
            Indicator(type=item.type, value=item.value, evidence_ids=list(item.evidence_ids))
            for item in linked.indicators
        ],
        evidence=rows,
        mitre_attack=mitre_refs(evidence),
        timeline=[
            TimelineEvent(
                timestamp=item.timestamp,
                description="Stored tool result.",
                evidence_ids=[item.evidence_id],
            )
            for item in rows
        ],
        recommended_actions=[],
        limitations=_limitations(alert, evidence, classification),
    )


def published_report(state: InvestigationState) -> IncidentReport:
    """Return the stored verified report. A missing or rejected report is not a draft."""
    report = state.report
    verification = state.verification
    if report is None or verification is None or not verification.accepted:
        raise ReportNotFound()
    return report


def finalize_investigation(
    state: InvestigationState,
    *,
    alert: NormalizedAlert,
    llm: LlmProvider,
    clock: Clock,
    max_repair_attempts: int,
) -> InvestigationState:
    """Ask for narrative text, verify, then store or fail.

    Starts from ``VERIFYING``. A verified report moves to ``AWAITING_REVIEW``.
    Schema failure gets one repair from ``max_repair_attempts``, then ``FAILED``.
    A report ``verify_report`` rejects is not stored. This does not enter
    ``COMPLETE`` and does not return to ``INVESTIGATING``.
    """
    if state.status is not InvestigationStatus.VERIFYING:
        raise ValueError("report generation starts from VERIFYING")
    if alert.alert_id != state.alert_id:
        return _fail(state, "alert id does not match the investigation", clock.now())

    messages = report_messages(alert, state.evidence)
    repairs_used = 0
    initial_repairs = state.repair_attempts
    while True:
        now = clock.now()
        if is_past_deadline(state, now):
            return _fail(state, "deadline exceeded", now)
        prompt_tokens = _message_tokens(messages)
        try:
            assert_can_spend_tokens(state, prompt_tokens)
        except BudgetExhausted:
            return _fail(state, "token budget exhausted", now)
        try:
            narrative = llm.complete_structured(messages, ReportNarrative)
        except ModelOutputInvalid as exc:
            state, repairs_used, failed = _repair(
                state,
                messages,
                detail=exc.detail,
                raw_text=exc.raw_text,
                now=clock.now(),
                repairs_used=repairs_used,
                initial_repairs=initial_repairs,
                max_repair_attempts=max_repair_attempts,
            )
            if failed:
                return state
            continue
        except LlmTransportError as exc:
            return _fail(state, f"llm transport failed: {exc.reason}", clock.now())

        response_tokens = _text_tokens(narrative.model_dump_json())
        try:
            assert_can_spend_tokens(
                state.model_copy(update={"tokens_used": state.tokens_used + prompt_tokens}),
                response_tokens,
            )
        except BudgetExhausted:
            spent = state.model_copy(
                update={
                    "tokens_used": state.tokens_used + prompt_tokens,
                    "updated_at": clock.now(),
                }
            )
            return _fail(spent, "token budget exhausted", clock.now())
        state = state.model_copy(
            update={
                "tokens_used": state.tokens_used + prompt_tokens + response_tokens,
                "updated_at": clock.now(),
            }
        )
        try:
            report = assemble_report(
                investigation_id=state.investigation_id,
                alert=alert,
                evidence=state.evidence,
                narrative=narrative,
            )
        except ReportRejected as exc:
            return _fail(state, exc.detail, clock.now())
        except ValidationError:
            state, repairs_used, failed = _repair(
                state,
                messages,
                detail=_SCHEMA_FAILURE,
                raw_text=narrative.model_dump_json(),
                now=clock.now(),
                repairs_used=repairs_used,
                initial_repairs=initial_repairs,
                max_repair_attempts=max_repair_attempts,
            )
            if failed:
                return state
            continue

        outcome = verify_report(report, alert=alert, evidence=state.evidence)
        now = clock.now()
        recorded = state.model_copy(update={"verification": outcome, "updated_at": now})
        if not outcome.accepted:
            return transition(
                recorded,
                InvestigationStatus.FAILED,
                now=now,
                error=_verification_error(outcome),
            )
        stored = recorded.model_copy(update={"report": report, "error": None})
        return transition(stored, InvestigationStatus.AWAITING_REVIEW, now=now)


def _limitations(
    alert: NormalizedAlert,
    evidence: Sequence[Evidence],
    classification: Classification,
) -> list[str]:
    items = [
        "Classification uses stored tool fields only. No facts were added outside those fields."
    ]
    if not evidence:
        items.append("No tool results were collected.")
    if correlate(evidence).contradictions:
        items.append("Provider results disagree. They were not merged or averaged.")
    if len({item.source for item in evidence}) == 1:
        items.append("Only one provider returned results.")
    if any(
        item.reliability in {EvidenceReliability.LOW, EvidenceReliability.UNKNOWN}
        for item in evidence
    ):
        items.append("At least one source is low or unknown reliability under tool policy.")
    if not lookup_coverage_met(alert, evidence):
        items.append("Not every lookup-capable indicator type on the alert was looked up.")
    if classification is Classification.INCONCLUSIVE:
        items.append("Stored fields do not support one benign or malicious verdict.")
    if alert.severity is None:
        items.append("The alert did not include a severity.")
    return items


def _assets(alert: NormalizedAlert) -> list[str]:
    values: list[str] = []
    for value in (alert.hostname, alert.username):
        if value is None:
            continue
        text = value.strip()
        if text:
            values.append(text[:500])
    return values


def _repair(
    state: InvestigationState,
    messages: list[LlmMessage],
    *,
    detail: str,
    raw_text: str,
    now: datetime,
    repairs_used: int,
    initial_repairs: int,
    max_repair_attempts: int,
) -> tuple[InvestigationState, int, bool]:
    bounded_raw = raw_text.strip()[:20_000] or "(empty)"
    bounded_detail = detail.strip()[:2000] or _SCHEMA_FAILURE
    recorded = state.model_copy(
        update={
            "error": bounded_detail,
            "updated_at": now,
            "report": None,
            "model_outputs": [
                *state.model_outputs,
                ModelOutputRecord(raw_text=bounded_raw, error=bounded_detail),
            ],
        }
    )
    if repairs_used >= max_repair_attempts:
        return _fail(recorded, _SCHEMA_FAILURE, now), repairs_used, True
    repairs_used += 1
    recorded = recorded.model_copy(update={"repair_attempts": initial_repairs + repairs_used})
    messages.append(repair_message(detail=bounded_detail, raw_text=bounded_raw))
    return recorded, repairs_used, False


def _fail(state: InvestigationState, error: str, now: datetime) -> InvestigationState:
    text = error.strip()[:2000] or "investigation failed"
    cleared = state.model_copy(update={"report": None})
    return transition(cleared, InvestigationStatus.FAILED, now=now, error=text)


def _verification_error(result: VerificationResult) -> str:
    codes = ", ".join(issue.code for issue in result.issues) or "rejected"
    return f"verification failed: {codes}"[:2000]


def _message_tokens(messages: Sequence[LlmMessage]) -> int:
    return sum(_text_tokens(message.content) for message in messages)


def _text_tokens(text: str) -> int:
    return max(1, len(text) // 4)
