"""Start, reload, and review an investigation."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from sentinel.agents.executor import run_investigation
from sentinel.agents.reporting import published_report
from sentinel.agents.review import apply_analyst_review, review_status
from sentinel.agents.transitions import new_investigation
from sentinel.api.deps import get_db
from sentinel.config.settings import get_settings
from sentinel.errors import (
    AlertNotFound,
    BodyValidationError,
    FieldIssue,
    InvestigationNotFound,
)
from sentinel.evidence.correlate import correlate
from sentinel.models.alert import AlertRecord
from sentinel.observability.metrics import update_investigation_status
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.errors import ValidationCode
from sentinel.schemas.investigation import (
    CreateInvestigationRequest,
    EvidenceList,
    InvestigationState,
)
from sentinel.schemas.reports import IncidentReport
from sentinel.schemas.review import AnalystReview, ReviewResult
from sentinel.services.clock import SystemClock
from sentinel.services.llm_http import build_llm_client
from sentinel.storage.alerts import AlertRepository
from sentinel.storage.investigations import InvestigationRepository
from sentinel.tools.registry import build_registry

router = APIRouter(tags=["investigations"])


def _alert(record: AlertRecord) -> NormalizedAlert:
    return NormalizedAlert.model_validate(record.document)


@router.post("/investigations", response_model=InvestigationState, status_code=201)
def create_investigation(
    body: CreateInvestigationRequest,
    session: Annotated[Session, Depends(get_db)],
) -> InvestigationState:
    """Create a state for a stored alert, run the executor, and return that state.

    The run is synchronous. A verified report moves the state to
    ``AWAITING_REVIEW``. Anything else that stops the run is ``FAILED``.
    This route does not approve a conclusion.
    """
    stored = AlertRepository(session).get(body.alert_id)
    if stored is None:
        raise AlertNotFound()
    alert = _alert(stored)
    settings = get_settings()
    clock = SystemClock()
    finished = run_investigation(
        new_investigation(
            investigation_id=uuid.uuid4().hex,
            alert_id=alert.alert_id,
            now=clock.now(),
            settings=settings,
        ),
        alert=alert,
        llm=build_llm_client(settings),
        tools=build_registry(settings),
        clock=clock,
        max_repair_attempts=settings.max_repair_attempts,
    )
    InvestigationRepository(session).save(finished)
    return finished


@router.get("/investigations/{id}", response_model=InvestigationState)
def get_investigation(
    id: str,
    session: Annotated[Session, Depends(get_db)],
) -> InvestigationState:
    """Reload one stored investigation. A missing id is ``investigation_not_found``."""
    state = InvestigationRepository(session).load(id)
    if state is None:
        raise InvestigationNotFound()
    return state


@router.get("/investigations/{id}/evidence", response_model=EvidenceList)
def get_evidence(
    id: str,
    session: Annotated[Session, Depends(get_db)],
) -> EvidenceList:
    """Return each stored row, indicator links, and contradiction links.

    Two provider results stay two rows. This does not verify a report and does
    not change investigation status.
    """
    state = InvestigationRepository(session).load(id)
    if state is None:
        raise InvestigationNotFound()
    linked = correlate(state.evidence)
    return EvidenceList(
        investigation_id=state.investigation_id,
        evidence=linked.evidence,
        indicators=linked.indicators,
        contradictions=linked.contradictions,
    )


@router.get("/investigations/{id}/report", response_model=IncidentReport)
def get_report(
    id: str,
    session: Annotated[Session, Depends(get_db)],
) -> IncidentReport:
    """Return the stored verified report. A missing report is not a draft."""
    state = InvestigationRepository(session).load(id)
    if state is None:
        raise InvestigationNotFound()
    return published_report(state)


@router.post("/investigations/{id}/review", response_model=ReviewResult)
def review_investigation(
    id: str,
    review: AnalystReview,
    session: Annotated[Session, Depends(get_db)],
) -> ReviewResult:
    """Store an analyst decision. Approving the conclusion completes the run.

    Approving remediation stores that decision and does not run an action.
    """
    state = InvestigationRepository(session).load(id)
    if state is None:
        raise InvestigationNotFound()
    if review.investigation_id != id:
        raise BodyValidationError(
            (FieldIssue(code=ValidationCode.INVALID_FIELD, field="investigation_id"),)
        )
    updated = apply_analyst_review(state, review, now=SystemClock().now())
    InvestigationRepository(session).save(updated)
    update_investigation_status(updated.investigation_id, updated.status.value)
    stored = updated.review
    if stored is None:
        raise InvestigationNotFound()
    return ReviewResult(status=review_status(updated), review=stored)
