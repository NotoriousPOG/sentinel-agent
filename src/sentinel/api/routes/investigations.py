"""Start and reload an investigation. Review and report stay unimplemented."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from sentinel.agents.executor import run_investigation
from sentinel.agents.transitions import new_investigation
from sentinel.api.deps import get_db
from sentinel.config.settings import get_settings
from sentinel.errors import AlertNotFound, InvestigationNotFound
from sentinel.models.alert import AlertRecord
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.investigation import (
    CreateInvestigationRequest,
    EvidenceList,
    InvestigationState,
)
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

    The run is synchronous. It stops at ``VERIFYING`` or ``FAILED``. It does
    not approve a conclusion and it does not build an incident report.
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
    """Return evidence records stored on the state. This does not correlate them."""
    state = InvestigationRepository(session).load(id)
    if state is None:
        raise InvestigationNotFound()
    return EvidenceList(investigation_id=state.investigation_id, evidence=list(state.evidence))
