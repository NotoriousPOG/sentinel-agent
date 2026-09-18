"""Store an analyst decision.

Approving the conclusion is the only transition to ``COMPLETE`` in this
package. Approving remediation writes that field and stops. There is no
executor to call, and this module does not add one.
"""

from datetime import datetime
from typing import Literal

from sentinel.agents.transitions import transition
from sentinel.errors import BodyValidationError, FieldIssue, ReviewNotAllowed
from sentinel.schemas.errors import ValidationCode
from sentinel.schemas.investigation import InvestigationState, InvestigationStatus
from sentinel.schemas.review import AnalystReview, ReviewDecision

ReviewStatus = Literal["COMPLETE", "FAILED"]


def apply_analyst_review(
    state: InvestigationState,
    review: AnalystReview,
    *,
    now: datetime,
) -> InvestigationState:
    """Persist ``review`` and move status. Does not isolate, block, or delete.

    ``AWAITING_REVIEW`` plus a verified report is required. Rejection records
    the decision and moves to ``FAILED``. It does not return to
    ``INVESTIGATING``. The remediation field is stored and not interpreted.
    """
    if review.investigation_id != state.investigation_id:
        raise BodyValidationError(
            (FieldIssue(code=ValidationCode.INVALID_FIELD, field="investigation_id"),)
        )
    verified = (
        state.status is InvestigationStatus.AWAITING_REVIEW
        and state.report is not None
        and state.verification is not None
        and state.verification.accepted
    )
    if not verified:
        raise ReviewNotAllowed()
    updated = state.model_copy(update={"review": review})
    if review.conclusion is ReviewDecision.APPROVE:
        return transition(updated, InvestigationStatus.COMPLETE, now=now)
    return transition(
        updated,
        InvestigationStatus.FAILED,
        now=now,
        error="analyst rejected the conclusion",
    )


def review_status(state: InvestigationState) -> ReviewStatus:
    """Label the status a stored review produced."""
    if state.status is InvestigationStatus.COMPLETE:
        return "COMPLETE"
    if state.status is InvestigationStatus.FAILED:
        return "FAILED"
    raise ReviewNotAllowed()
