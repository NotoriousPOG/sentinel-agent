"""Product routes that exist so the contract is stable. They do no work."""

from fastapi import APIRouter

from sentinel.api.errors import NotImplementedBody, not_implemented
from sentinel.schemas.investigation import CreateInvestigationRequest
from sentinel.schemas.review import AnalystReview

router = APIRouter(tags=["reserved"])


@router.post("/investigations", response_model=NotImplementedBody, status_code=501)
def create_investigation(body: CreateInvestigationRequest) -> NotImplementedBody:
    """Accept an alert id and do not start an investigation."""
    _ = body
    return not_implemented(4, "Investigation execution is not implemented.")


@router.get("/investigations/{id}", response_model=NotImplementedBody, status_code=501)
def get_investigation(id: str) -> NotImplementedBody:
    _ = id
    return not_implemented(4, "Investigation lookup is not implemented.")


@router.get(
    "/investigations/{id}/evidence",
    response_model=NotImplementedBody,
    status_code=501,
)
def get_evidence(id: str) -> NotImplementedBody:
    _ = id
    return not_implemented(5, "Evidence retrieval is not implemented.")


@router.get(
    "/investigations/{id}/report",
    response_model=NotImplementedBody,
    status_code=501,
)
def get_report(id: str) -> NotImplementedBody:
    _ = id
    return not_implemented(6, "Report retrieval is not implemented.")


@router.post(
    "/investigations/{id}/review",
    response_model=NotImplementedBody,
    status_code=501,
)
def review_investigation(id: str, review: AnalystReview) -> NotImplementedBody:
    """Validate a review document and do not store it or execute remediation."""
    _ = (id, review)
    return not_implemented(6, "Analyst review is not implemented.")


@router.get("/metrics", response_model=NotImplementedBody, status_code=501)
def metrics() -> NotImplementedBody:
    return not_implemented(9, "Metrics are not implemented.")
