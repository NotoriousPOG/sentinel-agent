"""Routes that are named and not built yet. They do no work."""

from fastapi import APIRouter

from sentinel.api.errors import NotImplementedBody, not_implemented
from sentinel.schemas.review import AnalystReview

router = APIRouter(tags=["reserved"])


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
