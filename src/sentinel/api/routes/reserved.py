"""Routes that are named and not built yet. They do no work."""

from fastapi import APIRouter

from sentinel.api.errors import NotImplementedBody, not_implemented

router = APIRouter(tags=["reserved"])


@router.get("/metrics", response_model=NotImplementedBody, status_code=501)
def metrics() -> NotImplementedBody:
    return not_implemented(9, "Metrics are not implemented.")
