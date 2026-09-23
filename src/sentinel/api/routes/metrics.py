"""Process counters. This route does not read alerts or the database."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from sentinel.api.auth import require_api_key
from sentinel.config.settings import get_settings
from sentinel.observability.metrics import snapshot

router = APIRouter(tags=["metrics"], dependencies=[Depends(require_api_key)])


class MetricsResponse(BaseModel):
    """Counts for this process. No alert text, command lines, usernames, or keys."""

    model_config = ConfigDict(extra="forbid")

    investigations_total: int = Field(ge=0)
    investigations_by_status: dict[str, int]
    tool_errors: int = Field(ge=0)
    tokens_total: int = Field(ge=0)
    estimated_cost_usd: str


@router.get("/metrics", response_model=MetricsResponse)
def metrics() -> MetricsResponse:
    """Return investigation counts, tool errors, and token totals.

    ``estimated_cost_usd`` is ``0`` unless ``SENTINEL_USD_PER_MILLION_TOKENS``
    is set. That variable is not a model price.
    """
    settings = get_settings()
    current = snapshot(settings.usd_per_million_tokens)
    return MetricsResponse(
        investigations_total=current.investigations_total,
        investigations_by_status=current.investigations_by_status,
        tool_errors=current.tool_errors,
        tokens_total=current.tokens_total,
        estimated_cost_usd=current.estimated_cost_usd,
    )
