"""Alert ingestion. Other investigation routes stay unimplemented."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from sentinel.api.deps import get_db
from sentinel.errors import (
    AlertNotFound,
    AlertValidationError,
    FieldIssue,
    prefix_issues,
)
from sentinel.models.alert import AlertRecord
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.errors import ValidationCode
from sentinel.schemas.ingest import AlertIngestRequest, AlertIngestResponse, StoredAlert
from sentinel.services.sources import GenericJsonAdapter, SourceAdapter, WazuhAdapter
from sentinel.storage.alerts import AlertRepository, aware_utc

router = APIRouter(tags=["alerts"])

_ADAPTERS: dict[str, SourceAdapter] = {
    GenericJsonAdapter.name: GenericJsonAdapter(),
    WazuhAdapter.name: WazuhAdapter(),
}


def _normalize(body: AlertIngestRequest) -> NormalizedAlert:
    adapter = _ADAPTERS.get(body.source)
    if adapter is None:
        raise AlertValidationError(
            (FieldIssue(code=ValidationCode.UNKNOWN_SOURCE, field="source"),)
        )
    try:
        alert = adapter.normalize(body.payload)
    except AlertValidationError as exc:
        raise AlertValidationError(prefix_issues(exc.issues, "payload")) from exc
    except TypeError as exc:
        raise AlertValidationError(
            (FieldIssue(code=ValidationCode.INVALID_TYPE, field="payload"),)
        ) from exc
    return alert


def _stored(record: AlertRecord, *, replay: bool) -> AlertIngestResponse:
    return AlertIngestResponse(
        received_at=aware_utc(record.received_at),
        idempotent_replay=replay,
        alert=NormalizedAlert.model_validate(record.document),
    )


@router.post("/alerts", response_model=AlertIngestResponse, status_code=201)
def create_alert(
    body: AlertIngestRequest,
    response: Response,
    session: Annotated[Session, Depends(get_db)],
) -> AlertIngestResponse:
    """Normalize and store an alert. The same ``alert_id`` returns the first stored copy."""
    alert = _normalize(body)
    record, created = AlertRepository(session).save(alert, datetime.now(UTC))
    response.status_code = 201 if created else 200
    return _stored(record, replay=not created)


@router.get("/alerts/{id}", response_model=StoredAlert)
def get_alert(id: str, session: Annotated[Session, Depends(get_db)]) -> StoredAlert:
    """Reload one stored alert. A missing id is ``alert_not_found``, not an empty document."""
    record = AlertRepository(session).get(id)
    if record is None:
        raise AlertNotFound()
    stored = _stored(record, replay=False)
    return StoredAlert(received_at=stored.received_at, alert=stored.alert)
