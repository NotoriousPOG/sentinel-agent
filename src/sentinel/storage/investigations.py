"""Investigation persistence. Callers own the session."""

from sqlalchemy.orm import Session

from sentinel.models.investigation import InvestigationRecord
from sentinel.schemas.investigation import InvestigationState


class InvestigationRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, investigation_id: str) -> InvestigationRecord | None:
        return self._session.get(InvestigationRecord, investigation_id)

    def load(self, investigation_id: str) -> InvestigationState | None:
        record = self.get(investigation_id)
        if record is None:
            return None
        return InvestigationState.model_validate(record.document)

    def save(self, state: InvestigationState) -> InvestigationRecord:
        document = state.model_dump(mode="json")
        record = self.get(state.investigation_id)
        if record is None:
            record = InvestigationRecord(
                investigation_id=state.investigation_id,
                alert_id=state.alert_id,
                status=state.status.value,
                updated_at=state.updated_at,
                document=document,
            )
            self._session.add(record)
        else:
            record.alert_id = state.alert_id
            record.status = state.status.value
            record.updated_at = state.updated_at
            record.document = document
        self._session.commit()
        return record
