"""Alert persistence. The first write for an ``alert_id`` wins.

A second request with the same id does not overwrite the stored document.
That keeps a replay from replacing an alert an attacker has already seen stored.
"""

from datetime import UTC, datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from sentinel.models.alert import AlertRecord
from sentinel.schemas.alerts import NormalizedAlert


def aware_utc(value: datetime) -> datetime:
    """Return a UTC datetime.

    SQLite drops the offset on read. This process only writes UTC, so a naive
    value from SQLite is treated as UTC. PostgreSQL returns an aware value.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class AlertRepository:
    """Read and insert alerts. Callers own the session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, alert_id: str) -> AlertRecord | None:
        return self._session.get(AlertRecord, alert_id)

    def save(self, alert: NormalizedAlert, received_at: datetime) -> tuple[AlertRecord, bool]:
        """Insert ``alert`` or return the existing row. The bool is true when this call inserted."""
        existing = self.get(alert.alert_id)
        if existing is not None:
            return existing, False
        record = AlertRecord(
            alert_id=alert.alert_id,
            source=alert.source,
            received_at=received_at,
            document=alert.model_dump(mode="json"),
        )
        self._session.add(record)
        try:
            self._session.commit()
        except IntegrityError:
            self._session.rollback()
            raced = self.get(alert.alert_id)
            if raced is None:
                raise
            return raced, False
        return record, True
