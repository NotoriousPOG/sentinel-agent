"""Datetime rules shared by domain models."""

from datetime import datetime


def require_aware(value: datetime) -> datetime:
    """Reject naive datetimes. Stored instants must carry an offset."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value
