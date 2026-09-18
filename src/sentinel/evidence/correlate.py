"""Group tool results by indicator without merging provider rows."""

from collections.abc import Sequence

from sentinel.evidence.indicators import IndicatorKey, indicators_from_evidence
from sentinel.schemas.correlation import (
    Contradiction,
    CorrelationResult,
    FieldObservation,
    JsonScalar,
    LinkedIndicator,
)
from sentinel.schemas.evidence import Evidence

# Tool-output fields that can disagree. ``raw`` is not one of them.
_FIELDS: dict[str, tuple[str, ...]] = {
    "lookup_ip": ("reported_malicious",),
    "lookup_domain": ("reported_malicious",),
    "lookup_hash": ("malicious_count",),
    "lookup_cve": ("cvss_score",),
}


def correlate(evidence: Sequence[Evidence]) -> CorrelationResult:
    """Return the same rows, plus indicator links and contradiction links.

    Two results for one indicator stay two rows. A disagreeing value is listed
    on each row's claim ids and on ``contradictions``. Nothing is averaged and
    nothing is dropped. ``null`` does not contradict a value.
    """
    grouped: dict[IndicatorKey, list[int]] = {}
    for index, item in enumerate(evidence):
        for key in indicators_from_evidence(item):
            grouped.setdefault(key, []).append(index)

    support: list[set[str]] = [set() for _ in evidence]
    against: list[set[str]] = [set() for _ in evidence]
    contradictions: list[Contradiction] = []
    for key in sorted(grouped, key=lambda item: (item[0].value, item[1])):
        indexes = grouped[key]
        fields = _fields_for(evidence, indexes)
        for field in fields:
            observed: list[tuple[int, JsonScalar]] = []
            for index in indexes:
                value = _observed(evidence[index], field)
                if value is not None:
                    observed.append((index, value))
            _record_claims(support, against, key, field, observed)
            distinct = {value for _, value in observed}
            if len(distinct) < 2:
                continue
            kind, indicator = key
            contradictions.append(
                Contradiction(
                    type=kind,
                    value=indicator,
                    field=field,
                    observations=[
                        FieldObservation(evidence_id=evidence[index].evidence_id, value=value)
                        for index, value in observed
                    ],
                )
            )

    rows = [
        item.model_copy(
            update={
                "supports": sorted(support[index]),
                "contradicts": sorted(against[index]),
            }
        )
        for index, item in enumerate(evidence)
    ]
    indicators = [
        LinkedIndicator(
            type=kind,
            value=indicator,
            evidence_ids=[evidence[index].evidence_id for index in grouped[key]],
        )
        for key in sorted(grouped, key=lambda item: (item[0].value, item[1]))
        for kind, indicator in (key,)
    ]
    return CorrelationResult(evidence=rows, indicators=indicators, contradictions=contradictions)


def _fields_for(evidence: Sequence[Evidence], indexes: list[int]) -> tuple[str, ...]:
    names: list[str] = []
    seen: set[str] = set()
    for index in indexes:
        for field in _FIELDS.get(evidence[index].tool, ()):
            if field not in seen:
                seen.add(field)
                names.append(field)
    return tuple(names)


def _record_claims(
    support: list[set[str]],
    against: list[set[str]],
    key: IndicatorKey,
    field: str,
    observed: list[tuple[int, JsonScalar]],
) -> None:
    kind, indicator = key
    for index, value in observed:
        token = _token(value)
        support[index].add(f"{kind.value}|{indicator}|{field}|{token}")
        opposite = _opposite(field, value)
        if opposite is not None:
            against[index].add(f"{kind.value}|{indicator}|{field}|{opposite}")


def _opposite(field: str, value: JsonScalar) -> str | None:
    if value is True:
        return "false"
    if value is False:
        return "true"
    if field == "malicious_count" and isinstance(value, int) and not isinstance(value, bool):
        if value > 0:
            return "0"
        if value == 0:
            return "positive"
    return None


def _observed(item: Evidence, field: str) -> JsonScalar | None:
    if field not in _FIELDS.get(item.tool, ()):
        return None
    if field not in item.result:
        return None
    value = item.result[field]
    if field == "reported_malicious":
        if isinstance(value, bool):
            return value
        return None
    if field == "malicious_count":
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value
    if field == "cvss_score" and not isinstance(value, bool) and isinstance(value, int | float):
        return float(value)
    return None


def _token(value: JsonScalar) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, float):
        return format(value, "g")
    return str(value)
