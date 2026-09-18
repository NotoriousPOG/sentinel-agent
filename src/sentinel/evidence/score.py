"""Set ``weighted_evidence_v1`` booleans from an alert and stored tool rows.

The percentage is ``compute_confidence_score``. A model does not supply it.
Rules match the table in ``docs/architecture.md``. URL has no lookup tool, so
it counts for data completeness and not for evidence coverage.
"""

from collections.abc import Iterable, Sequence

from sentinel.evidence.correlate import correlate
from sentinel.evidence.indicators import indicators_from_alert
from sentinel.evidence.verify import _supports_benign, _supports_malicious
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.confidence import (
    FACTOR_WEIGHTS,
    ConfidenceAssessment,
    ConfidenceFactor,
    ConfidenceFactorName,
    compute_confidence_score,
)
from sentinel.schemas.evidence import Evidence, EvidenceReliability
from sentinel.schemas.reports import Classification, IndicatorType

# Indicator types that have a tool. Hostname, user, process, and URL do not.
_LOOKUP_TOOLS: dict[IndicatorType, str] = {
    IndicatorType.IP: "lookup_ip",
    IndicatorType.DOMAIN: "lookup_domain",
    IndicatorType.HASH: "lookup_hash",
    IndicatorType.CVE: "lookup_cve",
}
_TOOL_TYPES = {tool: kind for kind, tool in _LOOKUP_TOOLS.items()}
_RELIABLE = frozenset({EvidenceReliability.HIGH, EvidenceReliability.MEDIUM})


def lookup_coverage_met(alert: NormalizedAlert, evidence: Sequence[Evidence]) -> bool:
    """True when every lookup-capable type on the alert has a tool row.

    An alert with none of those types is covered. That does not by itself
    satisfy the factor: a satisfied factor other than data completeness still
    has to cite an evidence id.
    """
    present = _present_lookup_types(alert)
    if not present:
        return True
    return present <= _looked_up_types(evidence)


def score_confidence(
    *,
    alert: NormalizedAlert,
    evidence: Sequence[Evidence],
    classification: Classification,
) -> ConfidenceAssessment:
    """Return the fixed five factors with ``satisfied`` set from ``evidence``."""
    factors = [
        _coverage_factor(alert, evidence),
        _reliability_factor(evidence, classification),
        _corroboration_factor(evidence, classification),
        _contradiction_factor(evidence, classification),
        _completeness_factor(alert),
    ]
    return ConfidenceAssessment(
        method="weighted_evidence_v1",
        score=compute_confidence_score(factors),
        factors=factors,
    )


def _coverage_factor(alert: NormalizedAlert, evidence: Sequence[Evidence]) -> ConfidenceFactor:
    present = _present_lookup_types(alert)
    if not present:
        ids = _unique(item.evidence_id for item in evidence)
        if ids:
            return _factor(
                ConfidenceFactorName.EVIDENCE_COVERAGE,
                satisfied=True,
                evidence_ids=ids,
                rationale="The alert has no lookup-capable indicator.",
            )
        return _factor(
            ConfidenceFactorName.EVIDENCE_COVERAGE,
            satisfied=False,
            evidence_ids=[],
            rationale="The alert has no lookup-capable indicator and no evidence id to cite.",
        )
    covering = [item.evidence_id for item in evidence if _TOOL_TYPES.get(item.tool) in present]
    ids = _unique(covering)
    if lookup_coverage_met(alert, evidence) and ids:
        return _factor(
            ConfidenceFactorName.EVIDENCE_COVERAGE,
            satisfied=True,
            evidence_ids=ids,
            rationale="Every lookup-capable indicator type on the alert was looked up.",
        )
    return _factor(
        ConfidenceFactorName.EVIDENCE_COVERAGE,
        satisfied=False,
        evidence_ids=ids,
        rationale="Not every lookup-capable indicator type on the alert was looked up.",
    )


def _reliability_factor(
    evidence: Sequence[Evidence],
    classification: Classification,
) -> ConfidenceFactor:
    supporting = _supporting(evidence, classification)
    ids = _unique(item.evidence_id for item in supporting)
    reliable = bool(supporting) and all(item.reliability in _RELIABLE for item in supporting)
    if reliable and ids:
        return _factor(
            ConfidenceFactorName.SOURCE_RELIABILITY,
            satisfied=True,
            evidence_ids=ids,
            rationale="Supporting evidence is high or medium under tool policy.",
        )
    if not supporting:
        rationale = "No stored field supports the classification."
    else:
        rationale = "Supporting evidence is not high or medium under tool policy."
    return _factor(
        ConfidenceFactorName.SOURCE_RELIABILITY,
        satisfied=False,
        evidence_ids=ids,
        rationale=rationale,
    )


def _corroboration_factor(
    evidence: Sequence[Evidence],
    classification: Classification,
) -> ConfidenceFactor:
    supporting = _supporting(evidence, classification)
    ids = _unique(item.evidence_id for item in supporting)
    providers = {item.source for item in supporting}
    if len(providers) >= 2 and ids:
        return _factor(
            ConfidenceFactorName.CORROBORATION,
            satisfied=True,
            evidence_ids=ids,
            rationale="At least two providers support the classification.",
        )
    return _factor(
        ConfidenceFactorName.CORROBORATION,
        satisfied=False,
        evidence_ids=ids,
        rationale="Fewer than two providers support the classification.",
    )


def _contradiction_factor(
    evidence: Sequence[Evidence],
    classification: Classification,
) -> ConfidenceFactor:
    ids = _opposing_ids(evidence, classification)
    if ids:
        return _factor(
            ConfidenceFactorName.CONTRADICTION_PENALTY,
            satisfied=False,
            evidence_ids=ids,
            rationale="Stored fields contradict the classification.",
        )
    return _factor(
        ConfidenceFactorName.CONTRADICTION_PENALTY,
        satisfied=True,
        evidence_ids=[],
        rationale="No stored field contradicts the classification.",
    )


def _completeness_factor(alert: NormalizedAlert) -> ConfidenceFactor:
    present = any(
        value is not None
        for value in (
            alert.source_ip,
            alert.destination_ip,
            alert.file_hash,
            alert.domain,
            alert.url,
            alert.cve,
        )
    )
    if present:
        rationale = "The alert contains an ip, hash, domain, url, or cve."
    else:
        rationale = "The alert contains none of ip, hash, domain, url, or cve."
    return _factor(
        ConfidenceFactorName.DATA_COMPLETENESS,
        satisfied=present,
        evidence_ids=[],
        rationale=rationale,
    )


def _supporting(evidence: Sequence[Evidence], classification: Classification) -> list[Evidence]:
    if classification is Classification.BENIGN:
        return [item for item in evidence if _supports_benign(item)]
    if classification in {Classification.MALICIOUS, Classification.SUSPICIOUS}:
        return [item for item in evidence if _supports_malicious(item)]
    return list(evidence)


def _opposing_ids(evidence: Sequence[Evidence], classification: Classification) -> list[str]:
    """Evidence that contradicts a definite classification.

    Conflicting rows do not contradict ``INCONCLUSIVE``. That classification is
    how the conflict is recorded.
    """
    if classification is Classification.INCONCLUSIVE:
        return []
    ids: list[str] = []
    for item in evidence:
        benign_opposed = classification is Classification.BENIGN and _supports_malicious(item)
        malicious_opposed = classification is not Classification.BENIGN and _supports_benign(item)
        if benign_opposed or malicious_opposed:
            ids.append(item.evidence_id)
    for contradiction in correlate(evidence).contradictions:
        ids.extend(item.evidence_id for item in contradiction.observations)
    return _unique(ids)


def _present_lookup_types(alert: NormalizedAlert) -> set[IndicatorType]:
    return {kind for kind, _value in indicators_from_alert(alert) if kind in _LOOKUP_TOOLS}


def _looked_up_types(evidence: Sequence[Evidence]) -> set[IndicatorType]:
    found: set[IndicatorType] = set()
    for item in evidence:
        kind = _TOOL_TYPES.get(item.tool)
        if kind is not None:
            found.add(kind)
    return found


def _factor(
    name: ConfidenceFactorName,
    *,
    satisfied: bool,
    evidence_ids: list[str],
    rationale: str,
) -> ConfidenceFactor:
    return ConfidenceFactor(
        name=name,
        weight=FACTOR_WEIGHTS[name],
        satisfied=satisfied,
        evidence_ids=evidence_ids,
        rationale=rationale,
    )


def _unique(ids: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for item in ids:
        if item not in seen:
            seen.append(item)
    return seen
