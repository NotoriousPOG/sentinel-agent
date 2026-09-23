"""Check a report against an alert and collected tool output.

The report is built by the caller. This module does not call a model and does
not score ``weighted_evidence_v1``. A MITRE id is accepted only when a cited
``search_mitre`` result contains it and the id is in the local ATT&CK subset.
"""

from collections.abc import Sequence
from datetime import datetime

from sentinel.agents.transitions import transition
from sentinel.evidence.correlate import correlate
from sentinel.evidence.indicators import (
    canonical_indicator,
    known_indicators,
    mentions,
)
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.correlation import Contradiction, JsonScalar
from sentinel.schemas.evidence import Evidence
from sentinel.schemas.investigation import InvestigationState, InvestigationStatus
from sentinel.schemas.reports import Classification, IncidentReport, MitreTechniqueRef
from sentinel.schemas.timestamps import require_aware
from sentinel.schemas.verification import (
    FailedLookup,
    Statement,
    VerificationIssue,
    VerificationResult,
)
from sentinel.services.providers.mitre import official_technique, technique_ids_in_result
from sentinel.tools.policy import reliability_for_provider

# Fields a fact may cite. ``raw`` is intentionally absent. Reliability is not here.
_STORED_FIELDS: dict[str, frozenset[str]] = {
    "lookup_ip": frozenset(
        {
            "ip",
            "provider",
            "categories",
            "reported_malicious",
            "asn",
            "country",
            "organization",
            "reference_ids",
        }
    ),
    "lookup_hash": frozenset(
        {
            "file_hash",
            "algorithm",
            "provider",
            "malicious_count",
            "harmless_count",
            "undetected_count",
        }
    ),
    "lookup_cve": frozenset(
        {"cve_id", "provider", "description", "cvss_score", "cvss_version", "references"}
    ),
    "search_mitre": frozenset({"query", "provider", "techniques"}),
    "lookup_domain": frozenset({"domain", "provider", "resolved_ips", "reported_malicious"}),
}


def verify_report(
    report: IncidentReport,
    *,
    alert: NormalizedAlert,
    evidence: Sequence[Evidence],
    statements: Sequence[Statement] = (),
    failed_lookups: Sequence[FailedLookup] = (),
) -> VerificationResult:
    """Accept the report only when its claims stay inside collected fields.

    Unknown stays unknown. A failed lookup is not benign. Absence of a hit is
    not a benign verdict. Conflicting values are returned as contradictions.
    """
    collected = list(evidence)
    by_id = {item.evidence_id: item for item in collected}
    linked = correlate(collected)
    issues: list[VerificationIssue] = []
    _extend(issues, _unknown_indicators(report, alert, collected))
    _extend(issues, _record_issues(report, by_id))
    _extend(issues, _mitre_issues(report, by_id))
    _extend(issues, _reliability_issues([*report.evidence, *collected]))
    _extend(
        issues, _classification_issues(report, collected, failed_lookups, linked.contradictions)
    )
    _extend(issues, _statement_issues(statements, by_id))
    return VerificationResult(
        accepted=not issues,
        issues=issues,
        contradictions=linked.contradictions,
    )


def apply_verification(
    state: InvestigationState,
    result: VerificationResult,
    *,
    now: datetime,
) -> InvestigationState:
    """Record ``result`` without leaving ``VERIFYING`` unless retries are spent.

    A pass stays ``VERIFYING``. A failure calls ``transition`` to ``FAILED``
    only when ``retries >= max_retries``. This does not return to
    ``INVESTIGATING`` and does not enter ``AWAITING_REVIEW`` or ``COMPLETE``.
    """
    if state.status is not InvestigationStatus.VERIFYING:
        raise ValueError("verification applies to a VERIFYING investigation")
    instant = require_aware(now)
    recorded = state.model_copy(update={"verification": result, "updated_at": instant})
    if result.accepted:
        return recorded
    message = _failure_message(result)
    if state.retries >= state.max_retries:
        return transition(recorded, InvestigationStatus.FAILED, now=instant, error=message)
    return recorded.model_copy(update={"error": message})


def _unknown_indicators(
    report: IncidentReport,
    alert: NormalizedAlert,
    evidence: Sequence[Evidence],
) -> list[VerificationIssue]:
    known = known_indicators(alert, evidence)
    ignore = {item.evidence_id for item in evidence}
    ignore.update(item.evidence_id for item in report.evidence)
    issues: list[VerificationIssue] = []
    texts = [report.executive_summary, report.analyst_notes]
    texts.extend(event.description for event in report.timeline)
    for text in texts:
        for kind, value in mentions(text, ignore_hashes=ignore):
            if (kind, value) not in known:
                issues.append(_issue("unknown_indicator", _absent(kind.value, value)))
    for indicator in report.indicators:
        key = canonical_indicator(indicator.type, indicator.value)
        label = indicator.type.value
        shown = indicator.value if key is None else key[1]
        if key is None or key not in known:
            issues.append(_issue("unknown_indicator", _absent(label, shown)))
    return issues


def _record_issues(
    report: IncidentReport,
    by_id: dict[str, Evidence],
) -> list[VerificationIssue]:
    issues: list[VerificationIssue] = []
    for item in report.evidence:
        stored = by_id.get(item.evidence_id)
        if stored is None:
            issues.append(
                _issue("dangling_citation", f"evidence id {item.evidence_id} was not collected")
            )
            continue
        if not _same_record(stored, item):
            issues.append(
                _issue(
                    "evidence_mismatch",
                    f"evidence id {item.evidence_id} does not match the collected tool output",
                )
            )
    return issues


def _mitre_issues(
    report: IncidentReport,
    by_id: dict[str, Evidence],
) -> list[VerificationIssue]:
    issues: list[VerificationIssue] = []
    for technique in report.mitre_attack:
        if official_technique(technique.technique_id) is None:
            issues.append(
                _issue(
                    "unknown_technique",
                    f"technique {technique.technique_id} is not in the Enterprise ATT&CK subset",
                )
            )
            continue
        if not _technique_cited(technique, by_id):
            issues.append(
                _issue(
                    "technique_not_in_evidence",
                    f"technique {technique.technique_id} is not in a cited search_mitre result",
                )
            )
    return issues


def _technique_cited(technique: MitreTechniqueRef, by_id: dict[str, Evidence]) -> bool:
    for evidence_id in technique.evidence_ids:
        item = by_id.get(evidence_id)
        if item is None or item.tool != "search_mitre":
            continue
        if technique.technique_id in technique_ids_in_result(item.result):
            return True
    return False


def _reliability_issues(items: Sequence[Evidence]) -> list[VerificationIssue]:
    issues: list[VerificationIssue] = []
    for item in items:
        expected = reliability_for_provider(item.source)
        if item.reliability is not expected:
            issues.append(
                _issue(
                    "reliability_not_from_policy",
                    f"{item.evidence_id} reliability is {item.reliability.value}, "
                    f"policy for {item.source} is {expected.value}",
                )
            )
    return issues


def _classification_issues(
    report: IncidentReport,
    evidence: Sequence[Evidence],
    failed_lookups: Sequence[FailedLookup],
    contradictions: Sequence[Contradiction],
) -> list[VerificationIssue]:
    issues: list[VerificationIssue] = []
    kind = report.classification
    benign = any(_supports_benign(item) for item in evidence)
    malicious = any(_supports_malicious(item) for item in evidence)
    if kind is Classification.BENIGN:
        if not benign:
            issues.append(_issue("unknown_not_benign", "no stored field supports a benign verdict"))
        if failed_lookups and not benign:
            issues.append(
                _issue("failed_lookup_not_benign", "a failed lookup is not a benign result")
            )
    elif kind is not Classification.INCONCLUSIVE and not malicious:
        issues.append(
            _issue(
                "unsupported_classification",
                f"{kind.value} is not supported by a stored verdict field",
            )
        )
    present = {item.evidence_id for item in report.evidence}
    dropped = False
    for contradiction in contradictions:
        ids = [item.evidence_id for item in contradiction.observations]
        if any(evidence_id not in present for evidence_id in ids):
            dropped = True
    if dropped:
        issues.append(
            _issue("contradiction_dropped", "contradicting evidence is missing from the report")
        )
    if contradictions and kind is not Classification.INCONCLUSIVE:
        issues.append(
            _issue(
                "contradiction_ignored",
                "conflicting intelligence cannot be collapsed into one verdict",
            )
        )
    return issues


def _statement_issues(
    statements: Sequence[Statement],
    by_id: dict[str, Evidence],
) -> list[VerificationIssue]:
    issues: list[VerificationIssue] = []
    for statement in statements:
        missing = [item for item in statement.evidence_ids if item not in by_id]
        if missing:
            issues.append(
                _issue("dangling_citation", f"evidence id {missing[0]} was not collected")
            )
            continue
        if statement.presented_as == "inference":
            continue
        field = statement.field or ""
        if not _field_allowed(field):
            issues.append(
                _issue("not_a_stored_field", f"{field or 'missing'} is not a tool output field")
            )
            continue
        cited = [by_id[item] for item in statement.evidence_ids]
        if not any(_field_equals(item, field, statement.value) for item in cited):
            issues.append(
                _issue("unsupported_fact", f"no evidence field {field} supports that value")
            )
    return issues


def _supports_malicious(item: Evidence) -> bool:
    if item.tool in {"lookup_ip", "lookup_domain"}:
        return item.result.get("reported_malicious") is True
    if item.tool == "lookup_hash":
        count = item.result.get("malicious_count")
        return isinstance(count, int) and not isinstance(count, bool) and count > 0
    return False


def _supports_benign(item: Evidence) -> bool:
    """A stored false verdict. Missing counts and ``null`` are not false."""
    if item.tool in {"lookup_ip", "lookup_domain"}:
        return item.result.get("reported_malicious") is False
    if item.tool == "lookup_hash":
        malicious = item.result.get("malicious_count")
        harmless = item.result.get("harmless_count")
        return (
            isinstance(malicious, int)
            and not isinstance(malicious, bool)
            and malicious == 0
            and isinstance(harmless, int)
            and not isinstance(harmless, bool)
            and harmless > 0
        )
    return False


def _field_allowed(field: str) -> bool:
    if not field or field == "raw" or field.startswith("raw.") or field.startswith("raw["):
        return False
    return any(field in names for names in _STORED_FIELDS.values())


def _field_equals(item: Evidence, field: str, value: JsonScalar) -> bool:
    names = _STORED_FIELDS.get(item.tool)
    if names is None or field not in names or field not in item.result:
        return False
    stored = item.result[field]
    if isinstance(value, bool) or value is None:
        return stored is value
    if isinstance(value, int) and not isinstance(stored, bool) and isinstance(stored, int):
        return stored == value
    if (
        isinstance(value, float)
        and not isinstance(stored, bool)
        and isinstance(stored, int | float)
    ):
        return float(stored) == value
    if isinstance(value, str) and isinstance(stored, str):
        return stored == value
    return False


def _same_record(stored: Evidence, reported: Evidence) -> bool:
    return (
        stored.tool == reported.tool
        and stored.source == reported.source
        and stored.query == reported.query
        and stored.result == reported.result
    )


def _extend(issues: list[VerificationIssue], more: list[VerificationIssue]) -> None:
    for issue in more:
        if issue not in issues:
            issues.append(issue)


def _issue(code: str, detail: str) -> VerificationIssue:
    text = detail.strip()[:500] or code
    return VerificationIssue(code=code, detail=text)


def _absent(kind: str, value: str) -> str:
    shown = value.strip()[:180]
    return f"{kind} {shown} is absent from the alert and the evidence"


def _failure_message(result: VerificationResult) -> str:
    codes = ", ".join(issue.code for issue in result.issues) or "rejected"
    return f"verification failed: {codes}"[:2000]
