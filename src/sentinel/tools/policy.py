"""Reliability is a property of the provider, not of text in its body."""

from sentinel.schemas.evidence import EvidenceReliability

_POLICY: dict[str, EvidenceReliability] = {
    "abuseipdb": EvidenceReliability.MEDIUM,
    "virustotal": EvidenceReliability.MEDIUM,
    "osv": EvidenceReliability.HIGH,
    "mitre-attack": EvidenceReliability.HIGH,
    "dns": EvidenceReliability.LOW,
}


def reliability_for_provider(provider: str) -> EvidenceReliability:
    """Map a provider name to a reliability.

    Names that start with ``mock:`` are low: the result is synthetic. Any other
    unrecognized name is unknown. The function does not read a provider body.
    """
    if provider.startswith("mock:"):
        return EvidenceReliability.LOW
    return _POLICY.get(provider, EvidenceReliability.UNKNOWN)
