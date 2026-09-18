"""Synthetic providers. Selected only when ``demo_mode`` is on.

Results are labeled and are not live intelligence. A failed live call must
not construct these classes as a fallback; ``build_providers`` chooses once.
"""

from sentinel.schemas.tools import (
    LookupHashInput,
    LookupHashOutput,
    LookupIpInput,
    LookupIpOutput,
)
from sentinel.services.clock import Clock

_LABEL = "SYNTHETIC MOCK — not live intelligence"


class MockIpIntelligence:
    name = "mock:abuseipdb"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def lookup_ip(self, query: LookupIpInput) -> LookupIpOutput:
        return LookupIpOutput(
            ip=str(query.ip),
            provider=self.name,
            categories=["synthetic-demo"],
            reported_malicious=None,
            reference_ids=["synthetic-not-live"],
            raw={"synthetic": True, "label": _LABEL},
            retrieved_at=self._clock.now(),
        )


class MockFileIntelligence:
    name = "mock:virustotal"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def lookup_hash(self, query: LookupHashInput) -> LookupHashOutput:
        return LookupHashOutput(
            file_hash=query.file_hash,
            algorithm=query.algorithm,
            provider=self.name,
            malicious_count=None,
            harmless_count=None,
            undetected_count=None,
            raw={"synthetic": True, "label": _LABEL, "last_analysis_stats": None},
            retrieved_at=self._clock.now(),
        )
