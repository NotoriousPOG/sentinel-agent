"""Synthetic providers. Selected only when ``demo_mode`` is on.

Results are labeled and are not live intelligence. A failed live call must
not construct these classes as a fallback; ``build_providers`` chooses once.
Listed fixture indicators carry canned verdicts. Anything else stays unknown
or, for DNS, fails closed.
"""

from sentinel.errors import ProviderError
from sentinel.schemas.tools import (
    LookupCveInput,
    LookupCveOutput,
    LookupDomainInput,
    LookupDomainOutput,
    LookupHashInput,
    LookupHashOutput,
    LookupIpInput,
    LookupIpOutput,
)
from sentinel.services.clock import Clock
from sentinel.services.providers.fixtures import (
    LABEL,
    cve_fixture,
    domain_fixture,
    hash_fixture,
    ip_fixture,
)


class MockIpIntelligence:
    name = "mock:abuseipdb"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def lookup_ip(self, query: LookupIpInput) -> LookupIpOutput:
        fixture = ip_fixture(str(query.ip))
        if fixture is None:
            return LookupIpOutput(
                ip=str(query.ip),
                provider=self.name,
                categories=["synthetic-demo"],
                reported_malicious=None,
                reference_ids=["synthetic-not-live"],
                raw={"synthetic": True, "label": LABEL, "fixture": False},
                retrieved_at=self._clock.now(),
            )
        return LookupIpOutput(
            ip=str(query.ip),
            provider=self.name,
            categories=list(fixture.categories),
            reported_malicious=fixture.reported_malicious,
            asn=fixture.asn,
            country=fixture.country,
            organization=fixture.organization,
            reference_ids=["synthetic-fixture"],
            raw={"synthetic": True, "label": LABEL, "fixture": True},
            retrieved_at=self._clock.now(),
        )


class MockFileIntelligence:
    name = "mock:virustotal"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def lookup_hash(self, query: LookupHashInput) -> LookupHashOutput:
        fixture = hash_fixture(query.file_hash)
        if fixture is None:
            return LookupHashOutput(
                file_hash=query.file_hash,
                algorithm=query.algorithm,
                provider=self.name,
                malicious_count=None,
                harmless_count=None,
                undetected_count=None,
                raw={
                    "synthetic": True,
                    "label": LABEL,
                    "fixture": False,
                    "last_analysis_stats": None,
                },
                retrieved_at=self._clock.now(),
            )
        return LookupHashOutput(
            file_hash=query.file_hash,
            algorithm=query.algorithm,
            provider=self.name,
            malicious_count=fixture.malicious_count,
            harmless_count=fixture.harmless_count,
            undetected_count=fixture.undetected_count,
            raw={"synthetic": True, "label": LABEL, "fixture": True},
            retrieved_at=self._clock.now(),
        )


class MockCveIntelligence:
    name = "mock:osv"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def lookup_cve(self, query: LookupCveInput) -> LookupCveOutput:
        fixture = cve_fixture(query.cve_id)
        if fixture is None:
            return LookupCveOutput(
                cve_id=query.cve_id,
                provider=self.name,
                description=None,
                cvss_score=None,
                cvss_version=None,
                references=[],
                raw={"synthetic": True, "label": LABEL, "fixture": False},
                retrieved_at=self._clock.now(),
            )
        return LookupCveOutput(
            cve_id=query.cve_id,
            provider=self.name,
            description=fixture.description,
            cvss_score=None,
            cvss_version=None,
            references=list(fixture.references),
            raw={"synthetic": True, "label": LABEL, "fixture": True},
            retrieved_at=self._clock.now(),
        )


class MockDnsIntelligence:
    name = "mock:dns"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def lookup_domain(self, query: LookupDomainInput) -> LookupDomainOutput:
        fixture = domain_fixture(query.domain)
        if fixture is None:
            raise ProviderError(self.name, "resolution_failed")
        return LookupDomainOutput(
            domain=query.domain,
            provider=self.name,
            resolved_ips=list(fixture.resolved_ips),
            reported_malicious=fixture.reported_malicious,
            raw={"synthetic": True, "label": LABEL, "fixture": True},
            retrieved_at=self._clock.now(),
        )
