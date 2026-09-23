"""Choose providers once. ``demo_mode`` is not a failure fallback."""

from dataclasses import dataclass

from sentinel.config.settings import Settings
from sentinel.services.clock import Clock
from sentinel.services.http import HttpTransport
from sentinel.services.providers.abuseipdb import AbuseIpdbIntelligence
from sentinel.services.providers.dns import DnsIntelligence, DomainResolver
from sentinel.services.providers.mitre import MitreAttackCatalog
from sentinel.services.providers.mocks import (
    MockCveIntelligence,
    MockDnsIntelligence,
    MockFileIntelligence,
    MockIpIntelligence,
)
from sentinel.services.providers.osv import OsvIntelligence
from sentinel.services.providers.virustotal import VirusTotalIntelligence
from sentinel.services.threat_intel import (
    CveIntelligence,
    DomainIntelligence,
    FileIntelligence,
    IpIntelligence,
    MitreCatalog,
)


@dataclass(frozen=True, slots=True)
class ProviderSet:
    ip: IpIntelligence
    file: FileIntelligence
    cve: CveIntelligence
    mitre: MitreCatalog
    domain: DomainIntelligence


def build_providers(
    settings: Settings,
    *,
    transport: HttpTransport,
    clock: Clock,
    resolver: DomainResolver,
) -> ProviderSet:
    if settings.demo_mode:
        ip: IpIntelligence = MockIpIntelligence(clock)
        file_intel: FileIntelligence = MockFileIntelligence(clock)
        cve: CveIntelligence = MockCveIntelligence(clock)
        domain: DomainIntelligence = MockDnsIntelligence(clock)
    else:
        ip = AbuseIpdbIntelligence(
            api_key=settings.abuseipdb_api_key,
            transport=transport,
            clock=clock,
            timeout_seconds=settings.provider_timeout_seconds,
        )
        file_intel = VirusTotalIntelligence(
            api_key=settings.virustotal_api_key,
            transport=transport,
            clock=clock,
            timeout_seconds=settings.provider_timeout_seconds,
        )
        cve = OsvIntelligence(
            transport=transport,
            clock=clock,
            timeout_seconds=settings.provider_timeout_seconds,
        )
        domain = DnsIntelligence(
            resolver=resolver,
            clock=clock,
            timeout_seconds=settings.provider_timeout_seconds,
        )
    return ProviderSet(
        ip=ip,
        file=file_intel,
        cve=cve,
        mitre=MitreAttackCatalog(clock=clock),
        domain=domain,
    )
