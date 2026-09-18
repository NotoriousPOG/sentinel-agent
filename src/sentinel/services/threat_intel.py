"""Threat-intelligence ports.

A vendor implements the protocols it can actually serve. No adapter is included.
Keys are never arguments of these methods; a later client reads ``SecretStr``
settings itself and must not copy them into ``raw``.
"""

from typing import Protocol

from sentinel.schemas.tools import (
    LookupCveInput,
    LookupCveOutput,
    LookupDomainInput,
    LookupDomainOutput,
    LookupHashInput,
    LookupHashOutput,
    LookupIpInput,
    LookupIpOutput,
    SearchMitreInput,
    SearchMitreOutput,
)


class IpIntelligence(Protocol):
    name: str

    def lookup_ip(self, query: LookupIpInput) -> LookupIpOutput:
        """Look up an IP. No implementation ships in milestone 1."""
        ...


class FileIntelligence(Protocol):
    name: str

    def lookup_hash(self, query: LookupHashInput) -> LookupHashOutput:
        """Look up a file hash. No implementation ships in milestone 1."""
        ...


class CveIntelligence(Protocol):
    name: str

    def lookup_cve(self, query: LookupCveInput) -> LookupCveOutput:
        """Look up a CVE. No implementation ships in milestone 1."""
        ...


class MitreCatalog(Protocol):
    name: str

    def search_mitre(self, query: SearchMitreInput) -> SearchMitreOutput:
        """Search MITRE ATT&CK. No implementation ships in milestone 1."""
        ...


class DomainIntelligence(Protocol):
    name: str

    def lookup_domain(self, query: LookupDomainInput) -> LookupDomainOutput:
        """Look up a domain. No implementation ships in milestone 1."""
        ...
