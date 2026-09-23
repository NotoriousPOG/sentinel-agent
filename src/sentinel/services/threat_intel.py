"""Threat-intelligence ports.

A vendor implements the protocols it can actually serve. Concrete clients live
in ``sentinel.services.providers`` and are not imported here, so importing this
module does not construct a client or select a mock.
Keys are never arguments of these methods. A client reads ``SecretStr``
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
        """Look up an IP. Missing credentials raise; they do not return a verdict."""
        ...


class FileIntelligence(Protocol):
    name: str

    def lookup_hash(self, query: LookupHashInput) -> LookupHashOutput:
        """Look up a file hash. A transport failure is an error, not a zero count."""
        ...


class CveIntelligence(Protocol):
    name: str

    def lookup_cve(self, query: LookupCveInput) -> LookupCveOutput:
        """Look up a CVE. Absent fields stay unknown; they are not filled in."""
        ...


class MitreCatalog(Protocol):
    name: str

    def search_mitre(self, query: SearchMitreInput) -> SearchMitreOutput:
        """Search the vendored ATT&CK extract. This does not download a bundle."""
        ...


class DomainIntelligence(Protocol):
    name: str

    def lookup_domain(self, query: LookupDomainInput) -> LookupDomainOutput:
        """Resolve a domain. This must not fetch the domain over HTTP."""
        ...
