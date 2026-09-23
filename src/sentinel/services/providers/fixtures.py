"""Labeled synthetic intelligence for ``demo_mode``.

These rows are not live threat intelligence. An IP or hash that is not listed
stays unknown (null verdict fields). An unlisted domain fails closed. CVE
lookups without a fixture return an empty record, not a severity.
"""

from __future__ import annotations

from dataclasses import dataclass

LABEL = "SYNTHETIC MOCK — not live intelligence"

# Documentation-range addresses (RFC 5737) and synthetic digests used by
# examples/ and evals/. AS64512 is from the private ASN block, not a real ISP.
_DEMO_SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
_EVAL_SHA256 = "abababababababababababababababababababababababababababababababab"


@dataclass(frozen=True, slots=True)
class IpFixture:
    reported_malicious: bool
    categories: tuple[str, ...]
    asn: str | None
    country: str | None
    organization: str | None


@dataclass(frozen=True, slots=True)
class HashFixture:
    malicious_count: int
    harmless_count: int
    undetected_count: int


@dataclass(frozen=True, slots=True)
class CveFixture:
    description: str
    references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DomainFixture:
    resolved_ips: tuple[str, ...]
    reported_malicious: bool | None


IP_FIXTURES: dict[str, IpFixture] = {
    "198.51.100.23": IpFixture(
        reported_malicious=True,
        categories=("synthetic-scanning",),
        asn="AS64512",
        country="ZZ",
        organization="RFC 5737 documentation range",
    ),
    "192.0.2.50": IpFixture(
        reported_malicious=True,
        categories=("synthetic-password-guessing",),
        asn="AS64512",
        country="ZZ",
        organization="RFC 5737 documentation range",
    ),
    "203.0.113.10": IpFixture(
        reported_malicious=False,
        categories=("synthetic-jump-host",),
        asn="AS64512",
        country="ZZ",
        organization="RFC 5737 documentation range",
    ),
    "203.0.113.44": IpFixture(
        reported_malicious=True,
        categories=("synthetic-password-guessing",),
        asn="AS64512",
        country="ZZ",
        organization="RFC 5737 documentation range",
    ),
}

HASH_FIXTURES: dict[str, HashFixture] = {
    _DEMO_SHA256: HashFixture(malicious_count=8, harmless_count=0, undetected_count=20),
    _EVAL_SHA256: HashFixture(malicious_count=12, harmless_count=1, undetected_count=40),
}

CVE_FIXTURES: dict[str, CveFixture] = {
    "CVE-2021-44228": CveFixture(
        description=(
            "Synthetic fixture for the public Log4Shell identifier. "
            "This text was not fetched from NVD or OSV. cvss_score stays unknown."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2021-44228",),
    ),
}

DOMAIN_FIXTURES: dict[str, DomainFixture] = {
    "login.example": DomainFixture(
        resolved_ips=("203.0.113.80",),
        reported_malicious=None,
    ),
}


def ip_fixture(ip: str) -> IpFixture | None:
    return IP_FIXTURES.get(ip)


def hash_fixture(digest: str) -> HashFixture | None:
    return HASH_FIXTURES.get(digest.casefold())


def cve_fixture(cve_id: str) -> CveFixture | None:
    return CVE_FIXTURES.get(cve_id.upper())


def domain_fixture(domain: str) -> DomainFixture | None:
    return DOMAIN_FIXTURES.get(domain.casefold())
