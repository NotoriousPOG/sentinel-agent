"""Shared validators for indicator-shaped strings.

These check shape only. They do not resolve DNS, fetch URLs, or score reputation.
"""

import ipaddress
import re

HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}\Z){_LABEL}(?:\.{_LABEL})*\Z", re.IGNORECASE)
TOOL_CALL_KEY_RE = re.compile(r"^[0-9a-f]{64}$")


def normalize_hash(value: str) -> str:
    normalized = value.strip().lower()
    if not HASH_RE.fullmatch(normalized):
        raise ValueError("hash must be md5, sha1, or sha256 hexadecimal")
    return normalized


def normalize_cve(value: str) -> str:
    normalized = value.strip().upper()
    if not CVE_RE.fullmatch(normalized):
        raise ValueError("cve must look like CVE-2024-12345")
    return normalized


def normalize_domain(value: str) -> str:
    """Accept a DNS name. Reject URLs, paths, and IP addresses."""
    normalized = value.strip().rstrip(".").lower()
    if "://" in normalized or "/" in normalized or " " in normalized:
        raise ValueError("domain must be a DNS name, not a URL")
    if not DOMAIN_RE.fullmatch(normalized):
        raise ValueError("domain must be a DNS name")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return normalized
    raise ValueError("domain must not be an IP address")


def normalize_technique_id(value: str) -> str:
    if not TECHNIQUE_RE.fullmatch(value):
        raise ValueError("technique_id must look like T1059 or T1059.001")
    return value
