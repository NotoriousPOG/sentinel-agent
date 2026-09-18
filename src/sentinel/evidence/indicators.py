"""Indicator identity taken from structured fields. ``raw`` is not read."""

import ipaddress
import re
from collections.abc import Sequence
from typing import Any

from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.evidence import Evidence
from sentinel.schemas.patterns import normalize_cve, normalize_domain, normalize_hash
from sentinel.schemas.reports import IndicatorType

IndicatorKey = tuple[IndicatorType, str]

_URL = re.compile(r"https?://[^\s<>'\"]+")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_HASH = re.compile(r"\b(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b", re.IGNORECASE)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)
_FILE_SUFFIXES = frozenset(
    {
        "csv",
        "doc",
        "docx",
        "gif",
        "gz",
        "html",
        "jpeg",
        "jpg",
        "json",
        "log",
        "md",
        "pdf",
        "png",
        "ppt",
        "pptx",
        "py",
        "tar",
        "txt",
        "xls",
        "xlsx",
        "xml",
        "yaml",
        "yml",
        "zip",
    }
)


def canonical_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        return None


def indicators_from_alert(alert: NormalizedAlert) -> set[IndicatorKey]:
    found: set[IndicatorKey] = set()
    _add_ip(found, None if alert.source_ip is None else str(alert.source_ip))
    _add_ip(found, None if alert.destination_ip is None else str(alert.destination_ip))
    _add_domain(found, alert.domain)
    _add_hash(found, alert.file_hash)
    _add_cve(found, alert.cve)
    if alert.hostname:
        found.add((IndicatorType.HOSTNAME, alert.hostname.strip().lower()))
    if alert.username:
        found.add((IndicatorType.USER, alert.username.strip()))
    if alert.process:
        found.add((IndicatorType.PROCESS, alert.process.strip()))
    if alert.url is not None:
        _add_url(found, str(alert.url))
    return found


def indicators_from_evidence(item: Evidence) -> list[IndicatorKey]:
    """Structured query and result fields only. ``raw`` and prose fields are skipped."""
    found: set[IndicatorKey] = set()
    _take_mapping(found, item.query)
    _take_mapping(found, item.result)
    return sorted(found, key=lambda pair: (pair[0].value, pair[1]))


def known_indicators(alert: NormalizedAlert, evidence: Sequence[Evidence]) -> set[IndicatorKey]:
    found = indicators_from_alert(alert)
    for item in evidence:
        found.update(indicators_from_evidence(item))
    return found


def mentions(text: str, *, ignore_hashes: set[str]) -> set[IndicatorKey]:
    """Indicators named in prose. File suffixes such as ``notes.md`` are not domains."""
    found: set[IndicatorKey] = set()
    spans: list[tuple[int, int]] = []
    for match in _URL.finditer(text):
        spans.append((match.start(), match.end()))
        _add_url(found, match.group(0))
    masked = _mask(text, spans)
    ip_spans: list[tuple[int, int]] = []
    for match in _IPV4.finditer(masked):
        if _add_ip(found, match.group(0)):
            ip_spans.append((match.start(), match.end()))
    for token in re.findall(r"[0-9a-f:]{2,}", masked, flags=re.IGNORECASE):
        parsed = canonical_ip(token)
        if parsed is not None and ":" in parsed:
            found.add((IndicatorType.IP, parsed))
    masked = _mask(masked, ip_spans)
    for match in _CVE.finditer(masked):
        _add_cve(found, match.group(0))
    ignored = {item.lower() for item in ignore_hashes}
    for match in _HASH.finditer(masked):
        digest = match.group(0).lower()
        if digest in ignored:
            continue
        _add_hash(found, digest)
    for match in _DOMAIN.finditer(masked):
        _add_domain(found, match.group(0))
    return found


def canonical_indicator(kind: IndicatorType, value: str) -> IndicatorKey | None:
    if kind is IndicatorType.IP:
        ip = canonical_ip(value)
        if ip is None:
            return None
        return (kind, ip)
    if kind is IndicatorType.DOMAIN:
        domain = _domain_value(value)
        if domain is None:
            return None
        return (kind, domain)
    if kind is IndicatorType.HASH:
        try:
            return (kind, normalize_hash(value))
        except ValueError:
            return None
    if kind is IndicatorType.CVE:
        try:
            return (kind, normalize_cve(value))
        except ValueError:
            return None
    if kind is IndicatorType.URL:
        text = value.strip().rstrip("/")
        if not text:
            return None
        return (kind, text)
    if kind is IndicatorType.HOSTNAME:
        text = value.strip().lower()
        if not text:
            return None
        return (kind, text)
    text = value.strip()
    if not text:
        return None
    return (kind, text)


def _take_mapping(found: set[IndicatorKey], payload: dict[str, Any]) -> None:
    _add_ip(found, payload.get("ip"))
    for item in _strings(payload.get("resolved_ips")):
        _add_ip(found, item)
    _add_domain(found, payload.get("domain"))
    _add_hash(found, payload.get("file_hash"))
    _add_cve(found, payload.get("cve_id"))
    _add_cve(found, payload.get("cve"))
    _add_url(found, payload.get("url"))
    for ref in _strings(payload.get("reference_ids")):
        _add_parsed(found, ref)
    for ref in _strings(payload.get("references")):
        _add_parsed(found, ref)


def _add_parsed(found: set[IndicatorKey], value: str) -> None:
    if _add_ip(found, value):
        return
    if _add_cve(found, value):
        return
    if _add_hash(found, value):
        return
    if "://" in value:
        _add_url(found, value)
        return
    _add_domain(found, value)


def _add_ip(found: set[IndicatorKey], value: object) -> bool:
    ip = canonical_ip(value)
    if ip is None:
        return False
    found.add((IndicatorType.IP, ip))
    return True


def _add_domain(found: set[IndicatorKey], value: object) -> bool:
    if not isinstance(value, str):
        return False
    domain = _domain_value(value)
    if domain is None:
        return False
    found.add((IndicatorType.DOMAIN, domain))
    return True


def _domain_value(value: str) -> str | None:
    if "." not in value:
        return None
    try:
        normalized = normalize_domain(value)
    except ValueError:
        return None
    suffix = normalized.rsplit(".", 1)[-1]
    if suffix in _FILE_SUFFIXES:
        return None
    return normalized


def _add_hash(found: set[IndicatorKey], value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        found.add((IndicatorType.HASH, normalize_hash(value)))
    except ValueError:
        return False
    return True


def _add_cve(found: set[IndicatorKey], value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        found.add((IndicatorType.CVE, normalize_cve(value)))
    except ValueError:
        return False
    return True


def _add_url(found: set[IndicatorKey], value: object) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip().rstrip(".,);]").rstrip("/")
    if "://" not in text:
        return False
    found.add((IndicatorType.URL, text))
    return True


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def _mask(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        for index in range(max(start, 0), min(end, len(chars))):
            chars[index] = " "
    return "".join(chars)
