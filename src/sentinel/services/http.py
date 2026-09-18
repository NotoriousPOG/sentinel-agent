"""Allowlisted HTTPS for threat-intel providers.

Tool arguments and alert text never become the request URL. Each client passes
a URL built from the constants below. Other schemes, hosts, ports, and paths
are rejected before a socket is opened.
"""

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx2

from sentinel.errors import ProviderError

# Hosts a provider client may call. Add a host here only when a tool needs it.
ABUSEIPDB_HOST = "api.abuseipdb.com"
VIRUSTOTAL_HOST = "www.virustotal.com"
OSV_HOST = "api.osv.dev"

ALLOWED_HOSTS = frozenset({ABUSEIPDB_HOST, VIRUSTOTAL_HOST, OSV_HOST})

_ABUSEIPDB_PATH = "/api/v2/check"
_VIRUSTOTAL_PREFIX = "/api/v3/files/"
_OSV_PREFIX = "/v1/vulns/"

# httpx2 debug logs include request headers. The API key lives in a header.
logging.getLogger("httpx2").setLevel(logging.WARNING)
logging.getLogger("httpcore2").setLevel(logging.WARNING)


@dataclass(frozen=True, slots=True)
class HttpResult:
    status_code: int
    body: dict[str, Any] | None


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None,
        timeout_seconds: float,
    ) -> HttpResult:
        """Perform one allowlisted request. Implementations must set a timeout."""
        ...


def enforce_allowlist(url: str) -> None:
    """Reject every destination that is not one of the provider constants."""
    parts = urlsplit(url)
    host = parts.hostname
    if parts.scheme != "https" or host not in ALLOWED_HOSTS:
        raise ProviderError("http", "destination_not_allowed")
    if parts.port not in (None, 443):
        raise ProviderError("http", "destination_not_allowed")
    if parts.username is not None or parts.password is not None:
        raise ProviderError("http", "destination_not_allowed")
    if parts.query or parts.fragment or ".." in parts.path:
        raise ProviderError("http", "destination_not_allowed")
    if not _path_allowed(host, parts.path):
        raise ProviderError("http", "destination_not_allowed")


def _path_allowed(host: str, path: str) -> bool:
    if host == ABUSEIPDB_HOST:
        return path == _ABUSEIPDB_PATH
    if host == VIRUSTOTAL_HOST:
        remainder = path.removeprefix(_VIRUSTOTAL_PREFIX)
        return path.startswith(_VIRUSTOTAL_PREFIX) and remainder != "" and "/" not in remainder
    if host == OSV_HOST:
        remainder = path.removeprefix(_OSV_PREFIX)
        return path.startswith(_OSV_PREFIX) and remainder != "" and "/" not in remainder
    return False


def status_reason(status_code: int) -> str:
    if status_code in {301, 302, 303, 307, 308}:
        return "redirect_rejected"
    if 100 <= status_code <= 599:
        return f"http_{status_code}"
    return "invalid_response"


class HttpxAllowlistTransport:
    """httpx2 client. ``follow_redirects`` is off so a 3xx cannot leave the allowlist."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None,
        timeout_seconds: float,
    ) -> HttpResult:
        enforce_allowlist(url)
        if timeout_seconds <= 0:
            raise ProviderError("http", "timeout")
        try:
            with httpx2.Client(
                timeout=timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.request(
                    method,
                    url,
                    headers=dict(headers),
                    params=None if params is None else dict(params),
                )
        except httpx2.TimeoutException:
            raise ProviderError("http", "timeout") from None
        except httpx2.RequestError:
            raise ProviderError("http", "transport") from None
        if response.status_code != 200:
            return HttpResult(status_code=response.status_code, body=None)
        try:
            parsed = response.json()
        except ValueError:
            raise ProviderError("http", "invalid_response") from None
        if not isinstance(parsed, dict):
            raise ProviderError("http", "invalid_response")
        return HttpResult(status_code=response.status_code, body=parsed)
