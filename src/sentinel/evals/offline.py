"""In-process stand-ins so the eval runner does not open a socket.

With ``demo_mode`` on, IP, hash, CVE, and DNS use mock providers. The
transport and resolver below stay injected as a second offline guard: if
``demo_mode`` is accidentally off, CVE still cannot download OSV and DNS
still does not call ``getaddrinfo``.
"""

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from sentinel.errors import ProviderError
from sentinel.services.http import HttpResult
from sentinel.services.providers.osv import OSV_VULNS_PREFIX

# Public id. The body is a fixture. It is not an OSV download.
INJECTED_CVE_ID = "CVE-2021-44228"


class OfflineTransport:
    """Return one injected OSV body. Any other URL is refused locally."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None,
        timeout_seconds: float,
    ) -> HttpResult:
        del method, headers, params, timeout_seconds
        self.urls.append(url)
        if url != injected_osv_url():
            raise ProviderError("http", "offline_eval_refused")
        return HttpResult(status_code=200, body=injected_osv_body())


class FailingResolver:
    """A domain lookup that fails in process. It does not call ``getaddrinfo``."""

    def __init__(self) -> None:
        self.domains: list[str] = []

    def resolve(self, domain: str, *, timeout_seconds: float) -> list[str]:
        del timeout_seconds
        self.domains.append(domain)
        raise ProviderError("dns", "resolution_failed")


def injected_osv_url() -> str:
    return f"{OSV_VULNS_PREFIX}{quote(INJECTED_CVE_ID, safe='')}"


def injected_osv_body() -> dict[str, Any]:
    return {
        "id": INJECTED_CVE_ID,
        "summary": "Injected fixture. Not a live OSV response.",
        "details": (
            "Synthetic transport body for the public id CVE-2021-44228. "
            "This text was not fetched from OSV."
        ),
    }
