"""OSV vulnerability lookup.

``GET https://api.osv.dev/v1/vulns/{id}`` as documented at
https://google.github.io/osv.dev/get-v1-vulns/. No API key.

OSV ``severity[].score`` is a CVSS vector string, not a numeric base score
(https://ossf.github.io/osv-schema/). ``cvss_score`` and ``cvss_version`` stay
unknown. Reference URLs are stored and not fetched.
"""

from typing import Any
from urllib.parse import quote

from sentinel.errors import ProviderError
from sentinel.schemas.patterns import CVE_RE
from sentinel.schemas.tools import LookupCveInput, LookupCveOutput
from sentinel.services.clock import Clock
from sentinel.services.http import OSV_HOST, HttpTransport
from sentinel.services.providers.common import log_failure, log_ok, request_json

OSV_VULNS_PREFIX = f"https://{OSV_HOST}/v1/vulns/"


class OsvIntelligence:
    name = "osv"

    def __init__(
        self,
        *,
        transport: HttpTransport,
        clock: Clock,
        timeout_seconds: float,
    ) -> None:
        self._transport = transport
        self._clock = clock
        self._timeout = timeout_seconds

    def lookup_cve(self, query: LookupCveInput) -> LookupCveOutput:
        if not CVE_RE.fullmatch(query.cve_id):
            log_failure(self.name, "invalid_query")
            raise ProviderError(self.name, "invalid_query")
        body = request_json(
            self._transport,
            provider=self.name,
            method="GET",
            url=f"{OSV_VULNS_PREFIX}{quote(query.cve_id, safe='')}",
            headers={"Accept": "application/json"},
            params=None,
            timeout_seconds=self._timeout,
            secret=None,
        )
        if not isinstance(body.get("id"), str):
            log_failure(self.name, "invalid_response")
            raise ProviderError(self.name, "invalid_response")
        log_ok(self.name)
        return LookupCveOutput(
            cve_id=query.cve_id,
            provider=self.name,
            description=_description(body),
            cvss_score=None,
            cvss_version=None,
            references=_references(body),
            raw=body,
            retrieved_at=self._clock.now(),
        )


def _description(body: dict[str, Any]) -> str | None:
    for key in ("details", "summary"):
        value = body.get(key)
        if isinstance(value, str) and value.strip():
            return value[:8000]
    return None


def _references(body: dict[str, Any]) -> list[str]:
    items = body.get("references")
    if not isinstance(items, list):
        return []
    urls: list[str] = []
    for item in items:
        if len(urls) >= 50:
            break
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if isinstance(url, str) and url:
            urls.append(url[:2048])
    return urls
