"""VirusTotal API v3 file report.

``GET /api/v3/files/{id}`` as documented at
https://docs.virustotal.com/reference/file-info. The key is the ``x-apikey``
header. Counts come only from ``data.attributes.last_analysis_stats``. A
missing stat stays unknown; it is not stored as zero.
"""

from typing import Any
from urllib.parse import quote

from pydantic import SecretStr

from sentinel.errors import ProviderError
from sentinel.schemas.patterns import HASH_RE
from sentinel.schemas.tools import LookupHashInput, LookupHashOutput
from sentinel.services.clock import Clock
from sentinel.services.http import VIRUSTOTAL_HOST, HttpTransport
from sentinel.services.providers.common import log_failure, log_ok, request_json, require_api_key

VIRUSTOTAL_FILES_PREFIX = f"https://{VIRUSTOTAL_HOST}/api/v3/files/"


class VirusTotalIntelligence:
    name = "virustotal"

    def __init__(
        self,
        *,
        api_key: SecretStr | None,
        transport: HttpTransport,
        clock: Clock,
        timeout_seconds: float,
    ) -> None:
        self._api_key = api_key
        self._transport = transport
        self._clock = clock
        self._timeout = timeout_seconds

    def lookup_hash(self, query: LookupHashInput) -> LookupHashOutput:
        secret = require_api_key(self.name, self._api_key)
        if not HASH_RE.fullmatch(query.file_hash):
            log_failure(self.name, "invalid_query")
            raise ProviderError(self.name, "invalid_query")
        body = request_json(
            self._transport,
            provider=self.name,
            method="GET",
            url=f"{VIRUSTOTAL_FILES_PREFIX}{quote(query.file_hash, safe='')}",
            headers={"Accept": "application/json", "x-apikey": secret},
            params=None,
            timeout_seconds=self._timeout,
            secret=secret,
        )
        stats = _stats(body)
        if stats is None:
            log_failure(self.name, "invalid_response")
            raise ProviderError(self.name, "invalid_response")
        log_ok(self.name)
        return LookupHashOutput(
            file_hash=query.file_hash,
            algorithm=query.algorithm,
            provider=self.name,
            malicious_count=_count(stats, "malicious"),
            harmless_count=_count(stats, "harmless"),
            undetected_count=_count(stats, "undetected"),
            raw=body,
            retrieved_at=self._clock.now(),
        )


def _stats(body: dict[str, Any]) -> dict[str, Any] | None:
    data = body.get("data")
    if not isinstance(data, dict):
        return None
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        return None
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return None
    return stats


def _count(stats: dict[str, Any], key: str) -> int | None:
    value = stats.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0:
        return None
    return value
