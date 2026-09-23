"""AbuseIPDB API v2 check client.

Documented at https://docs.abuseipdb.com/ (CHECK endpoint). The key is sent in
the ``Key`` header, never in the query string. ``abuseConfidenceScore`` is not
a boolean, and the vendor docs say ``isWhitelisted`` must not be treated as a
verdict, so ``reported_malicious`` stays unknown.
"""

from typing import Any

from pydantic import SecretStr

from sentinel.errors import ProviderError
from sentinel.schemas.tools import LookupIpInput, LookupIpOutput
from sentinel.services.clock import Clock
from sentinel.services.http import ABUSEIPDB_HOST, HttpTransport
from sentinel.services.providers.common import log_failure, log_ok, request_json, require_api_key

ABUSEIPDB_CHECK_URL = f"https://{ABUSEIPDB_HOST}/api/v2/check"


class AbuseIpdbIntelligence:
    name = "abuseipdb"

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

    def lookup_ip(self, query: LookupIpInput) -> LookupIpOutput:
        secret = require_api_key(self.name, self._api_key)
        body = request_json(
            self._transport,
            provider=self.name,
            method="GET",
            url=ABUSEIPDB_CHECK_URL,
            headers={"Accept": "application/json", "Key": secret},
            params={"ipAddress": str(query.ip)},
            timeout_seconds=self._timeout,
            secret=secret,
        )
        data = body.get("data")
        if not isinstance(data, dict):
            log_failure(self.name, "invalid_response")
            raise ProviderError(self.name, "invalid_response")
        log_ok(self.name)
        return LookupIpOutput(
            ip=str(query.ip),
            provider=self.name,
            categories=[],
            reported_malicious=None,
            asn=_optional_asn(data),
            country=_optional_text(data.get("countryCode"), max_length=8),
            organization=_optional_text(data.get("isp"), max_length=256),
            reference_ids=[],
            raw=body,
            retrieved_at=self._clock.now(),
        )


def _optional_text(value: object, *, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    return stripped[:max_length]


def _optional_asn(data: dict[str, Any]) -> str | None:
    """Copy a documented ASN string or integer. Do not invent one."""
    value = data.get("asn")
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return f"AS{value}"[:32]
    if isinstance(value, str):
        return _optional_text(value, max_length=32)
    return None
