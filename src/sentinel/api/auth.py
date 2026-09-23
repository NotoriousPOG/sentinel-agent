"""Optional API credential for data routes.

``/health`` and ``/ready`` do not use this dependency. When
``SENTINEL_API_KEY`` is unset, data routes stay open so unit tests and a
casual local process do not need a credential. When it is set, a request
must send ``Authorization: Bearer`` or ``X-API-Key``. A mismatch is 401.
The presented value is not logged.
"""

import hmac
from typing import Annotated

from fastapi import Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from sentinel.config.settings import configured_secret, get_settings
from sentinel.errors import Unauthorized

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_bearer = HTTPBearer(auto_error=False)


def require_api_key(
    x_api_key: Annotated[str | None, Security(_api_key_header)] = None,
    bearer: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)] = None,
) -> None:
    """Accept the configured key. Do nothing when no key is configured."""
    expected = configured_secret(get_settings().api_key)
    if expected is None:
        return
    presented: list[str] = []
    if bearer is not None and bearer.scheme.lower() == "bearer":
        presented.append(bearer.credentials)
    if isinstance(x_api_key, str) and x_api_key:
        presented.append(x_api_key)
    if any(_same(item, expected) for item in presented):
        return
    raise Unauthorized()


def _same(presented: str, expected: str) -> bool:
    presented_bytes = presented.encode()
    expected_bytes = expected.encode()
    if len(presented_bytes) != len(expected_bytes):
        hmac.compare_digest(expected_bytes, expected_bytes)
        return False
    return hmac.compare_digest(presented_bytes, expected_bytes)
