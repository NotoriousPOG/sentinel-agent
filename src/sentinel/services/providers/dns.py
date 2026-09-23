"""Domain resolution. This client does not make HTTP requests."""

import ipaddress
import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from sentinel.errors import ProviderError
from sentinel.schemas.tools import LookupDomainInput, LookupDomainOutput
from sentinel.services.clock import Clock
from sentinel.services.providers.common import log_failure, log_ok, pause

GetAddrInfo = Callable[[str, int | None], list[tuple[object, ...]]]


class DomainResolver(Protocol):
    def resolve(self, domain: str, *, timeout_seconds: float) -> list[str]:
        """Return IP addresses or raise ``ProviderError`` / ``TimeoutError``."""
        ...


class SystemDomainResolver:
    """``socket.getaddrinfo`` on a worker thread so the wait can be bounded."""

    def __init__(self, getaddrinfo: GetAddrInfo | None = None) -> None:
        self._getaddrinfo = socket.getaddrinfo if getaddrinfo is None else getaddrinfo

    def resolve(self, domain: str, *, timeout_seconds: float) -> list[str]:
        if "://" in domain or "/" in domain or " " in domain:
            raise ProviderError("dns", "url_rejected")
        if timeout_seconds <= 0:
            raise ProviderError("dns", "timeout")
        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(self._lookup, domain)
        try:
            return future.result(timeout=timeout_seconds)
        except TimeoutError:
            raise ProviderError("dns", "timeout") from None
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def _lookup(self, domain: str) -> list[str]:
        try:
            infos = self._getaddrinfo(domain, None)
        except socket.gaierror:
            raise ProviderError("dns", "resolution_failed") from None
        ips: list[str] = []
        for info in infos:
            if len(info) < 5:
                continue
            sockaddr = info[4]
            if not isinstance(sockaddr, tuple) or not sockaddr:
                continue
            candidate = sockaddr[0]
            if not isinstance(candidate, str):
                continue
            address = candidate.split("%", 1)[0]
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            if address not in ips:
                ips.append(address)
        if not ips:
            raise ProviderError("dns", "resolution_failed")
        return ips


class DnsIntelligence:
    name = "dns"

    def __init__(
        self,
        *,
        resolver: DomainResolver,
        clock: Clock,
        timeout_seconds: float,
        max_attempts: int = 1,
        backoff_seconds: float = 0.0,
    ) -> None:
        self._resolver = resolver
        self._clock = clock
        self._timeout = timeout_seconds
        self._attempts = max(1, max_attempts)
        self._backoff = backoff_seconds

    def lookup_domain(self, query: LookupDomainInput) -> LookupDomainOutput:
        addresses = self._resolve(query.domain)
        ips = _ip_addresses(addresses)
        if not ips:
            log_failure(self.name, "resolution_failed")
            raise ProviderError(self.name, "resolution_failed")
        log_ok(self.name)
        return LookupDomainOutput(
            domain=query.domain,
            provider=self.name,
            resolved_ips=ips[:50],
            reported_malicious=None,
            raw={"status": "resolved"},
            retrieved_at=self._clock.now(),
        )

    def _resolve(self, domain: str) -> list[str]:
        """Retry a timeout. A resolution failure is not a timeout and is not retried."""
        for attempt in range(self._attempts):
            try:
                return self._resolver.resolve(domain, timeout_seconds=self._timeout)
            except TimeoutError:
                reason = "timeout"
            except ProviderError as exc:
                reason = exc.reason
                if reason != "timeout" or attempt + 1 == self._attempts:
                    log_failure(self.name, reason)
                    raise
            if attempt + 1 == self._attempts:
                log_failure(self.name, reason)
                raise ProviderError(self.name, reason)
            pause(self._backoff, attempt)
        log_failure(self.name, "timeout")
        raise ProviderError(self.name, "timeout")


def _ip_addresses(values: list[str]) -> list[str]:
    """Keep IP addresses. Drop anything that could be fetched as a URL."""
    cleaned: list[str] = []
    for value in values:
        address = value.split("%", 1)[0]
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        if address not in cleaned:
            cleaned.append(address)
    return cleaned
