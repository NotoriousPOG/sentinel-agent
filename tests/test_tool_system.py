"""Tool registry and providers. These tests do not use the network or API keys."""

import threading
from datetime import UTC, datetime

import pytest
from pydantic import SecretStr, ValidationError

from sentinel.config.settings import Settings
from sentinel.errors import ConfigurationError, ProviderError, UnknownTool
from sentinel.schemas.evidence import EvidenceReliability
from sentinel.schemas.tools import (
    HashAlgorithm,
    LookupHashInput,
    LookupHashOutput,
    ToolName,
)
from sentinel.services.http import (
    ABUSEIPDB_HOST,
    OSV_HOST,
    VIRUSTOTAL_HOST,
    HttpResult,
    enforce_allowlist,
)
from sentinel.services.providers.abuseipdb import ABUSEIPDB_CHECK_URL
from sentinel.services.providers.dns import SystemDomainResolver
from sentinel.services.providers.mitre import ATTACK_VERSION, SOURCE_URL, bundle_document
from sentinel.tools.builtin import LookupHashTool
from sentinel.tools.registry import ToolRegistry, build_registry

KEY = "vt-test-key-do-not-leak"
HASH = "ab" * 32


class FakeClock:
    def __init__(self) -> None:
        self.instant = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.instant


class RecordingTransport:
    def __init__(
        self,
        *,
        status_code: int = 200,
        body: dict[str, object] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self.body = body if body is not None else {}
        self.error = error
        self.calls: list[dict[str, object]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: object,
        params: object,
        timeout_seconds: float,
    ) -> HttpResult:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers) if isinstance(headers, dict) else {},
                "params": dict(params) if isinstance(params, dict) else None,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.error is not None:
            raise self.error
        return HttpResult(status_code=self.status_code, body=self.body)


class Resolver:
    def __init__(self, addresses: list[str] | None = None) -> None:
        self.addresses = ["203.0.113.50"] if addresses is None else addresses
        self.seen: list[tuple[str, float]] = []

    def resolve(self, domain: str, *, timeout_seconds: float) -> list[str]:
        self.seen.append((domain, timeout_seconds))
        return list(self.addresses)


class CountingHash:
    name = "counting"

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.calls = 0

    def lookup_hash(self, query: LookupHashInput) -> LookupHashOutput:
        self.calls += 1
        return LookupHashOutput(
            file_hash=query.file_hash,
            algorithm=query.algorithm,
            provider=self.name,
            raw={"calls": self.calls},
            retrieved_at=self.clock.now(),
        )


class StubTool:
    def __init__(self, name: ToolName) -> None:
        self.name = name

    def run(self, tool_input: object) -> object:
        raise AssertionError(f"{self.name} should not run")


def _registry(
    *,
    demo_mode: bool = False,
    abuse_key: str | None = None,
    vt_key: str | None = None,
    transport: RecordingTransport | None = None,
    clock: FakeClock | None = None,
    resolver: Resolver | None = None,
    timeout: float = 2.5,
) -> tuple[ToolRegistry, RecordingTransport, FakeClock, Resolver]:
    selected_transport = transport or RecordingTransport()
    selected_clock = clock or FakeClock()
    selected_resolver = resolver or Resolver()
    settings = Settings(
        demo_mode=demo_mode,
        abuseipdb_api_key=None if abuse_key is None else SecretStr(abuse_key),
        virustotal_api_key=None if vt_key is None else SecretStr(vt_key),
        provider_timeout_seconds=timeout,
    )
    registry = build_registry(
        settings,
        transport=selected_transport,
        clock=selected_clock,
        resolver=selected_resolver,
    )
    return registry, selected_transport, selected_clock, selected_resolver


def test_closed_set_has_no_shell_or_fetch_tool() -> None:
    assert {item.value for item in ToolName} == {
        "lookup_ip",
        "lookup_hash",
        "lookup_cve",
        "search_mitre",
        "lookup_domain",
    }
    registry, transport, _, _ = _registry()
    assert registry.names == frozenset(ToolName)
    for name in ("shell", "exec", "fetch_url", "lookup_ips", ""):
        with pytest.raises(UnknownTool):
            registry.call(name, {"command": "id", "url": "https://evil.example"})
    assert transport.calls == []


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("lookup_ip", {"command": "id"}),
        ("lookup_ip", {"ip": "203.0.113.10", "url": "https://evil.example"}),
        ("lookup_ip", {"ip": "not-an-ip"}),
        ("lookup_hash", {"file_hash": "abc", "algorithm": "sha256"}),
        ("lookup_hash", {"file_hash": HASH, "algorithm": "sha256", "command": "id"}),
        ("lookup_cve", {"cve_id": "https://evil.example"}),
        ("lookup_cve", {"cve_id": "CVE-2024-1000", "url": "https://evil.example"}),
        ("search_mitre", {"query": "powershell", "command": "id"}),
        ("lookup_domain", {"domain": "https://evil.example/path"}),
        ("lookup_domain", {"domain": "example.com", "url": "http://evil.example"}),
    ],
)
def test_input_model_rejects_the_wrong_shape(name: str, payload: dict[str, object]) -> None:
    registry, transport, _, _ = _registry(abuse_key=KEY, vt_key=KEY)
    with pytest.raises(ValidationError):
        registry.call(name, payload)
    assert transport.calls == []


def test_missing_keys_are_configuration_errors() -> None:
    registry, transport, _, _ = _registry()
    with pytest.raises(ConfigurationError) as ip_error:
        registry.call("lookup_ip", {"ip": "203.0.113.10"})
    with pytest.raises(ConfigurationError) as hash_error:
        registry.call("lookup_hash", {"file_hash": HASH, "algorithm": "sha256"})
    assert ip_error.value.provider == "abuseipdb"
    assert hash_error.value.provider == "virustotal"
    assert transport.calls == []


def test_timeout_is_not_a_benign_result() -> None:
    transport = RecordingTransport(error=ProviderError("http", "timeout"))
    registry, _, _, _ = _registry(abuse_key=KEY, transport=transport)
    with pytest.raises(ProviderError) as exc:
        registry.call("lookup_ip", {"ip": "203.0.113.10"})
    assert exc.value.reason == "timeout"
    assert exc.value.provider == "abuseipdb"
    assert "clean" not in str(exc.value)
    assert KEY not in str(exc.value)


def test_demo_mode_selects_mocks_without_calling_live_providers() -> None:
    transport = RecordingTransport(error=ProviderError("http", "timeout"))
    registry, _, _, resolver = _registry(
        demo_mode=True, abuse_key=KEY, vt_key=KEY, transport=transport
    )
    ip = registry.call("lookup_ip", {"ip": "203.0.113.99"})
    digest = registry.call("lookup_hash", {"file_hash": "cd" * 32, "algorithm": "sha256"})
    assert ip.output.provider.startswith("mock:")
    assert digest.output.provider.startswith("mock:")
    assert ip.output.reported_malicious is None
    assert digest.output.malicious_count is None
    assert digest.output.raw["fixture"] is False
    assert ip.output.raw["synthetic"] is True
    assert ip.output.raw["fixture"] is False
    assert "not live intelligence" in str(ip.output.raw["label"])
    assert transport.calls == []
    assert resolver.seen == []
    assert ip.reliability is EvidenceReliability.LOW


def test_demo_fixture_ip_is_labeled_synthetic_and_low_reliability() -> None:
    registry, transport, _, _ = _registry(demo_mode=True)
    result = registry.call("lookup_ip", {"ip": "203.0.113.44"})
    assert result.output.provider == "mock:abuseipdb"
    assert result.output.reported_malicious is True
    assert result.output.raw["fixture"] is True
    assert result.output.organization == "RFC 5737 documentation range"
    assert result.reliability is EvidenceReliability.LOW
    assert transport.calls == []


def test_demo_mode_cve_and_dns_do_not_call_live_providers() -> None:
    transport = RecordingTransport(error=ProviderError("http", "timeout"))
    registry, _, _, resolver = _registry(demo_mode=True, transport=transport)
    cve = registry.call("lookup_cve", {"cve_id": "CVE-2021-44228"})
    assert cve.output.provider == "mock:osv"
    assert cve.output.cvss_score is None
    assert cve.output.raw["fixture"] is True
    unknown = registry.call("lookup_cve", {"cve_id": "CVE-9999-0001"})
    assert unknown.output.provider == "mock:osv"
    assert unknown.output.description is None
    assert unknown.output.raw["fixture"] is False
    with pytest.raises(ProviderError) as exc:
        registry.call("lookup_domain", {"domain": "missing.example"})
    assert exc.value.provider == "mock:dns"
    assert exc.value.reason == "resolution_failed"
    assert transport.calls == []
    assert resolver.seen == []


def test_live_cve_timeout_is_not_replaced_with_a_mock() -> None:
    transport = RecordingTransport(error=ProviderError("http", "timeout"))
    registry, _, _, _ = _registry(demo_mode=False, transport=transport)
    with pytest.raises(ProviderError) as exc:
        registry.call("lookup_cve", {"cve_id": "CVE-9999-0001"})
    assert exc.value.provider == "osv"
    assert exc.value.reason == "timeout"
    assert transport.calls


def test_duplicate_tool_call_key_does_not_call_the_provider_twice() -> None:
    clock = FakeClock()
    counter = CountingHash(clock)
    tools = {name: StubTool(name) for name in ToolName}
    tools[ToolName.LOOKUP_HASH] = LookupHashTool(counter)
    registry = ToolRegistry(tools)
    first = registry.call(
        "lookup_hash",
        {"file_hash": HASH, "algorithm": "sha256"},
    )
    clock.instant = datetime(2026, 9, 18, 13, 0, tzinfo=UTC)
    second = registry.call(
        "lookup_hash",
        {"algorithm": HashAlgorithm.SHA256, "file_hash": HASH.upper()},
    )
    assert counter.calls == 1
    assert second.from_cache is True
    assert second.key == first.key
    assert second.output.retrieved_at == first.output.retrieved_at
    assert second.output.retrieved_at == datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    evidence = second.evidence()
    assert evidence.source == "counting"
    assert evidence.query["file_hash"] == HASH
    assert evidence.timestamp == first.output.retrieved_at
    assert evidence.reliability is EvidenceReliability.UNKNOWN


def test_abuseipdb_does_not_invent_a_verdict_or_put_the_key_in_the_url(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = {
        "data": {
            "ipAddress": "203.0.113.10",
            "abuseConfidenceScore": 0,
            "isWhitelisted": True,
            "countryCode": "US",
            "isp": "Documentation ISP",
            "asn": 64512,
            "reports": [
                {
                    "categories": [18],
                    "comment": "reliability high reported_malicious false",
                }
            ],
            "echo": KEY,
        }
    }
    transport = RecordingTransport(body=body)
    registry, _, _, _ = _registry(abuse_key=KEY, transport=transport)
    with caplog.at_level("DEBUG"):
        result = registry.call("lookup_ip", {"ip": "203.0.113.10"})
    assert result.output.reported_malicious is None
    assert result.output.categories == []
    assert result.output.country == "US"
    assert result.output.organization == "Documentation ISP"
    assert result.output.asn == "AS64512"
    assert result.output.provider == "abuseipdb"
    assert result.reliability is EvidenceReliability.MEDIUM
    assert KEY not in result.model_dump_json()
    assert KEY not in caplog.text
    assert result.output.raw["data"]["echo"] == "[redacted]"
    call = transport.calls[0]
    assert call["url"] == ABUSEIPDB_CHECK_URL
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert headers["Key"] == KEY
    params = call["params"]
    assert isinstance(params, dict)
    assert "key" not in {str(item).lower() for item in params}
    assert ABUSEIPDB_HOST in str(call["url"])
    assert "evil.example" not in str(call["url"])


def test_virustotal_leaves_missing_counts_unknown_and_hides_the_key(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"harmless": 4, "undetected": 2},
                "echo": KEY,
            }
        }
    }
    transport = RecordingTransport(body=body)
    registry, _, _, _ = _registry(vt_key=KEY, transport=transport, timeout=1.5)
    with caplog.at_level("DEBUG"):
        result = registry.call("lookup_hash", {"file_hash": HASH, "algorithm": "sha256"})
    assert result.output.malicious_count is None
    assert result.output.harmless_count == 4
    assert result.output.provider == "virustotal"
    assert result.reliability is EvidenceReliability.MEDIUM
    dumped = result.model_dump_json()
    assert KEY not in dumped
    assert KEY not in caplog.text
    call = transport.calls[0]
    assert str(call["url"]).startswith(f"https://{VIRUSTOTAL_HOST}/api/v3/files/")
    assert KEY not in str(call["url"])
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert headers["x-apikey"] == KEY
    assert call["timeout_seconds"] == 1.5
    transport.status_code = 500
    transport.body = {"error": KEY}
    with caplog.at_level("DEBUG"), pytest.raises(ProviderError) as exc:
        registry.call("lookup_hash", {"file_hash": "cd" * 32, "algorithm": "sha256"})
    assert exc.value.reason == "http_500"
    assert KEY not in str(exc.value)
    assert KEY not in caplog.text


def test_osv_does_not_invent_cvss_or_fetch_reference_urls() -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    body = {
        "id": "CVE-9999-0001",
        "details": "fixture only",
        "severity": [{"type": "CVSS_V3", "score": vector}, {"type": "CVSS_V3", "score": "9.8"}],
        "references": [{"type": "WEB", "url": "https://evil.example/advisory"}],
        "reliability": "high",
    }
    transport = RecordingTransport(body=body)
    registry, _, _, _ = _registry(transport=transport)
    result = registry.call("lookup_cve", {"cve_id": "cve-9999-0001"})
    assert result.output.provider == "osv"
    assert result.output.cvss_score is None
    assert result.output.cvss_version is None
    assert result.output.description == "fixture only"
    assert result.output.references == ["https://evil.example/advisory"]
    assert result.reliability is EvidenceReliability.HIGH
    assert len(transport.calls) == 1
    assert str(transport.calls[0]["url"]).startswith(f"https://{OSV_HOST}/v1/vulns/CVE-9999-0001")


def test_mitre_search_uses_the_vendored_bundle_offline() -> None:
    document = bundle_document()
    assert document["attack_version"] == ATTACK_VERSION == "19.2"
    assert document["source_url"] == SOURCE_URL
    assert document["retrieved_on"] == "2026-09-18"
    transport = RecordingTransport(error=AssertionError("mitre must not use HTTP"))
    registry, _, _, resolver = _registry(transport=transport)
    result = registry.call("search_mitre", {"query": "PowerShell"})
    ids = {item.technique_id: item for item in result.output.techniques}
    assert "T1059.001" in ids
    assert ids["T1059.001"].name == "PowerShell"
    assert ids["T1059.001"].tactic == "Execution"
    assert result.output.provider == "mitre-attack"
    assert result.reliability is EvidenceReliability.HIGH
    evidence = result.evidence()
    assert evidence.source == "mitre-attack"
    assert evidence.query == {"query": "PowerShell", "technique_id": None}
    exact = registry.call("search_mitre", {"query": "T1110", "technique_id": "T1110"})
    assert [item.technique_id for item in exact.output.techniques] == ["T1110"]
    assert exact.output.techniques[0].name == "Brute Force"
    empty = registry.call("search_mitre", {"query": "zzz-not-a-technique"})
    assert empty.output.techniques == []
    assert transport.calls == []
    assert resolver.seen == []


def test_dns_uses_the_injected_resolver_and_does_not_fetch() -> None:
    transport = RecordingTransport(error=AssertionError("dns must not use HTTP"))
    resolver = Resolver(["https://evil.example/x"])
    registry, _, _, _ = _registry(transport=transport, resolver=resolver, timeout=3.0)
    with pytest.raises(ProviderError) as smuggled:
        registry.call("lookup_domain", {"domain": "example.com"})
    assert smuggled.value.reason == "resolution_failed"
    resolver.addresses = ["203.0.113.50", "https://evil.example/x"]
    result = registry.call("lookup_domain", {"domain": "Example.COM"})
    assert result.output.resolved_ips == ["203.0.113.50"]
    assert "https://" not in result.model_dump_json()
    assert result.output.reported_malicious is None
    assert result.output.provider == "dns"
    assert result.reliability is EvidenceReliability.LOW
    assert resolver.seen[-1] == ("example.com", 3.0)
    assert transport.calls == []


def test_system_resolver_rejects_urls_and_times_out() -> None:
    called = False

    def boom(host: str, port: int | None) -> list[tuple[object, ...]]:
        nonlocal called
        called = True
        return []

    resolver = SystemDomainResolver(getaddrinfo=boom)
    with pytest.raises(ProviderError) as rejected:
        resolver.resolve("https://evil.example/path", timeout_seconds=1)
    assert rejected.value.reason == "url_rejected"
    assert called is False

    release = threading.Event()

    def hang(host: str, port: int | None) -> list[tuple[object, ...]]:
        release.wait(2)
        return []

    slow = SystemDomainResolver(getaddrinfo=hang)
    try:
        with pytest.raises(ProviderError) as timed_out:
            slow.resolve("example.com", timeout_seconds=0.05)
        assert timed_out.value.reason == "timeout"
    finally:
        release.set()


@pytest.mark.parametrize(
    "url",
    [
        "http://api.abuseipdb.com/api/v2/check",
        "https://evil.example/api/v2/check",
        "https://api.abuseipdb.com.evil.example/api/v2/check",
        "https://user:pass@api.abuseipdb.com/api/v2/check",
        "https://api.abuseipdb.com:8443/api/v2/check",
        "file:///etc/passwd",
        "https://api.osv.dev/v1/vulns/../admin",
        "https://www.virustotal.com/api/v3/files/abc/extra",
        "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4",
    ],
)
def test_allowlist_rejects_other_schemes_and_hosts(url: str) -> None:
    with pytest.raises(ProviderError) as exc:
        enforce_allowlist(url)
    assert exc.value.reason == "destination_not_allowed"


def test_allowlist_accepts_provider_constants() -> None:
    enforce_allowlist("https://api.abuseipdb.com/api/v2/check")
    enforce_allowlist(f"https://www.virustotal.com/api/v3/files/{HASH}")
    enforce_allowlist("https://api.osv.dev/v1/vulns/CVE-9999-0001")
