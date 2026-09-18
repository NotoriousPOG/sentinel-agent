"""Closed tool registry.

Unknown names are errors. There is no default tool and no shell tool. A
repeated ``tool_call_key`` returns the first result and does not call the
provider again. The cache is in-process and belongs to one registry.
"""

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from sentinel.agents.budgets import tool_call_key
from sentinel.config.settings import Settings
from sentinel.errors import ProviderError, UnknownTool
from sentinel.schemas.evidence import Evidence, EvidenceReliability
from sentinel.schemas.tools import (
    TOOL_INPUT_MODELS,
    TOOL_OUTPUT_MODELS,
    LookupCveOutput,
    LookupDomainOutput,
    LookupHashOutput,
    LookupIpOutput,
    SearchMitreOutput,
    ToolName,
)
from sentinel.services.clock import Clock, SystemClock
from sentinel.services.http import HttpTransport, HttpxAllowlistTransport
from sentinel.services.providers import build_providers
from sentinel.services.providers.dns import DomainResolver, SystemDomainResolver
from sentinel.tools.base import SecurityTool
from sentinel.tools.builtin import (
    LookupCveTool,
    LookupDomainTool,
    LookupHashTool,
    LookupIpTool,
    SearchMitreTool,
)
from sentinel.tools.policy import reliability_for_provider

ToolOutput = (
    LookupIpOutput | LookupHashOutput | LookupCveOutput | SearchMitreOutput | LookupDomainOutput
)


class ToolExecution(BaseModel):
    """One tool result plus the evidence fields the output model does not carry."""

    model_config = ConfigDict(extra="forbid")

    tool: ToolName
    key: str
    query: dict[str, Any]
    output: ToolOutput
    reliability: EvidenceReliability
    from_cache: bool = False

    def evidence(self) -> Evidence:
        return Evidence(
            evidence_id=self.key,
            source=self.output.provider,
            tool=self.tool.value,
            query=self.query,
            result=self.output.model_dump(mode="json"),
            timestamp=self.output.retrieved_at,
            reliability=self.reliability,
        )


class ToolRegistry:
    def __init__(self, tools: Mapping[ToolName, SecurityTool]) -> None:
        names = set(tools)
        if names != set(ToolName):
            missing = sorted(tool.value for tool in set(ToolName) - names)
            message = f"registry must contain exactly the closed tool set, missing {missing}"
            raise ValueError(message)
        for name, tool in tools.items():
            if tool.name is not name:
                raise ValueError("tool object name does not match the registry key")
        self._tools = dict(tools)
        self._cache: dict[str, ToolExecution] = {}

    @property
    def names(self) -> frozenset[ToolName]:
        return frozenset(self._tools)

    def call(self, name: str, arguments: Mapping[str, object]) -> ToolExecution:
        tool_name = _parse_name(name)
        tool = self._tools[tool_name]
        parsed = TOOL_INPUT_MODELS[tool_name].model_validate(dict(arguments))
        query = parsed.model_dump(mode="json")
        key = tool_call_key(tool_name.value, query)
        cached = self._cache.get(key)
        if cached is not None:
            return cached.model_copy(update={"from_cache": True})
        try:
            produced = tool.run(parsed)
        except (ProviderError, ValidationError):
            raise
        output = _validate_output(tool_name, produced)
        execution = ToolExecution(
            tool=tool_name,
            key=key,
            query=query,
            output=output,
            reliability=reliability_for_provider(output.provider),
            from_cache=False,
        )
        self._cache[key] = execution
        return execution


def build_registry(
    settings: Settings,
    *,
    transport: HttpTransport | None = None,
    clock: Clock | None = None,
    resolver: DomainResolver | None = None,
) -> ToolRegistry:
    """Build the five tools. Pass fakes in tests so this does not touch the network."""
    selected_clock = clock or SystemClock()
    selected_transport = transport or HttpxAllowlistTransport()
    selected_resolver = resolver or SystemDomainResolver()
    providers = build_providers(
        settings,
        transport=selected_transport,
        clock=selected_clock,
        resolver=selected_resolver,
    )
    tools: dict[ToolName, SecurityTool] = {
        ToolName.LOOKUP_IP: LookupIpTool(providers.ip),
        ToolName.LOOKUP_HASH: LookupHashTool(providers.file),
        ToolName.LOOKUP_CVE: LookupCveTool(providers.cve),
        ToolName.SEARCH_MITRE: SearchMitreTool(providers.mitre),
        ToolName.LOOKUP_DOMAIN: LookupDomainTool(providers.domain),
    }
    return ToolRegistry(tools)


def _parse_name(name: str) -> ToolName:
    try:
        return ToolName(name)
    except ValueError as exc:
        raise UnknownTool(name) from exc


def _validate_output(tool_name: ToolName, produced: BaseModel) -> ToolOutput:
    model = TOOL_OUTPUT_MODELS[tool_name]
    try:
        validated = model.model_validate(produced)
    except ValidationError:
        raise ProviderError(tool_name.value, "invalid_response") from None
    if not isinstance(validated, ToolOutput):
        raise ProviderError(tool_name.value, "invalid_response")
    provider = validated.provider
    if not isinstance(provider, str) or not provider.strip():
        raise ProviderError(tool_name.value, "invalid_response")
    return validated
