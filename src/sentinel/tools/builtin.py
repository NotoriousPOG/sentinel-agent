"""The five tools. Each one calls the provider it was given and nothing else."""

from pydantic import BaseModel

from sentinel.schemas.tools import (
    LookupCveInput,
    LookupDomainInput,
    LookupHashInput,
    LookupIpInput,
    SearchMitreInput,
    ToolName,
)
from sentinel.services.threat_intel import (
    CveIntelligence,
    DomainIntelligence,
    FileIntelligence,
    IpIntelligence,
    MitreCatalog,
)


class LookupIpTool:
    name = ToolName.LOOKUP_IP

    def __init__(self, provider: IpIntelligence) -> None:
        self._provider = provider

    def run(self, tool_input: BaseModel) -> BaseModel:
        if not isinstance(tool_input, LookupIpInput):
            raise TypeError("lookup_ip requires LookupIpInput")
        return self._provider.lookup_ip(tool_input)


class LookupHashTool:
    name = ToolName.LOOKUP_HASH

    def __init__(self, provider: FileIntelligence) -> None:
        self._provider = provider

    def run(self, tool_input: BaseModel) -> BaseModel:
        if not isinstance(tool_input, LookupHashInput):
            raise TypeError("lookup_hash requires LookupHashInput")
        return self._provider.lookup_hash(tool_input)


class LookupCveTool:
    name = ToolName.LOOKUP_CVE

    def __init__(self, provider: CveIntelligence) -> None:
        self._provider = provider

    def run(self, tool_input: BaseModel) -> BaseModel:
        if not isinstance(tool_input, LookupCveInput):
            raise TypeError("lookup_cve requires LookupCveInput")
        return self._provider.lookup_cve(tool_input)


class SearchMitreTool:
    name = ToolName.SEARCH_MITRE

    def __init__(self, provider: MitreCatalog) -> None:
        self._provider = provider

    def run(self, tool_input: BaseModel) -> BaseModel:
        if not isinstance(tool_input, SearchMitreInput):
            raise TypeError("search_mitre requires SearchMitreInput")
        return self._provider.search_mitre(tool_input)


class LookupDomainTool:
    name = ToolName.LOOKUP_DOMAIN

    def __init__(self, provider: DomainIntelligence) -> None:
        self._provider = provider

    def run(self, tool_input: BaseModel) -> BaseModel:
        if not isinstance(tool_input, LookupDomainInput):
            raise TypeError("lookup_domain requires LookupDomainInput")
        return self._provider.lookup_domain(tool_input)
