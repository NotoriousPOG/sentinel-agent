"""Typed tool contracts. No tool in this release performs a lookup."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

from sentinel.schemas.patterns import (
    normalize_cve,
    normalize_domain,
    normalize_hash,
    normalize_technique_id,
)
from sentinel.schemas.timestamps import require_aware

ShortRef = Annotated[str, Field(min_length=1, max_length=2048)]


class ToolName(StrEnum):
    LOOKUP_IP = "lookup_ip"
    LOOKUP_HASH = "lookup_hash"
    LOOKUP_CVE = "lookup_cve"
    SEARCH_MITRE = "search_mitre"
    LOOKUP_DOMAIN = "lookup_domain"


class HashAlgorithm(StrEnum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


_HASH_LENGTH = {
    HashAlgorithm.MD5: 32,
    HashAlgorithm.SHA1: 40,
    HashAlgorithm.SHA256: 64,
}


class LookupIpInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: IPvAnyAddress


class LookupIpOutput(BaseModel):
    """Provider answer for an IP. ``reported_malicious`` defaults to unknown, not false.

    ``asn``, ``country``, and ``organization`` are copied from the provider when
    present. They are not a reputation verdict. Vendor scores such as
    AbuseIPDB ``abuseConfidenceScore`` stay on ``raw``.
    """

    model_config = ConfigDict(extra="forbid")

    ip: str
    provider: str = Field(min_length=1, max_length=128)
    categories: list[str] = Field(default_factory=list, max_length=50)
    reported_malicious: bool | None = None
    asn: str | None = Field(default=None, max_length=32)
    country: str | None = Field(default=None, max_length=8)
    organization: str | None = Field(default=None, max_length=256)
    reference_ids: list[ShortRef] = Field(default_factory=list, max_length=50)
    raw: dict[str, Any]
    retrieved_at: datetime

    @field_validator("retrieved_at")
    @classmethod
    def _retrieved_at(cls, value: datetime) -> datetime:
        return require_aware(value)


class LookupHashInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_hash: str
    algorithm: HashAlgorithm

    @model_validator(mode="after")
    def _hash_matches_algorithm(self) -> Self:
        digest = normalize_hash(self.file_hash)
        if len(digest) != _HASH_LENGTH[self.algorithm]:
            raise ValueError("file_hash length does not match algorithm")
        self.file_hash = digest
        return self


class LookupHashOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_hash: str
    algorithm: HashAlgorithm
    provider: str = Field(min_length=1, max_length=128)
    malicious_count: int | None = Field(default=None, ge=0)
    harmless_count: int | None = Field(default=None, ge=0)
    undetected_count: int | None = Field(default=None, ge=0)
    raw: dict[str, Any]
    retrieved_at: datetime

    @field_validator("retrieved_at")
    @classmethod
    def _retrieved_at(cls, value: datetime) -> datetime:
        return require_aware(value)

    @field_validator("file_hash")
    @classmethod
    def _file_hash(cls, value: str) -> str:
        return normalize_hash(value)


class LookupCveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str

    @field_validator("cve_id")
    @classmethod
    def _cve_id(cls, value: str) -> str:
        return normalize_cve(value)


class LookupCveOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    provider: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=8000)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_version: str | None = Field(default=None, max_length=16)
    references: list[ShortRef] = Field(
        default_factory=list,
        max_length=50,
        description="Reference strings stored as data. They are not fetched.",
    )
    raw: dict[str, Any]
    retrieved_at: datetime

    @field_validator("cve_id")
    @classmethod
    def _cve_id(cls, value: str) -> str:
        return normalize_cve(value)

    @field_validator("retrieved_at")
    @classmethod
    def _retrieved_at(cls, value: datetime) -> datetime:
        return require_aware(value)


class SearchMitreInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=256)
    technique_id: str | None = None

    @field_validator("technique_id")
    @classmethod
    def _technique_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_technique_id(value)


class MitreTechniqueResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str
    name: str = Field(min_length=1, max_length=256)
    tactic: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=4000)

    @field_validator("technique_id")
    @classmethod
    def _technique_id(cls, value: str) -> str:
        return normalize_technique_id(value)


class SearchMitreOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=256)
    provider: str = Field(min_length=1, max_length=128)
    techniques: list[MitreTechniqueResult] = Field(default_factory=list, max_length=50)
    retrieved_at: datetime

    @field_validator("retrieved_at")
    @classmethod
    def _retrieved_at(cls, value: datetime) -> datetime:
        return require_aware(value)


class LookupDomainInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        return normalize_domain(value)


class LookupDomainOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str
    provider: str = Field(min_length=1, max_length=128)
    resolved_ips: list[str] = Field(default_factory=list, max_length=50)
    reported_malicious: bool | None = None
    raw: dict[str, Any]
    retrieved_at: datetime

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("retrieved_at")
    @classmethod
    def _retrieved_at(cls, value: datetime) -> datetime:
        return require_aware(value)


TOOL_INPUT_MODELS: dict[ToolName, type[BaseModel]] = {
    ToolName.LOOKUP_IP: LookupIpInput,
    ToolName.LOOKUP_HASH: LookupHashInput,
    ToolName.LOOKUP_CVE: LookupCveInput,
    ToolName.SEARCH_MITRE: SearchMitreInput,
    ToolName.LOOKUP_DOMAIN: LookupDomainInput,
}

TOOL_OUTPUT_MODELS: dict[ToolName, type[BaseModel]] = {
    ToolName.LOOKUP_IP: LookupIpOutput,
    ToolName.LOOKUP_HASH: LookupHashOutput,
    ToolName.LOOKUP_CVE: LookupCveOutput,
    ToolName.SEARCH_MITRE: SearchMitreOutput,
    ToolName.LOOKUP_DOMAIN: LookupDomainOutput,
}
