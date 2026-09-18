"""Labeled synthetic cases. The runner reads labels. It does not assign them."""

from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.reports import Classification
from sentinel.schemas.tools import ToolName

_VENDOR_MARKERS = ("abuseipdb", "virustotal", "mock:")


class CaseKind(StrEnum):
    CLEARLY_BENIGN = "clearly_benign"
    MALICIOUS_IP = "malicious_ip"
    SUSPICIOUS_POWERSHELL = "suspicious_powershell"
    CREDENTIAL_ATTACK = "credential_attack"
    MALWARE_HASH = "malware_hash"
    KNOWN_CVE = "known_cve"
    AMBIGUOUS = "ambiguous"
    CONFLICTING_INTELLIGENCE = "conflicting_intelligence"
    MISSING_INTELLIGENCE = "missing_intelligence"
    PROMPT_INJECTION = "prompt_injection"


class SyntheticIpRow(BaseModel):
    """One synthetic evidence row. Not a vendor response and not a ``mock:`` result."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    ip: str = Field(min_length=1, max_length=64)
    reported_malicious: bool

    @field_validator("source")
    @classmethod
    def _source(cls, value: str) -> str:
        if not value.startswith("synthetic:"):
            raise ValueError("synthetic evidence source must start with synthetic:")
        lowered = value.casefold()
        for marker in _VENDOR_MARKERS:
            if marker in lowered:
                raise ValueError("synthetic evidence must not name a vendor or a mock provider")
        return value


class EvalCase(BaseModel):
    """One case. ``expected_*`` fields are the labels. The runner does not fill them."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1, max_length=128)
    synthetic: Literal[True]
    kind: CaseKind
    summary: str = Field(min_length=1, max_length=500)
    label_note: str = Field(min_length=1, max_length=1000)
    expected_classification: Classification
    expected_tools: list[str] | None
    expected_report: bool
    expected_verification: str | None = None
    execution: Literal["pipeline", "synthetic_evidence"]
    prompt_injection: bool
    must_not_classify_as: Classification | None = None
    alert: NormalizedAlert
    synthetic_rows: list[SyntheticIpRow] | None = None

    @field_validator("expected_tools")
    @classmethod
    def _tools(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        allowed = {item.value for item in ToolName}
        unknown = [item for item in value if item not in allowed]
        if unknown:
            raise ValueError(f"unknown expected tool {unknown[0]}")
        return value

    @model_validator(mode="after")
    def _shape(self) -> Self:
        if self.prompt_injection is not (self.kind is CaseKind.PROMPT_INJECTION):
            raise ValueError("prompt_injection must match the prompt_injection kind")
        if self.execution == "synthetic_evidence":
            rows = self.synthetic_rows or []
            if len(rows) < 2:
                raise ValueError("conflicting intelligence needs two synthetic rows")
            if self.expected_tools is not None:
                raise ValueError("synthetic evidence does not declare a tool list")
            return self
        if self.synthetic_rows:
            raise ValueError("pipeline cases do not carry synthetic rows")
        if self.kind is CaseKind.MISSING_INTELLIGENCE:
            if self.expected_report:
                raise ValueError("missing intelligence does not expect a stored report")
            if self.must_not_classify_as is not Classification.BENIGN:
                raise ValueError("missing intelligence must not be labeled as allowed to be BENIGN")
        return self


class EvalDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    synthetic: Literal[True]
    notice: str = Field(min_length=1, max_length=1000)
    cases: list[EvalCase] = Field(min_length=1)

    @model_validator(mode="after")
    def _cover(self) -> Self:
        ids = [item.case_id for item in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("case_id values must be unique")
        kinds = {item.kind for item in self.cases}
        missing = set(CaseKind) - kinds
        if missing:
            names = ", ".join(sorted(item.value for item in missing))
            raise ValueError(f"dataset is missing case kinds: {names}")
        return self


def default_dataset_path() -> Path:
    return Path(__file__).resolve().parents[3] / "evals" / "dataset.json"


def load_dataset(path: Path | None = None) -> EvalDataset:
    selected = default_dataset_path() if path is None else path
    return EvalDataset.model_validate_json(selected.read_text(encoding="utf-8"))
