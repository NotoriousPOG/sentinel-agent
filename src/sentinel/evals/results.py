"""Report objects. Numbers are filled by the runner, not by this module."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Count(BaseModel):
    model_config = ConfigDict(extra="forbid")

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)


class InjectionCounts(BaseModel):
    """Structural counts. Not a detection rate and not a resistance percentage."""

    model_config = ConfigDict(extra="forbid")

    cases: int = Field(ge=0)
    system_prompt_constant: int = Field(ge=0)
    unknown_tool_ran: int = Field(ge=0)
    complete_without_review: int = Field(ge=0)


class CaseRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    kind: str
    synthetic: Literal[True]
    summary: str
    label_note: str
    execution: str
    live_intelligence: Literal[False]
    expected_classification: str
    observed_classification: str | None
    classification_agreed: bool
    expected_tools: list[str] | None
    selected_tools: list[str]
    tool_selection_agreed: bool | None
    expected_report: bool
    report_stored: bool
    schema_valid: bool
    expected_verification: str | None
    verification_accepted: bool | None
    verification_codes: list[str]
    grounding_ok: bool | None
    mitre_ok: bool | None
    mitre_technique_ids: list[str]
    status: str
    review_recorded: bool
    tool_calls_made: int = Field(ge=0)
    tokens_used: int = Field(ge=0)
    providers: list[str]
    prompt_injection: bool
    system_prompt_constant: bool | None
    unknown_tool_ran: bool | None
    complete_without_review: bool | None
    must_not_classify_as: str | None
    excluded_label_avoided: bool | None
    contradiction_count: int | None
    notes: str


class EvalMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification_agreement: Count
    tool_selection_agreement: Count
    evidence_grounding: Count
    mitre_citation: Count
    mitre_techniques_on_reports: int = Field(ge=0)
    schema_compliance: Count
    unsupported_claim_count: int = Field(ge=0)
    injection: InjectionCounts
    excluded_label_avoided: Count
    tool_calls_total: int = Field(ge=0)
    case_count: int = Field(ge=1)
    wall_clock_seconds: float = Field(ge=0)
    token_counter_total: int = Field(ge=0)
    estimated_cost_usd: Literal[0]
    estimated_cost_reason: str


class EvalReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    synthetic: Literal[True]
    hosted_model: Literal[False]
    live_network: Literal[False]
    model_name: Literal["scripted-eval"]
    notice: str
    what_a_number_is_not: list[str]
    dataset_path: str
    metrics: EvalMetrics
    transport_urls: list[str]
    cases: list[CaseRecord]
