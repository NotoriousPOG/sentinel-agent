"""Tool contracts. These tests do not call a provider."""

import pytest
from pydantic import ValidationError
from tests.support import NOW

from sentinel.schemas.tools import (
    TOOL_INPUT_MODELS,
    TOOL_OUTPUT_MODELS,
    LookupDomainInput,
    LookupHashInput,
    LookupIpOutput,
    SearchMitreInput,
    ToolName,
)


def test_every_tool_has_an_input_and_output_model() -> None:
    assert set(TOOL_INPUT_MODELS) == set(ToolName)
    assert set(TOOL_OUTPUT_MODELS) == set(ToolName)


def test_ip_output_does_not_assume_benign() -> None:
    result = LookupIpOutput(
        ip="203.0.113.10",
        provider="unconfigured",
        raw={},
        retrieved_at=NOW,
    )
    assert result.reported_malicious is None


def test_hash_length_must_match_algorithm() -> None:
    with pytest.raises(ValidationError):
        LookupHashInput(file_hash="ab" * 16, algorithm="sha256")
    parsed = LookupHashInput(file_hash="AB" * 32, algorithm="sha256")
    assert parsed.file_hash == "ab" * 32


def test_domain_tool_rejects_urls() -> None:
    with pytest.raises(ValidationError):
        LookupDomainInput(domain="https://evil.example")


def test_mitre_query_rejects_bad_technique_id() -> None:
    with pytest.raises(ValidationError):
        SearchMitreInput(query="powershell", technique_id="t1059")
    parsed = SearchMitreInput(query="powershell", technique_id="T1059.001")
    assert parsed.technique_id == "T1059.001"
