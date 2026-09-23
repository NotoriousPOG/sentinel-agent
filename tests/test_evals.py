"""Offline evaluation runner. No sockets and no hosted model."""

import socket
from pathlib import Path

import pytest

from sentinel.evals.cli import main
from sentinel.evals.dataset import CaseKind, load_dataset
from sentinel.evals.model import plan_tool_names
from sentinel.evals.offline import INJECTED_CVE_ID
from sentinel.evals.reports import render_markdown
from sentinel.evals.runner import execute, schema_compliance_total
from sentinel.services.llm_http import OpenAiCompatibleClient

ROOT = Path(__file__).resolve().parents[1]


def test_dataset_is_synthetic_and_covers_every_kind() -> None:
    dataset = load_dataset()
    assert dataset.synthetic is True
    assert "synthetic" in dataset.notice.casefold()
    kinds = {case.kind for case in dataset.cases}
    assert kinds == set(CaseKind)
    for case in dataset.cases:
        assert case.synthetic is True
        assert case.expected_classification is not None


def test_scripted_tool_plan_matches_dataset_labels() -> None:
    """Regression check against the scripted model, not a score threshold."""
    dataset = load_dataset()
    for case in dataset.cases:
        if case.expected_tools is None:
            continue
        assert plan_tool_names(case.alert) == case.expected_tools


def test_conflicting_case_is_two_synthetic_rows() -> None:
    dataset = load_dataset()
    case = next(item for item in dataset.cases if item.kind is CaseKind.CONFLICTING_INTELLIGENCE)
    assert case.execution == "synthetic_evidence"
    assert case.synthetic_rows is not None
    assert len(case.synthetic_rows) == 2
    sources = [row.source for row in case.synthetic_rows]
    assert all(source.startswith("synthetic:") for source in sources)
    assert len(set(sources)) == 2
    verdicts = {row.reported_malicious for row in case.synthetic_rows}
    assert verdicts == {True, False}


def test_run_is_offline_and_schema_compliance_is_total(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("eval run opened a socket")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    dataset = load_dataset()
    report = execute(dataset, dataset_path=str(ROOT / "evals" / "dataset.json"))
    assert report.synthetic is True
    assert report.hosted_model is False
    assert report.live_network is False
    assert report.model_name == "scripted-eval"
    assert schema_compliance_total(report)
    assert report.metrics.estimated_cost_usd == 0
    assert "price table" in report.metrics.estimated_cost_reason
    assert report.metrics.token_counter_total == sum(case.tokens_used for case in report.cases)
    assert report.metrics.injection.cases == 1
    rendered = render_markdown(report)
    assert "detection_rate" not in rendered
    assert "resistance_percentage" not in rendered
    assert "hallucination_percentage" not in rendered

    missing = next(case for case in report.cases if case.kind == "missing_intelligence")
    assert missing.observed_classification != "BENIGN"
    assert missing.status == "FAILED"
    assert missing.report_stored is False
    assert missing.excluded_label_avoided is True

    conflict = next(case for case in report.cases if case.kind == "conflicting_intelligence")
    assert conflict.contradiction_count is not None
    assert conflict.contradiction_count >= 1
    assert conflict.observed_classification == "INCONCLUSIVE"
    assert all(provider.startswith("synthetic:") for provider in conflict.providers)

    injection = next(case for case in report.cases if case.prompt_injection)
    assert injection.system_prompt_constant is True
    assert injection.unknown_tool_ran is False
    assert injection.complete_without_review is False
    assert injection.status != "COMPLETE"
    assert injection.review_recorded is False

    ip_case = next(case for case in report.cases if case.case_id == "malicious-ip")
    assert any(provider.startswith("mock:") for provider in ip_case.providers)

    hash_case = next(case for case in report.cases if case.case_id == "malware-hash")
    assert any(provider.startswith("mock:") for provider in hash_case.providers)

    assert report.transport_urls == []
    cve_label = next(item for item in dataset.cases if item.case_id == "known-cve")
    assert cve_label.alert.cve == INJECTED_CVE_ID
    cve_case = next(case for case in report.cases if case.case_id == "known-cve")
    assert "mock:osv" in cve_case.providers
    assert "osv" not in cve_case.providers

    exit_code = main(["run", "--output-dir", str(tmp_path)])
    assert exit_code == 0
    text = (tmp_path / "report.md").read_text(encoding="utf-8")
    body = (tmp_path / "report.json").read_text(encoding="utf-8")
    assert "Synthetic dataset" in text
    assert "scripted-eval" in body
    assert "OpenAiCompatibleClient" not in body


def test_eval_package_does_not_construct_the_http_client() -> None:
    package = ROOT / "src" / "sentinel" / "evals"
    for path in package.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "from sentinel.services.llm_http import" not in source
        assert "OpenAiCompatibleClient(" not in source
    assert OpenAiCompatibleClient.__name__ == "OpenAiCompatibleClient"


def test_readme_does_not_copy_eval_metrics() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "classification_agreement" not in text
    assert "detection_rate" not in text
    assert "hallucination" not in text
    assert "python -m sentinel.evals run" in text
