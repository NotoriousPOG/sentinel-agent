"""Write the JSON and Markdown reports from one run. This module does not recompute metrics."""

from pathlib import Path

from sentinel.evals.results import Count, EvalReport

_HEADER = (
    "Synthetic dataset. These cases are not live alerts. "
    "demo_mode rows are labeled mock: and are not live intelligence. "
    "Listed fixture indicators may carry canned verdicts; unknown IPs stay null. "
    "The conflicting-intelligence case uses synthetic evidence rows, not a second vendor. "
    "CVE and DNS in this run use mock providers. An injected transport remains as a "
    "second offline guard and is not an OSV download. "
    "The model is scripted-eval, in process. It is not a hosted model. "
    "A number below is a count from this run. It is not a detection rate, "
    "not a jailbreak resistance percentage, not a hallucination percentage, "
    "not a benchmark ranking, and not a comparison with a vendor product."
)


def write_reports(report: EvalReport, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    markdown_path = output_dir / "report.md"
    json_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def render_markdown(report: EvalReport) -> str:
    metrics = report.metrics
    average = metrics.tool_calls_total / metrics.case_count
    lines = [
        "# Sentinel offline evaluation",
        "",
        _HEADER,
        "",
        f"Dataset notice: {report.notice}",
        "",
        f"Dataset file: `{report.dataset_path}`",
        "",
        "Model: `scripted-eval`. Hosted model: no. Live network: no.",
        "",
        "## Metrics",
        "",
        "| Metric | Result |",
        "| --- | --- |",
        f"| Classification agreement | {_ratio(metrics.classification_agreement)} |",
        f"| Tool-selection agreement | {_ratio(metrics.tool_selection_agreement)} |",
        f"| Evidence grounding | {_ratio(metrics.evidence_grounding)} |",
        f"| MITRE citation | {_ratio(metrics.mitre_citation)} |",
        f"| MITRE techniques on reports | {metrics.mitre_techniques_on_reports} |",
        f"| Schema compliance | {_ratio(metrics.schema_compliance)} |",
        f"| Unsupported-claim count | {metrics.unsupported_claim_count} |",
        f"| Injection cases | {metrics.injection.cases} |",
        (
            "| Injection: system prompt stayed constant | "
            f"{metrics.injection.system_prompt_constant} |"
        ),
        f"| Injection: unknown tool ran | {metrics.injection.unknown_tool_ran} |",
        (f"| Injection: COMPLETE without a review | {metrics.injection.complete_without_review} |"),
        f"| Excluded label avoided | {_ratio(metrics.excluded_label_avoided)} |",
        f"| Average tool calls | {average:.3f} ({metrics.tool_calls_total}/{metrics.case_count}) |",
        f"| Wall-clock seconds | {metrics.wall_clock_seconds:.6f} |",
        f"| Token counter total | {metrics.token_counter_total} |",
        f"| Estimated cost USD | {metrics.estimated_cost_usd} |",
        "",
        metrics.estimated_cost_reason,
        "",
        "Schema compliance is the share of cases whose dataset label `expected_report` "
        "is true and whose stored report validates as `IncidentReport`. "
        "That check is a regression check against the scripted model and those labels. "
        "It is not a classification threshold.",
        "",
        "A MITRE pass with no technique on the report means there was no technique to cite. "
        "It does not mean the case was mapped.",
        "",
        "Tool-selection agreement is only over cases that declare `expected_tools`. "
        "That comparison is a regression check against the scripted model.",
        "",
        "## Cases",
        "",
    ]
    for case in report.cases:
        lines.append(f"### {case.case_id}")
        lines.append("")
        lines.append(f"Kind: `{case.kind}`. Synthetic: yes. Live intelligence: no.")
        lines.append("")
        lines.append(case.summary)
        lines.append("")
        lines.append(f"Label note: {case.label_note}")
        lines.append("")
        lines.append(
            f"Expected classification: `{case.expected_classification}`. "
            f"Observed: `{case.observed_classification}`."
        )
        lines.append("")
        lines.append(f"Status: `{case.status}`. Providers: {_providers(case.providers)}.")
        lines.append("")
        lines.append(case.notes)
        lines.append("")
    return "\n".join(lines)


def format_summary(report: EvalReport, *, json_path: Path, markdown_path: Path) -> str:
    metrics = report.metrics
    average = metrics.tool_calls_total / metrics.case_count
    rows = [
        "Sentinel offline evaluation",
        "synthetic: true",
        "model: scripted-eval (not a hosted model)",
        "live_network: false",
        f"json: {json_path}",
        f"markdown: {markdown_path}",
        f"classification_agreement: {_ratio(metrics.classification_agreement)}",
        f"tool_selection_agreement: {_ratio(metrics.tool_selection_agreement)}",
        f"evidence_grounding: {_ratio(metrics.evidence_grounding)}",
        f"mitre_citation: {_ratio(metrics.mitre_citation)}",
        f"mitre_techniques_on_reports: {metrics.mitre_techniques_on_reports}",
        f"schema_compliance: {_ratio(metrics.schema_compliance)}",
        f"unsupported_claim_count: {metrics.unsupported_claim_count}",
        f"injection_cases: {metrics.injection.cases}",
        f"injection_system_prompt_constant: {metrics.injection.system_prompt_constant}",
        f"injection_unknown_tool_ran: {metrics.injection.unknown_tool_ran}",
        f"injection_complete_without_review: {metrics.injection.complete_without_review}",
        f"excluded_label_avoided: {_ratio(metrics.excluded_label_avoided)}",
        f"average_tool_calls: {average:.3f}",
        f"wall_clock_seconds: {metrics.wall_clock_seconds:.6f}",
        f"token_counter_total: {metrics.token_counter_total}",
        f"estimated_cost_usd: {metrics.estimated_cost_usd}",
        metrics.estimated_cost_reason,
    ]
    return "\n".join(rows)


def _ratio(count: Count) -> str:
    return f"{count.numerator}/{count.denominator}"


def _providers(providers: list[str]) -> str:
    if not providers:
        return "(none)"
    rendered: list[str] = []
    for provider in providers:
        if provider.startswith("mock:"):
            rendered.append(f"{provider} (not live intelligence)")
        elif provider.startswith("synthetic:"):
            rendered.append(f"{provider} (synthetic row, not a vendor)")
        elif provider == "osv":
            rendered.append("osv (injected transport, not a live call)")
        else:
            rendered.append(provider)
    return ", ".join(rendered)
