# Evaluations

`python -m sentinel.evals run --output-dir <dir>` runs the checked-in dataset and writes `report.json` and `report.md` in that directory. The command prints the same counts. This file does not copy them.

The dataset is synthetic. `evals/dataset.json` says so, and the report header says so. The cases are not live alerts and not customer incidents.

## What is executed

The runner builds the tool registry with `demo_mode` on. IP, hash, CVE, and DNS lookups use mock providers (`mock:abuseipdb`, `mock:virustotal`, `mock:osv`, `mock:dns`). Those labels mean the row is not live intelligence. `demo_mode` is not a fallback for a failed live call.

Listed fixture indicators in `src/sentinel/services/providers/fixtures.py` may carry canned verdicts. An unlisted IP or hash stays unknown. An unlisted domain raises `ProviderError`. MITRE search reads the checked-in Enterprise subset. An injected OSV transport and a failing resolver stay in the runner as a second offline guard. Nothing in the run is downloaded.

The model is `ScriptedEvalModel` in `src/sentinel/evals/model.py`. It is not `OpenAiCompatibleClient`. It does not read dataset labels. It plans tools from indicator fields, in this order: source IP, destination IP, file hash, CVE, domain, then at most one `search_mitre` query. The query comes from the first match in a fixed keyword table against title, description, process, and command line. `raw_event`, `metadata`, usernames, and text inside the untrusted-data markers are not scanned. The report narrative is a constant. It does not name indicators.

One case does not use that model. Conflicting intelligence is two synthetic evidence rows, sources `synthetic:row-a` and `synthetic:row-b`, passed through `correlate`, `verify_report`, and `score_confidence`. The mock provider is one provider and cannot disagree with itself. The rows are not a second vendor response. That case adds nothing to the token counter because the model is not called.

## Dataset labels

Every `expected_classification`, `expected_tools`, `expected_report`, `expected_verification`, and `must_not_classify_as` value is in `evals/dataset.json`. The runner reads those fields. It does not choose them. `label_note` is explanation for a reader. It is not parsed into a label.

The cases are: clearly benign activity, malicious IP activity, suspicious PowerShell, a credential-attack shape, a malware-hash shape (the digest is synthetic, not a published sample), a known public CVE id, an ambiguous alert, conflicting synthetic rows, a failed domain lookup, and prompt injection embedded in a log.

## Metrics

Each metric is a count from the run.

Classification agreement. Observed classification on a stored report, compared with `expected_classification`. A case with no stored report does not agree. The scenario labels are not rewritten when the mock returns a null verdict. A null `reported_malicious` or a null hash count is not benign and not malicious. `classification_from_evidence` stays inconclusive in that situation. Disagreement is the measurement. It is not a quality target.

Tool-selection agreement. Cases that declare `expected_tools` are compared with the tools the scripted model selected, in order. A case that sets `expected_tools` to null is left out. pytest checks that the plan matches those labels. That pytest check is a regression check against the scripted model. It is not a score threshold. CI does not fail on this share.

Evidence grounding. `verify_report` accepts the stored report, and the issue list is empty, when the case label is `accepted`. If the label is an issue code, that code is present. Cases with `expected_verification` null are left out. The missing-intelligence case is left out because the lookup fails before a report exists.

MITRE citation. Every technique on a stored report appears in a cited `search_mitre` result. If one does not, the case fails this metric. A stored report with no technique passes, because there is nothing to cite. That pass does not mean the case was mapped. `mitre_techniques_on_reports` is the count of techniques that were on reports, so an empty list is visible. Cases with no report are left out.

Schema compliance. Share of cases whose dataset label `expected_report` is true and whose stored report validates as `IncidentReport`. The command exits non-zero when this share is not total. CI runs that command and checks the same fields in `report.json`. This is a regression check against the scripted model and the `expected_report` labels. It is not a classification threshold. The missing-intelligence case is labeled `expected_report: false` because a failed lookup does not store a report.

Unsupported-claim count. The number of verifier issue codes on the run. A rejection is not renamed to a hallucination percentage.

Injection checks. For each prompt-injection case the runner records three booleans: the system prompt object stayed the same and every system message was one of the two constants; an unknown tool name appeared in `tool_history`; the status was `COMPLETE` with no review. The report prints those as counts. There is no detector in this milestone, and these counts are not a resistance percentage. Milestone 7 already showed the control is separation plus the closed tool set. The scripted model does not follow text in the log. A count of zero unknown tools is that fact about this model, not a claim about a hosted model.

Excluded label. The missing-intelligence case is labeled `must_not_classify_as: BENIGN`. An absent classification is not `BENIGN`. The command exits non-zero if that label is violated. That is the failed-lookup rule, not a threshold chosen to raise agreement.

Average tool calls. `tool_calls_made` summed across cases, divided by the number of cases. A provider error is not recorded as a completed tool call. The conflicting case contributes zero.

Wall-clock latency. `time.perf_counter` around the case loop. It is not a hosted-model latency.

Estimated cost. `estimated_cost_usd` is 0. No price table is configured, and the scripted model does not return a provider usage object. `tokens_used` on the investigation state still moves for pipeline cases, because the executor estimates tokens as `len(text) // 4`. That counter is reported as `token_counter_total`. It is not a billed amount and it is not converted into dollars. The conflicting case adds 0 because the model is not called.

## What a number is not

The numbers measure this pipeline plus `ScriptedEvalModel` on this synthetic set. They do not measure a hosted model. They are not a detection rate, a benchmark ranking, or a comparison with a vendor product. They are not live threat intelligence. `verify_report` and `score_confidence` are unchanged. The runner does not weaken either one to move a count.
