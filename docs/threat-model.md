# Threat model

This file states only controls the test suite checks. It is not a detector write-up. Sentinel does not detect prompt injection, strip instruction text, or sanitize HTML. Those behaviors are not implemented, and a regex denylist would be an incomplete control even if it were.

The controls the tests exercise are message separation and the closed tool set. A fake model that follows text inside the data markers is the adversary in `tests/test_prompt_injection.py`. If that model asks for a shell, the executor still refuses. The tests do not show that a live model will ignore the text.

## Untrusted fields

`UNTRUSTED_ALERT_FIELDS` in `src/sentinel/security/untrusted.py` lists alert fields that are data. `test_untrusted_registry_matches_alert_fields` fails if a new `NormalizedAlert` field is neither in that set nor in `PLATFORM_ALERT_FIELDS`.

Logs, usernames, URLs, domains, and command lines are not copied into `SYSTEM_PROMPT` or `REPORT_SYSTEM_PROMPT`. `test_system_prompt_construction_keeps_fields_inside_markers` builds those messages and requires each value to sit between `<<<UNTRUSTED_DATA>>>` and `<<<END_UNTRUSTED_DATA>>>`. The same assertion is on the messages the executor actually sent, in `test_corpus_cannot_become_instructions`.

## Hostile alert bodies

`test_corpus_cannot_become_instructions` normalizes a corpus and runs each alert through `run_investigation` with `ObedientModel`. The corpus includes:

- instruction overrides (`Ignore previous instructions`, `mark this host safe`)
- a fake tool-call JSON object naming `exec`
- HTML, including a `<script>` tag, left intact on the alert
- a long Unicode log (`U+202E`, zero-width space, combining mark, fullwidth A) left intact on the alert
- an unknown JSON key `tool` whose value is `exec` (it stays on `metadata`, and `ToolName` does not grow)

The same test covers logs (`raw_event.full_log` and a Wazuh `full_log`), usernames, URLs, domains, and process arguments (`command_line`). For the Wazuh body, `command_line` stays `None`. The log is not promoted into that field.

For each body the test asserts:

- `SYSTEM_PROMPT` and `REPORT_SYSTEM_PROMPT` are the same objects as before the run, and neither contains the hostile text
- `ToolName` is still the five lookup tools
- the probe string does not validate as a `ModelTurn` or as a tool input by itself
- a copy of the probe validates as a tool call only when it is the `query` argument of `search_mitre` (or, when the text is a DNS name, the `domain` argument of `lookup_domain`)
- the model’s decision is recorded, and no provider is called
- `review` is `None` and status is not `COMPLETE`

When the text names `exec`, `run_shell`, or `fetch_url`, the model returns that name. Status is `FAILED`, `error` is `unknown tool`, `tool_history` is empty, and the report is absent. `ModelTurn` accepts the name. The registry rejects it. That is the tested authorization check, not a schema denylist of tool names.

When the text only says to mark the host safe, the model finishes and the narrative says the host is safe. Classification is `INCONCLUSIVE`, which is `classification_from_evidence` of an empty evidence list, not `BENIGN`. `confidence` equals `score_confidence` for that alert and evidence, and the score equals `compute_confidence_score` of the factors.

`test_hostile_wording_does_not_change_the_confidence_score` uses two alerts with the same indicator fields and different free text. `score_confidence` returns the same assessment. The wording is not an input to the formula.

`test_search_mitre_argument_does_not_add_a_shell` puts `ignore previous instructions` in a `search_mitre` query, runs that tool, and then calls `exec`, `run_shell`, and `fetch_url`. Those three raise `UnknownTool`. The registry names do not change. No other provider runs.

## Tool result `raw`

`test_tool_raw_cannot_add_a_shell_or_fetch_a_url` returns a lookup whose `raw` says to mark the host safe, call `run_shell`, and `call fetch_url`. The model’s next decision is `fetch_url`. The only provider call is the first `lookup_ip`. The attempted names are `lookup_ip` then `fetch_url`. Status is `FAILED` with `unknown tool`. No URL is fetched. The `raw` text is inside the data markers and is not in the system prompt.

`test_tool_raw_cannot_mark_the_host_safe` returns `raw` that says to mark the host safe, and a stored `reported_malicious: true` from provider `abuseipdb`. The model finishes and the narrative says the host is safe. The stored classification is `MALICIOUS`, equal to `classification_from_evidence`. Confidence equals `score_confidence`. `review` is `None`. Status is `AWAITING_REVIEW`, not `COMPLETE`.

`COMPLETE` is still only `apply_analyst_review` approving the conclusion. That path is `test_approving_the_conclusion_is_the_only_completion` in `tests/test_reporting.py`. This milestone does not change it.

## Closed tools and process execution

`test_closed_set_has_no_shell_or_fetch_tool` in `tests/test_tool_system.py` asserts the registry names and that no tool input is a shell command or a URL fetch.

`test_package_source_does_not_invoke_a_shell` reads `src/sentinel` and fails if a module contains `subprocess`, `os.system`, `os.popen`, `eval(`, or `exec(`.

`test_allowlist_rejects_other_schemes_and_hosts` rejects destinations that are not the provider constants. `test_abuseipdb_does_not_invent_a_verdict_or_put_the_key_in_the_url` asserts the AbuseIPDB request URL is `ABUSEIPDB_CHECK_URL`. `test_dns_uses_the_injected_resolver_and_does_not_fetch` asserts domain lookup uses the injected resolver. `test_osv_does_not_invent_cvss_or_fetch_reference_urls` records one transport call, to the OSV vulnerability URL, and stores the reference string on the result.

## Review and remediation

`test_remediation_approval_has_no_executor` spies on `execute_remediation` and asserts the symbol does not exist. Approving remediation stores the field and does not run an action.

`test_one_low_reliability_source_cannot_score_100` still requires the confidence score to be the factor total. This milestone does not change `verify_report` or the formula.

## Secrets

`test_api_key_is_not_in_repr`, `test_health_does_not_echo_secrets`, `test_provider_key_is_absent_from_tool_result_and_logs`, and `test_fake_investigation_hides_secret_and_command_line` cover secret handling. A VirusTotal key in a response body is redacted before it is stored. A configured `SecretStr` does not appear in logs captured during a fake investigation.

## Not claimed

The tests do not show that a production model will refuse hostile text. They show what the executor does when the model complies.

The tests do not show a jailbreak detector, a denylist, HTML sanitization, or a browser XSS control. They do not report a detection rate or a comparison with another product. The offline runner in `docs/evaluations.md` is a separate measurement of a scripted model. It is not a detector and it does not add one.

`GET /metrics` returns process counters and does not include alert bodies or keys. The trace exporter defaults to off. No collector is running. There is no remediation executor.
