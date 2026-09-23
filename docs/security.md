# Security notes

Operator notes for controls the test suite checks. Claims without a test are not listed. This is not a prompt-injection detector. See [threat-model.md](threat-model.md) for the corpus and the fake model that follows hostile text.

## What is enforced

| Control | Test |
| --- | --- |
| Alert fields that are data are listed in `UNTRUSTED_ALERT_FIELDS`. A new field fails the suite. | `test_untrusted_registry_matches_alert_fields` |
| Investigation and report system prompts are constants. Logs, usernames, URLs, domains, and command lines appear only inside `<<<UNTRUSTED_DATA>>>` markers. | `test_system_prompt_construction_keeps_fields_inside_markers` |
| A hostile corpus (instruction overrides, fake tool calls, HTML, long Unicode), including logs, usernames, URLs, domains, and process arguments, does not add a tool, change those constants, or validate as a tool call unless the text is a tool argument. | `test_corpus_cannot_become_instructions` |
| `exec`, `run_shell`, and `fetch_url` are unknown-tool failures. The provider is not called. | `test_corpus_cannot_become_instructions`, `test_tool_raw_cannot_add_a_shell_or_fetch_a_url` |
| Text inside a `search_mitre` query does not add a shell tool. | `test_search_mitre_argument_does_not_add_a_shell` |
| Tool `raw` that says to call a shell or fetch a URL does not add a tool and does not fetch that URL. | `test_tool_raw_cannot_add_a_shell_or_fetch_a_url` |
| The same class of `raw`, or alert text that says to mark the host safe, does not set classification or confidence. Those come from `classification_from_evidence` and `score_confidence`. | `test_tool_raw_cannot_mark_the_host_safe`, `test_hostile_wording_does_not_change_the_confidence_score` |
| `COMPLETE` is an approved analyst review, not alert text. | `test_approving_the_conclusion_is_the_only_completion` |
| Approving remediation does not execute anything. There is no remediation executor. | `test_remediation_approval_has_no_executor` |
| The tool set has no shell and no arbitrary URL fetch. | `test_closed_set_has_no_shell_or_fetch_tool` |
| Package source does not call `subprocess`, `os.system`, `os.popen`, `eval(`, or `exec(`. | `test_package_source_does_not_invoke_a_shell` |
| Provider HTTP is allowlisted. AbuseIPDB’s URL is the constant, not alert text. DNS does not HTTP-fetch the name. An OSV lookup makes one transport call, to the vulnerability URL, and stores reference strings. | `test_allowlist_rejects_other_schemes_and_hosts`, `test_abuseipdb_does_not_invent_a_verdict_or_put_the_key_in_the_url`, `test_dns_uses_the_injected_resolver_and_does_not_fetch`, `test_osv_does_not_invent_cvss_or_fetch_reference_urls` |
| API keys are not in `repr`, `/health`, tool results, or logs. | `test_api_key_is_not_in_repr`, `test_health_does_not_echo_secrets`, `test_provider_key_is_absent_from_tool_result_and_logs` |
| When `SENTINEL_API_KEY` is set, alert, investigation, and metrics routes reject a missing or wrong key. `/health` and `/ready` stay open. The presented key is not in the 401 body or the log. | `test_data_routes_reject_a_missing_or_wrong_key`, `test_bearer_and_header_are_accepted`, `test_health_and_ready_stay_open_when_a_key_is_set` |
| A configured `SecretStr` does not appear in logs captured during a fake investigation. The alert command line is not logged at info. | `test_fake_investigation_hides_secret_and_command_line` |
| One low-reliability source cannot score 100. The score is the factor total. | `test_one_low_reliability_source_cannot_score_100` |

Do not commit `.env`. `.env.example` has placeholders.

## What this does not do

The suite does not show a detector. HTML in an alert is stored and placed in the data channel; it is not stripped (`test_corpus_cannot_become_instructions`, case `html`). Instruction phrases are not removed.

The fake model follows the payload on purpose. A passing run means the executor refused an unknown tool or ignored the text when setting classification. It does not mean a live model will refuse.

There is no denylist. There is no eval score in this document.
