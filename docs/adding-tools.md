# Adding a tool

The tool set is closed. `ToolRegistry` in `src/sentinel/tools/registry.py` accepts only `ToolName`. An unknown name raises `UnknownTool` before a provider is called. There is no default tool, no shell tool, and no tool that fetches an arbitrary URL.

Adding a tool means extending that enum, the typed models, and the registry constructor. It does not grant `subprocess`, `eval`, or a client that takes a host from the alert.

## What you must not add

- Do not add `exec`, `run_shell`, `fetch_url`, or any name that runs a process or fetches a caller-supplied URL.
- Do not add an input field that is a command line, a shell string, or a URL to fetch. Alert text must not become a process argument.
- Do not build a request host, scheme, or path from alert text or from tool arguments. Hosts are constants in `src/sentinel/services/http.py`.
- Do not call a vendor SDK from the tool. Vendor I/O stays behind a protocol in `src/sentinel/services/threat_intel.py`.
- Do not return a benign or "clean" result when a credential is missing or a call fails. Missing credentials are `ConfigurationError`. Timeout and non-200 are `ProviderError`.
- Do not use a mock as the fallback when a live call fails. `demo_mode` chooses the provider once, in `build_providers`.

## Steps

1. Add a value to `ToolName` in `src/sentinel/schemas/tools.py`.
2. Add an input model and an output model. Both use `extra="forbid"`. Type the fields. An IP is `IPvAnyAddress`. A hash, CVE, domain, or technique id goes through the normalizers in `src/sentinel/schemas/patterns.py`. A free string is acceptable only when it is a search query with a length bound, as `SearchMitreInput.query` is. It is not a command and not a URL.
3. Register both models in `TOOL_INPUT_MODELS` and `TOOL_OUTPUT_MODELS`. `ToolRegistry.call` validates arguments with the input model and the provider result with the output model. Invalid arguments are a model-output failure. An output that fails validation becomes `ProviderError`.
4. Add a class in `src/sentinel/tools/builtin.py` with `name` set to that `ToolName` and `run` accepting the validated input model. `run` calls one provider method and returns that provider's output model.
5. If the tool needs a new provider shape, add a `Protocol` in `src/sentinel/services/threat_intel.py`. Implement it under `src/sentinel/services/providers/`. Construct it in `build_providers`.
6. Register the class in `build_registry`. The constructor requires the mapping to be exactly `set(ToolName)`. A missing name raises `ValueError` at startup. There is no plugin loader.
7. If the client makes HTTP calls, add the host to the constants in `src/sentinel/services/http.py` and to `ALLOWED_HOSTS`. Add the path rule in `_path_allowed`. The current hosts are `api.abuseipdb.com` (`/api/v2/check`), `www.virustotal.com` (`/api/v3/files/{hash}`), and `api.osv.dev` (`/v1/vulns/{id}`). Build the URL from those constants. Pass `timeout_seconds`. `HttpxAllowlistTransport` sets `follow_redirects=False`. `enforce_allowlist` rejects any other scheme, host, port, userinfo, query, fragment, or path before a socket is opened.
8. DNS is not HTTP. `lookup_domain` uses an injected resolver. A new name lookup must not fetch the name over HTTP.
9. Set reliability in `src/sentinel/tools/policy.py` by provider name. Do not read reliability, a verdict, or a score out of the provider body. An unknown provider name is `unknown`.
10. A mock, if you need one for `demo_mode`, is constructed only in `build_providers` when the flag is on. Its `provider` starts with `mock:`. Label the payload synthetic. Do not construct it inside an `except` on the live client. Canned verdicts belong in `src/sentinel/services/providers/fixtures.py` and only for indicators the examples or evals actually use. An unlisted indicator stays unknown or fails closed.
11. Add a test that an unknown name still raises `UnknownTool`, that a bad argument does not call the provider, and, if you added a host, that `enforce_allowlist` rejects a different host. Do not weaken `verify_report` or the confidence formula to make the new tool look conclusive.

`tool_call_key` caches a repeat inside one process. The cache is not a reason to skip validation. Redis is not used.
