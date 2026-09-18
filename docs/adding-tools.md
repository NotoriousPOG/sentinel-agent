# Adding a tool

Tools are a closed set. `ToolRegistry` accepts only `ToolName`. Unknown names raise `UnknownTool`. There is no default tool, no shell tool, and no tool that fetches an arbitrary URL.

To add one:

1. Add a `ToolName` value and an input model and output model with `extra=forbid`. Register both in `TOOL_INPUT_MODELS` and `TOOL_OUTPUT_MODELS`.
2. Add a class with `name` and `run`. Construct it in `build_registry`. The registry refuses a set that is not exactly those names.
3. Put vendor I/O behind a protocol in `services/threat_intel.py`. Do not call a vendor SDK from the tool.
4. If the client makes HTTP calls, add the host to the allowlist constants in `services/http.py`. Build the URL from that constant. Pass a timeout. Do not follow redirects. Do not put alert text or tool arguments in the host.
5. A missing credential raises `ConfigurationError`. A timeout or a non-200 raises `ProviderError`. Neither returns a benign or "clean" result.
6. Set reliability in `tools/policy.py` by provider name. Do not read it from the provider body.
7. A mock, if you need one, is constructed only when `demo_mode` is on, and its `provider` starts with `mock:`. Do not use it as the fallback when a live call fails. Label the payload as synthetic.

`lookup_domain` resolves DNS. It does not HTTP-fetch the name. Descriptions and reference URLs returned by other tools are stored as text.
