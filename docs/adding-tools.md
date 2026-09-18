# Adding a tool

This document is a stub. Milestone 3 defines the registry, and milestone 10 expands this page into a contributor guide.

A tool added later must:

- Have a dedicated input model and output model (`extra=forbid`).
- Be registered by name in the closed tool enum. No generic HTTP or shell tool.
- Treat provider payloads as untrusted data.
- Refuse to run when its credential is missing, rather than returning a guessed verdict.

None of that machinery is implemented. `src/sentinel/tools/base.py` is only the `Protocol`.
