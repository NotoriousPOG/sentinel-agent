# Security notes

This document is a stub. Milestone 7 turns it into operator-facing security guidance and links each claim to a test.

Current constraints, already enforced by types or by the absence of code:

- The application does not shell out.
- The application does not fetch arbitrary URLs.
- The application does not execute remediation.
- Provider credentials are configuration (`SecretStr`) and no client reads them yet.
- Do not commit `.env`.

`docs/threat-model.md` is the companion stub.
