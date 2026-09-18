"""Wazuh alert documents copied from Wazuh's own documentation.

These are fixtures, not a client. Nothing here talks to a Wazuh manager.

``wazuh_logtest_ssh_alert.json`` is the ``data.output`` object from the first
logtest request on
https://documentation.wazuh.com/current/user-manual/ruleset/testing.html
(retrieved 2026-09-18). It is not the logtest wrapper (``error``, ``token``,
``messages``).

``wazuh_auditd_dynamic_fields_alert.json`` is the JSON output on
https://documentation.wazuh.com/current/user-manual/ruleset/decoders/dynamic-fields.html
(retrieved 2026-09-18). ``rule.id`` is a number in that example, and the
timestamp is ``2017 Feb 07 15:57:53`` with no offset. That object has no
top-level ``id``.

Static decoder field names used by the mapper are the ones Wazuh lists under
"Static fields" on
https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html
"""

import json
from pathlib import Path
from typing import Any

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(name: str) -> dict[str, Any]:
    document = json.loads((_FIXTURES / name).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise TypeError(f"{name} must be a JSON object")
    return document


def wazuh_logtest_ssh_alert() -> dict[str, Any]:
    """Return a fresh copy of the documented sshd logtest alert."""
    return _load("wazuh_logtest_ssh_alert.json")


def wazuh_auditd_dynamic_fields_alert() -> dict[str, Any]:
    """Return a fresh copy of the documented auditd alert, which has no ``id``."""
    return _load("wazuh_auditd_dynamic_fields_alert.json")
