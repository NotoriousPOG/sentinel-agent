"""Fields that must be treated as data, never as instructions.

This registry is a tripwire for reviewers and tests. It does not sanitize,
detect jailbreaks, or wrap a prompt. Those controls are milestone 7, and they
depend on this list staying complete.
"""

UNTRUSTED_ALERT_FIELDS: frozenset[str] = frozenset(
    {
        "title",
        "description",
        "hostname",
        "username",
        "source_ip",
        "destination_ip",
        "domain",
        "url",
        "file_hash",
        "process",
        "command_line",
        "cve",
        "raw_event",
        "metadata",
        "source",
    }
)

# Constrained by the platform rather than free text. Still not a place to hide
# instructions, but they are not in the free-text channel the prompt builder
# must delimit. Adding a new alert field requires an explicit decision here.
PLATFORM_ALERT_FIELDS: frozenset[str] = frozenset(
    {
        "alert_id",
        "timestamp",
        "severity",
    }
)
