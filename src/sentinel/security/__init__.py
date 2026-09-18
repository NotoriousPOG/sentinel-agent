"""Security boundaries.

Runtime prompt-injection defenses are milestone 7. See ``untrusted.py`` for the
field registry that those defenses must honor, and ``docs/architecture.md`` for
the structural controls that already apply (no shell tool, no arbitrary URL
tool, schema rejection of unknown keys).
"""
