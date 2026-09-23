"""Sentinel Agent.

The package validates alerts, runs a bounded investigation through a closed
tool set, and stores a verified report for human review. It does not execute
remediation.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sentinel-agent")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]
