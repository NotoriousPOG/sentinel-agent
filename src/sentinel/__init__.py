"""Sentinel Agent.

Milestone 1 is a foundation: typed contracts, configuration, and a health
endpoint. It does not investigate alerts.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sentinel-agent")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]
