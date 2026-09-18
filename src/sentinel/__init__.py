"""Sentinel Agent.

The package validates alerts, stores them, and looks up indicators through a
closed tool set. It does not run an investigation.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sentinel-agent")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]
