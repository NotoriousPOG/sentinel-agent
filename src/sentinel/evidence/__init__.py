"""Link tool results to indicators and check that a report stays inside them.

No network, no model calls, and no confidence score.
"""

from sentinel.evidence.correlate import correlate
from sentinel.evidence.verify import apply_verification, verify_report

__all__ = ["apply_verification", "correlate", "verify_report"]
