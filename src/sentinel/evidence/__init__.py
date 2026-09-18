"""Link tool results, score confidence, and check that a report stays inside them.

``score_confidence`` sets ``weighted_evidence_v1`` booleans. ``verify_report``
does not. No network and no model calls.
"""

from sentinel.evidence.correlate import correlate
from sentinel.evidence.score import score_confidence
from sentinel.evidence.verify import apply_verification, verify_report

__all__ = ["apply_verification", "correlate", "score_confidence", "verify_report"]
