"""
Pure, side-effect-free triage logic.

This module deliberately contains NO LLM calls and NO network calls.
Both the live LangGraph agents AND the offline eval harness import these
functions, which is what makes our safety behaviour reproducible and testable.
"""

from .config import PAUSE_THRESHOLD


def severity_band(score):
    """Map a CVSS base score to the standard CVSS v3.1 qualitative band."""
    if score is None:
        return "unknown"
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def decide_gate(score, on_kev=False, scoring_error=None, threshold=PAUSE_THRESHOLD):
    """
    Decide whether this alert can be auto-resolved or must pause for a human.

    Policy (deliberately simple and auditable):
      * If we could not score it           -> needs_human_error  (fail safe -> human)
      * If it is on the CISA KEV list       -> pause             (actively exploited)
      * If score >= the pause threshold     -> pause             (too dangerous to auto-act)
      * Otherwise                           -> auto_resolve

    Returns one of: "auto_resolve", "pause", "needs_human_error".
    """
    if scoring_error:
        return "needs_human_error"
    if on_kev:
        return "pause"
    if score is not None and score >= threshold:
        return "pause"
    return "auto_resolve"


def requires_human(gate_decision):
    """True if the gate decision means a human must approve before acting."""
    return gate_decision in ("pause", "needs_human_error")
