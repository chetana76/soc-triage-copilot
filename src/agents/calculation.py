"""
Calculation agent (deterministic custom agent - NO LLM).

Computes the CVSS base score with a fixed formula. If the vector is malformed or
missing, it records a scoring_error instead of guessing, which the Policy agent
turns into a fail-safe human review.
"""

from ..cvss_scorer import score_vector
from ..core import severity_band
from ..notifier import post_slack


def calculation_node(state):
    vector = state.get("cvss_vector")
    try:
        score = score_vector(vector)
        band = severity_band(score)
        note = post_slack(f":bar_chart: *Stage 2 · Calculation* — CVSS {score} ({band.upper()}) "
                          f"[deterministic]")
        return {
            "cvss_score": score,
            "severity_band": band,
            "scoring_error": None,
            "notifications": state.get("notifications", []) + [{"stage": "calculation", **note}],
            "log": state.get("log", []) + [f"calc: score={score} band={band} (deterministic)"],
        }
    except Exception as e:
        note = post_slack(f":warning: *Stage 2 · Calculation* — scoring FAILED ({e}); fail safe to a human")
        return {
            "cvss_score": None,
            "severity_band": "unknown",
            "scoring_error": str(e),
            "notifications": state.get("notifications", []) + [{"stage": "calculation", **note}],
            "log": state.get("log", []) + [f"calc: SCORING ERROR ({e}) -> fail safe to human"],
        }
