"""
Deterministic CVSS scoring.

This is the heart of the CfoE-style "custom agent" idea: a security severity
score must NEVER come from an LLM, because the same input could yield different
numbers. Instead we compute the official CVSS v3.x base score from the vector
string with a fixed formula (via the `cvss` library). Identical input -> identical
output, every single time. That determinism is what makes the system trustworthy.
"""

from cvss import CVSS3


def score_vector(vector: str) -> float:
    """
    Compute the CVSS v3.x base score from a vector string, e.g.
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> 9.8

    Raises ValueError / CVSSError on a malformed or missing vector; callers are
    expected to catch this and route the alert to a human (fail safe).
    """
    if not vector or not isinstance(vector, str):
        raise ValueError("missing CVSS vector")
    return float(CVSS3(vector).base_score)
