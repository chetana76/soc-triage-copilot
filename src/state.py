"""The shared state object that flows through every node in the graph."""

from typing import TypedDict, Optional, List, Dict, Any


class TriageState(TypedDict, total=False):
    # --- input ---
    alert: Dict[str, Any]

    # --- Monitor agent outputs (grounding) ---
    cve_id: Optional[str]
    cvss_vector: Optional[str]
    on_kev: bool
    enrichment: Dict[str, Any]
    monitor_summary: str

    # --- Calculation agent outputs (deterministic) ---
    cvss_score: Optional[float]
    severity_band: str
    scoring_error: Optional[str]

    # --- Policy / HITL agent outputs ---
    gate_decision: str          # auto_resolve | pause | needs_human_error
    proposed_action: str
    human_decision: Optional[str]   # approve | deny | auto
    action_result: Dict[str, Any]

    # --- Reporting agent output ---
    report: str

    # --- notifications ---
    notifications: List[Dict[str, Any]]
    email_draft: Dict[str, Any]

    # --- observability ---
    log: List[str]
