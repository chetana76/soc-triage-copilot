"""
LangGraph wiring.

Sequential orchestration (Monitor -> Calculation -> Policy -> Reporting),
chosen deliberately for auditability over speed - the same justification CfoE
used. The SQLite checkpointer persists state so the Policy interrupt can pause
and resume across separate invocations (real pause/resume, not a fake prompt).
"""

import sqlite3
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.sqlite import SqliteSaver

from .state import TriageState
from .agents.monitor import monitor_node
from .agents.calculation import calculation_node
from .agents.policy import policy_node
from .agents.reporting import reporting_node


def build_graph(checkpoint_path: str = "checkpoints.sqlite"):
    conn = sqlite3.connect(checkpoint_path, check_same_thread=False)
    checkpointer = SqliteSaver(conn)

    g = StateGraph(TriageState)
    g.add_node("monitor", monitor_node)
    g.add_node("calculation", calculation_node)
    g.add_node("policy", policy_node)
    g.add_node("reporting", reporting_node)

    g.add_edge(START, "monitor")
    g.add_edge("monitor", "calculation")
    g.add_edge("calculation", "policy")
    g.add_edge("policy", "reporting")
    g.add_edge("reporting", END)

    return g.compile(checkpointer=checkpointer)
