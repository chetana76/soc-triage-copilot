"""
Policy / Human-in-the-Loop agent.

Decides auto_resolve vs pause using the deterministic gate. When a human is
required, it calls LangGraph's interrupt(), which freezes the whole workflow
(state persisted by the checkpointer) until a human approves or denies via resume.
This is the safety mechanism that prevents the agent from isolating a production
host on its own.
"""

from langgraph.types import interrupt
from ..core import decide_gate, requires_human
from ..mock_actions import isolate_host
from ..notifier import post_slack


def policy_node(state):
    score = state.get("cvss_score")
    on_kev = state.get("on_kev", False)
    err = state.get("scoring_error")

    decision = decide_gate(score, on_kev=on_kev, scoring_error=err)
    host = state["alert"].get("host", "unknown-host")
    proposed = f"Isolate host '{host}'"

    updates = {
        "gate_decision": decision,
        "proposed_action": proposed,
        "log": state.get("log", []) + [f"policy: gate={decision}"],
    }

    if not requires_human(decision):
        # Safe enough to resolve without bothering a human.
        updates["human_decision"] = "auto"
        updates["action_result"] = {"status": "AUTO_RESOLVED", "action": "none"}
    else:
        # --- HITL pause: workflow halts here until a human responds ---
        # NOTE: everything ABOVE this line re-runs on resume; the Slack post is
        # placed at the very END so it fires exactly once per outcome.
        human = interrupt({
            "type": "approval_required",
            "alert_id": state["alert"].get("id"),
            "reason": decision,
            "cvss_score": score,
            "on_kev": on_kev,
            "proposed_action": proposed,
            "hint": f"{decision.upper()}: approve '{proposed}'? (approve/deny)",
        })
        updates["human_decision"] = human
        if str(human).lower().startswith("a"):
            updates["action_result"] = isolate_host(host)
        else:
            updates["action_result"] = {"status": "DENIED_BY_HUMAN", "action": "none"}
        updates["log"] = updates["log"] + [f"policy: human={human}"]

    # Single notification for this stage (runs once: after resume, or on auto path).
    status = updates["action_result"].get("status")
    note = post_slack(f":shield: *Stage 3 · Policy* — {state['alert'].get('id')}: gate={decision}, "
                      f"human={updates['human_decision']}, action={status}")
    updates["notifications"] = state.get("notifications", []) + [{"stage": "policy", **note}]
    return updates
