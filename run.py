"""
Run a single alert end-to-end through the multi-agent graph.

Usage:
    python run.py                # runs ALERT-001
    python run.py ALERT-006      # runs a specific alert id

When the Policy agent pauses for approval, you'll be prompted in the console.
"""

import json
import sys
import uuid
import os

from langgraph.types import Command
from src.graph import build_graph
from src.llm import llm_was_used

DATA = os.path.join(os.path.dirname(__file__), "data", "alerts.json")


def load_alert(alert_id):
    with open(DATA) as f:
        alerts = json.load(f)
    if alert_id:
        for a in alerts:
            if a["id"] == alert_id:
                return a
        raise SystemExit(f"No alert with id {alert_id}")
    return alerts[0]


def main():
    alert_id = sys.argv[1] if len(sys.argv) > 1 else None
    alert = load_alert(alert_id)
    graph = build_graph()
    config = {"configurable": {"thread_id": str(uuid.uuid4())}}

    print(f"\n=== Triaging {alert['id']}: {alert['title']} ===")
    result = graph.invoke({"alert": alert, "log": []}, config)

    # Handle the HITL pause/resume loop.
    while "__interrupt__" in result:
        payload = result["__interrupt__"][0].value
        print("\n--- HUMAN APPROVAL REQUIRED ---")
        print(f"  Alert:    {payload.get('alert_id')}")
        print(f"  Reason:   {payload.get('reason')}")
        print(f"  CVSS:     {payload.get('cvss_score')}  KEV={payload.get('on_kev')}")
        print(f"  Proposed: {payload.get('proposed_action')}")
        ans = input("  Approve action? [approve/deny]: ").strip().lower() or "deny"
        decision = "approve" if ans.startswith("a") else "deny"
        result = graph.invoke(Command(resume=decision), config)

    print("\n=== EXECUTION TRACE ===")
    for line in result.get("log", []):
        print("  -", line)

    print("\n=== DECISION ===")
    print(f"  CVSS score:    {result.get('cvss_score')} ({result.get('severity_band')})")
    print(f"  Gate:          {result.get('gate_decision')}")
    print(f"  Human:         {result.get('human_decision')}")
    print(f"  Action result: {result.get('action_result')}")

    print("\n=== NOTIFICATIONS (Slack) ===")
    notes = result.get("notifications", [])
    if not notes:
        print("  (none)")
    for n in notes:
        state_str = "skipped (no webhook)" if n.get("skipped") else ("posted ✓" if n.get("ok") else "error")
        print(f"  - [{n['stage']:<11}] {state_str}: {n.get('text','')}")

    draft = result.get("email_draft") or {}
    if draft:
        print("\n=== EMAIL DRAFT (not sent — for analyst review) ===")
        print(f"  Saved to: {draft.get('path')}")
        print(f"  Subject:  {draft.get('subject')}")

    print("\n=== REPORT ===")
    print(result.get("report"))
    print(f"\n[observability] live Nebius LLM used this run: {llm_was_used()}")


if __name__ == "__main__":
    main()
