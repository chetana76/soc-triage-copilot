"""Reporting agent (LLM): turns the run into a concise analyst-facing report."""

from ..llm import chat
from ..notifier import post_slack, write_email_draft


def reporting_node(state):
    alert = state["alert"]
    report_input = (
        f"Alert ID: {alert.get('id')}\n"
        f"Title: {alert.get('title')}\n"
        f"Host: {alert.get('host')}\n"
        f"CVE: {state.get('cve_id')}\n"
        f"CVSS score: {state.get('cvss_score')} ({state.get('severity_band')})\n"
        f"Actively exploited (KEV): {state.get('on_kev')}\n"
        f"Gate decision: {state.get('gate_decision')}\n"
        f"Human decision: {state.get('human_decision')}\n"
        f"Action taken: {state.get('action_result')}\n"
        f"Analyst context: {state.get('monitor_summary')}\n"
    )

    body = chat(
        system=(
            "You are a SOC triage assistant. Write a short incident report with "
            "sections: Summary, Severity, Action Taken, Recommended Follow-up. "
            "Be concise and factual."
        ),
        user=report_input,
        max_tokens=450,
    )

    # Produce a reviewable email draft (never auto-sent) from the full outcome.
    draft = write_email_draft({**state, "report": body})
    note = post_slack(f":memo: *Stage 4 · Reporting* — {alert.get('id')}: report ready; "
                      f"email draft saved to {draft['path']}")

    return {
        "report": body,
        "email_draft": draft,
        "notifications": state.get("notifications", []) + [{"stage": "reporting", **note}],
        "log": state.get("log", []) + ["reporting: report generated + email draft written"],
    }
