"""Monitor agent (LLM + live grounding): enriches the raw alert with context."""

from .. import nvd_client
from ..llm import chat
from ..notifier import post_slack


def monitor_node(state):
    alert = state["alert"]
    post_slack(f":rotating_light: *━━━━━━ NEW TRIAGE ━━━━━━*\n*{alert.get('id')}* · {alert.get('title')}")
    cve_id = alert.get("cve_id")
    # Start from whatever the alert already carries...
    vector = alert.get("cvss_vector")
    on_kev = alert.get("on_kev", False)

    # ...then try to enrich from live sources (no-op if disabled / offline).
    enrichment = nvd_client.enrich(cve_id)
    vector = enrichment.get("cvss_vector") or vector
    on_kev = enrichment.get("on_kev", on_kev)

    summary = chat(
        system="You are a SOC analyst. In 2 sentences, summarize the threat and why it matters. Be factual.",
        user=(
            f"Alert: {alert.get('title')}\nHost: {alert.get('host')}\n"
            f"CVE: {cve_id}\nDescription: {alert.get('description')}\n"
            f"Actively exploited (KEV): {on_kev}"
        ),
    )

    note = post_slack(f":satellite: *Stage 1 · Monitor* — {alert.get('id')}: {alert.get('title')} "
                      f"(CVE {cve_id}, KEV={on_kev})")

    return {
        "cve_id": cve_id,
        "cvss_vector": vector,
        "on_kev": bool(on_kev),
        "enrichment": enrichment,
        "monitor_summary": summary,
        "notifications": state.get("notifications", []) + [{"stage": "monitor", **note}],
        "log": state.get("log", []) + [f"monitor: enriched {cve_id} (kev={on_kev})"],
    }
