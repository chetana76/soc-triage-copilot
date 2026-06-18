"""
SOC Alert Triage Copilot - demo UI.

Run from the project root:
    pip install streamlit
    streamlit run app.py

Set your Nebius env vars in the SAME terminal first (export ...), so the
Reporting agent makes a live model call.
"""

import json
import time
import uuid
import os

import streamlit as st
from langgraph.types import Command
from src.graph import build_graph
from src.config import PAUSE_THRESHOLD, NEBIUS_API_KEY, NEBIUS_MODEL, SLACK_WEBHOOK_URL, OUTBOX_DIR

st.set_page_config(page_title="SOC Alert Triage Copilot", page_icon="🛡️", layout="wide")

# ---------------- styling ----------------
st.markdown("""
<style>
.block-container {padding-top: 2rem; max-width: 1100px;}
.hero {border-left: 6px solid #2E5C8A; padding: 6px 16px; margin-bottom: 8px;}
.hero h1 {margin: 0; color: #2E5C8A; font-size: 30px;}
.hero p {margin: 2px 0 0 0; color: #667; font-style: italic;}
.card {border-radius: 10px; padding: 14px 16px; margin: 10px 0; border: 1px solid #e3e8ee;
       background: #fbfcfe; box-shadow: 0 1px 3px rgba(0,0,0,0.04);}
.card.pending {opacity: 0.38;}
.card.run {border-color:#E6A23C; box-shadow:0 0 0 2px rgba(230,162,60,.2);}
.card-mon {border-left:6px solid #2E5C8A;}
.card-calc {border-left:6px solid #2E8B57;}
.card-pol {border-left:6px solid #E67E22;}
.card-rep {border-left:6px solid #2E5C8A;}
.card h3 {margin:0 0 4px 0; font-size:17px;}
.dot {height:10px; width:10px; border-radius:50%; display:inline-block; margin-right:8px;}
.d-pending {background:#c8cdd4;}
.d-run {background:#E6A23C;}
.d-done {background:#2E8B57;}
.tag {display:inline-block; font-size:11px; padding:2px 8px; border-radius:10px; margin-left:6px;}
.t-llm {background:#e8f0fb; color:#2E5C8A;}
.t-det {background:#e7f5ec; color:#2E8B57;}
.t-gate {background:#fdf0e3; color:#E67E22;}
.sev {font-weight:700; padding:3px 12px; border-radius:8px; color:#fff; font-size:15px;}
.muted {color:#778; font-size:13px;}
.report {background:#f7f9fc; border:1px solid #e3e8ee; border-radius:10px; padding:16px; white-space:pre-wrap;
         font-size:14px; line-height:1.5;}
</style>
""", unsafe_allow_html=True)

SEV_COLORS = {"critical": "#C0392B", "high": "#E67E22", "medium": "#D4A017",
              "low": "#3498DB", "none": "#7F8C8D", "unknown": "#7F8C8D"}

# ---------------- state ----------------
ss = st.session_state
ss.setdefault("phase", "idle")     # idle | awaiting | done
ss.setdefault("nodes", {})
ss.setdefault("alert", None)
ss.setdefault("interrupt", None)
ss.setdefault("final", {})
ss.setdefault("action", None)

@st.cache_data
def load_alerts():
    with open(os.path.join(os.path.dirname(__file__), "data", "alerts.json")) as f:
        return {a["id"]: a for a in json.load(f)}

ALERTS = load_alerts()

# ---------------- header ----------------
st.markdown('<div class="hero"><h1>🛡️ SOC Alert Triage Copilot</h1>'
            '<p>Multi-agent triage · deterministic CVSS scoring · human-in-the-loop containment</p></div>',
            unsafe_allow_html=True)

# ---------------- sidebar ----------------
with st.sidebar:
    st.subheader("Run a triage")
    ids = list(ALERTS.keys())
    labels = {i: f"{i} — {ALERTS[i]['title'][:34]}" for i in ids}
    chosen = st.selectbox("Incoming alert", ids, format_func=lambda i: labels[i])
    run = st.button("▶  Run Triage", type="primary", use_container_width=True)
    if st.button("↺  Reset", use_container_width=True):
        for k in ("phase", "nodes", "alert", "interrupt", "final", "action"):
            ss[k] = "idle" if k == "phase" else ({} if k in ("nodes", "final") else None)
        st.rerun()

    st.divider()
    st.caption("Configuration")
    st.write(f"Pause threshold: **CVSS ≥ {PAUSE_THRESHOLD}**")
    if NEBIUS_API_KEY:
        st.success(f"Nebius LLM: on\n\n`{NEBIUS_MODEL}`")
    else:
        st.warning("Nebius LLM: offline\n\nReport uses fallback text. Export NEBIUS_API_KEY for a live call.")
    if SLACK_WEBHOOK_URL:
        st.success("Slack: on — posts at each stage")
    else:
        st.info("Slack: off (export SLACK_WEBHOOK_URL to post)")
    st.caption(f"Email drafts → `{OUTBOX_DIR}/`")

# ---------------- card renderer ----------------
AGENTS = [
    ("monitor", "card-mon", "1 · Monitor Agent", '<span class="tag t-llm">LLM + tools</span>'),
    ("calculation", "card-calc", "2 · Calculation Agent", '<span class="tag t-det">deterministic · no LLM</span>'),
    ("policy", "card-pol", "3 · Policy / HITL Agent", '<span class="tag t-gate">safety gate</span>'),
    ("reporting", "card-rep", "4 · Reporting Agent", '<span class="tag t-llm">LLM</span>'),
]

def card_body(node, data):
    if node == "monitor":
        return (f"<div class='muted'>CVE: <b>{data.get('cve_id') or '—'}</b> · "
                f"Actively exploited (KEV): <b>{data.get('on_kev')}</b></div>"
                f"<div style='margin-top:6px'>{(data.get('monitor_summary') or '')[:300]}</div>")
    if node == "calculation":
        if data.get("scoring_error"):
            return (f"<div style='color:#C0392B'><b>Scoring failed:</b> {data['scoring_error']}"
                    f" → fail safe to a human.</div>")
        band = data.get("severity_band", "unknown")
        col = SEV_COLORS.get(band, "#7F8C8D")
        return (f"<span class='sev' style='background:{col}'>CVSS {data.get('cvss_score')} · {band.upper()}</span>"
                f"<div class='muted' style='margin-top:6px'>Computed from the official CVSS v3.1 formula.</div>")
    if node == "policy":
        gate = data.get("gate_decision", "")
        hd = data.get("human_decision", "")
        ar = data.get("action_result", {})
        return (f"<div>Gate decision: <b>{gate}</b></div>"
                f"<div class='muted' style='margin-top:4px'>Proposed: {data.get('proposed_action','—')} · "
                f"Human: <b>{hd}</b> · Action: <b>{ar.get('status','—')}</b></div>")
    if node == "reporting":
        return "<div class='muted'>Incident report generated (see below).</div>"
    return ""

def status_for(node):
    if node in ss.nodes:
        return "done"
    # running = the next node to fire
    order = [a[0] for a in AGENTS]
    done = [a for a in order if a in ss.nodes]
    if ss.phase == "awaiting" and node == "policy":
        return "run"
    nxt = order[len(done)] if len(done) < len(order) else None
    return "run" if node == nxt and ss.action else "pending"

def slack_badge(data):
    notes = data.get("notifications", [])
    if not notes:
        return ""
    n = notes[-1]
    if n.get("skipped"):
        return "<div class='muted' style='margin-top:6px'>🔔 Slack notify (no webhook set)</div>"
    if n.get("ok"):
        return "<div class='muted' style='margin-top:6px'>🔔 Slack notified ✓</div>"
    return "<div class='muted' style='margin-top:6px'>🔔 Slack notify (error)</div>"

def render_pipeline(box):
    with box.container():
        for node, cls, title, tag in AGENTS:
            stt = status_for(node)
            dot = {"done": "d-done", "run": "d-run", "pending": "d-pending"}[stt]
            state_cls = "card pending" if stt == "pending" else ("card run" if stt == "run" else "card")
            if node in ss.nodes:
                body = card_body(node, ss.nodes[node]) + slack_badge(ss.nodes[node])
            elif stt == "run" and ss.phase == "awaiting":
                body = "<div class='muted'>awaiting human approval…</div>"
            else:
                body = "<div class='muted'>waiting…</div>"
            st.markdown(
                f"<div class='{state_cls} {cls}'>"
                f"<h3><span class='dot {dot}'></span>{title}{tag}</h3>{body}</div>",
                unsafe_allow_html=True)

pipe = st.empty()

# ---------------- actions ----------------
if run:
    ss.graph = build_graph(":memory:")
    ss.cfg = {"configurable": {"thread_id": str(uuid.uuid4())}}
    ss.nodes, ss.interrupt, ss.final = {}, None, {}
    ss.alert = ALERTS[chosen]
    ss.phase = "running"
    ss.action = "run"

if ss.action == "run":
    render_pipeline(pipe)
    time.sleep(0.4)
    for chunk in ss.graph.stream({"alert": ss.alert, "log": [], "notifications": []}, ss.cfg, stream_mode="updates"):
        if "__interrupt__" in chunk:
            ss.interrupt = chunk["__interrupt__"][0].value
            break
        for node, upd in chunk.items():
            ss.nodes[node] = upd
            render_pipeline(pipe)
            time.sleep(0.7)
    nxt = ss.graph.get_state(ss.cfg).next
    ss.phase = "awaiting" if nxt else "done"
    if ss.phase == "done":
        ss.final = ss.graph.get_state(ss.cfg).values
    ss.action = None
    render_pipeline(pipe)

elif ss.action in ("approve", "deny"):
    decision = ss.action
    for chunk in ss.graph.stream(Command(resume=decision), ss.cfg, stream_mode="updates"):
        if "__interrupt__" in chunk:
            break
        for node, upd in chunk.items():
            ss.nodes[node] = upd
            render_pipeline(pipe)
            time.sleep(0.7)
    ss.phase = "done"
    ss.final = ss.graph.get_state(ss.cfg).values
    ss.action = None
    render_pipeline(pipe)
else:
    render_pipeline(pipe)

# ---------------- approval panel ----------------
if ss.phase == "awaiting":
    p = ss.interrupt or {}
    st.markdown("### ⏸️ Human approval required")
    reason = p.get("reason", "")
    msg = "could not be scored automatically" if reason == "needs_human_error" else \
          ("is actively exploited / at-or-above threshold" if reason else "needs review")
    st.warning(f"**{p.get('alert_id')}** {msg}. Proposed action: **{p.get('proposed_action')}** "
               f"(CVSS {p.get('cvss_score')}, KEV={p.get('on_kev')}).")
    c1, c2, _ = st.columns([1, 1, 4])
    if c1.button("✅  Approve", type="primary", use_container_width=True):
        ss.action = "approve"; st.rerun()
    if c2.button("🚫  Deny", use_container_width=True):
        ss.action = "deny"; st.rerun()

# ---------------- result panel ----------------
if ss.phase == "done" and ss.final:
    f = ss.final
    st.markdown("### ✅ Triage complete")
    m = st.columns(4)
    m[0].metric("CVSS", f.get("cvss_score") if f.get("cvss_score") is not None else "—")
    m[1].metric("Severity", str(f.get("severity_band", "—")).upper())
    m[2].metric("Outcome", f.get("gate_decision", "—"))
    m[3].metric("Action", f.get("action_result", {}).get("status", "—"))
    st.markdown("#### Incident report")
    st.markdown(f"<div class='report'>{(f.get('report') or '').strip()}</div>", unsafe_allow_html=True)
    live = NEBIUS_API_KEY and "OFFLINE FALLBACK" not in (f.get("report") or "")
    st.caption(f"Live Nebius LLM used for this report: **{bool(live)}**")

    draft = f.get("email_draft") or {}
    if draft:
        with st.expander(f"✉️  Email draft  ·  saved to {draft.get('path')}", expanded=False):
            st.text_input("To", draft.get("to", ""), disabled=True)
            st.text_input("Subject", draft.get("subject", ""), disabled=True)
            st.text_area("Body", draft.get("body", ""), height=240, disabled=True)
            st.caption("This is a reviewable draft — an analyst opens the .eml and sends it.")

    notes = f.get("notifications") or []
    sent = sum(1 for n in notes if n.get("ok"))
    if SLACK_WEBHOOK_URL:
        st.caption(f"🔔 Slack: {sent}/{len(notes)} stage notifications posted.")
    else:
        st.caption(f"🔔 Slack: {len(notes)} stage notifications prepared (set SLACK_WEBHOOK_URL to post).")
