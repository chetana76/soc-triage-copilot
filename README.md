# SOC Alert Triage Copilot

A multi-agent system that triages security alerts from intake to containment.
Specialized agents enrich an alert with live threat intel, score its severity
**deterministically**, pause for **human approval** before any irreversible
action, and produce an analyst-ready report. Built with LangGraph.

Architecturally modeled on the hackathon-winning CfoE pattern: an LLM team for
reasoning + a *deterministic custom node* for the score nobody should trust an
LLM with + a hard human-in-the-loop safety gate + a rigorous eval suite.

## The agents

| Agent | Role | Type |
|---|---|---|
| **Monitor** | Enriches the alert via NVD (CVE details) + CISA KEV (actively exploited?) | LLM + tools |
| **Calculation** | Computes the CVSS base score from a fixed formula | **Deterministic – no LLM** |
| **Policy / HITL** | Decides auto-resolve vs. pause; `interrupt()`s for human approval | LLM hint + deterministic gate |
| **Reporting** | Writes the incident report | LLM |

Flow: `Monitor → Calculation → Policy → Reporting`, orchestrated as a LangGraph
state machine with a SQLite checkpointer (so the HITL pause genuinely persists
and resumes).

### Why deterministic scoring?
A severity score must be reproducible. The Calculation agent bypasses the LLM
entirely and runs the official CVSS v3.x formula (`cvss` lib): identical input →
identical score, every run. That is the system's trust guarantee.

### Why a human gate?
Isolating a production host is irreversible. The Policy agent **pauses the whole
workflow** when the score is at/above the threshold, when the CVE is on the CISA
KEV list, or when scoring fails — and waits for a human to approve or deny.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env     # add your NEBIUS_API_KEY for the live model call
```

The pipeline runs **without any keys** (offline LLM fallback) so you can verify
everything immediately. Add the Nebius key for the graded live generation.

## Run

```bash
python run.py              # triage ALERT-001 (a critical -> will pause for you)
python run.py ALERT-007    # a high-but-below-threshold alert -> auto-resolves
python run.py ALERT-014    # malformed vector -> fails safe to a human
```

When it pauses, approve/deny at the prompt — that is the human-in-the-loop gate.

## Evaluate (Week 4 deliverable)

```bash
python -m eval.run_eval
```

Runs fully offline against the deterministic core, so it's 100% reproducible.
Reports, CfoE-style:
- **Determinism**: every CVSS score identical across 10 runs
- **Gate accuracy** with a confusion matrix — the key metric is **zero false
  negatives** (never silently auto-resolve something that needed a human)
- **Severity-band accuracy**
- **Per-category** breakdown (critical / KEV-override / boundary / edge cases)

Current result on the 16-alert set: 100% band + gate accuracy, 0 FP / 0 FN.

## Maps to course concepts
- Multi-agent system (4 specialized agents + sequential orchestrator)
- Custom deterministic tool/agent (CVSS scorer)
- Built-in/live tools (NVD + CISA KEV grounding)
- Long-running operation (HITL `interrupt()` pause/resume via checkpointer)
- State management (shared `TriageState`, SQLite persistence)
- Observability (per-run execution trace + LLM-usage flag)
- Evaluation harness with category-level analytics

## Optional extensions (if you have time before the deadline)
- Set `ENABLE_LIVE_NVD=1` to pull real CVE data + KEV status at runtime.
- Add a Notifier: POST the final report to a Discord/Slack webhook (~5 lines).
- Swap the in-memory analyst directory into the Monitor agent for "verify caller".

## Submission checklist
- [ ] GitHub repo pushed
- [ ] `.env` NOT committed (only `.env.example`)
- [ ] 5-min demo video: show one auto-resolve, one pause+approve, one fail-safe,
      then `python -m eval.run_eval`
- [ ] Google Doc: overview, architecture diagram, the prompts you used while
      vibe-coding, iterations, and what you learned (lean on the eval numbers)
