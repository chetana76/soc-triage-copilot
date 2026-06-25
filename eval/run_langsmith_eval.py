__import__("dotenv").load_dotenv(override=True)
"""
Day 3 · step 3 — run the baseline experiment in LangSmith.

Wraps the real LangGraph agent as the eval `target`, auto-resolving the HITL
pause non-interactively (the gate DECISION is what we score, not the human's
click), runs every dataset example through it, applies the evaluators, and
prints the experiment URL plus a quick latency summary.

Usage:
    python -m eval.run_langsmith_eval                 # resumes paused cases with 'approve'
    EVAL_RESUME=deny python -m eval.run_langsmith_eval
"""
import os
import uuid
import statistics

from langgraph.types import Command
from src.graph import build_graph
from eval.evaluators import ALL_EVALUATORS

try:                                   # SDK moved this symbol around across versions
    from langsmith import evaluate
except ImportError:                    # pragma: no cover
    from langsmith.evaluation import evaluate

DATASET = "soc-triage-golden"
RESUME_DECISION = os.getenv("EVAL_RESUME", "approve")

# One in-memory graph reused across examples; unique thread_id isolates each run.
GRAPH = build_graph(":memory:")


def target(inputs: dict) -> dict:
    """Run one alert end-to-end and return the fields the evaluators score."""
    alert = inputs["alert"]
    cfg = {"configurable": {"thread_id": str(uuid.uuid4())}}
    result = GRAPH.invoke({"alert": alert, "log": [], "notifications": []}, cfg)

    # Non-interactive HITL: drive the pause to completion with a fixed policy.
    guard = 0
    while "__interrupt__" in result and guard < 3:
        result = GRAPH.invoke(Command(resume=RESUME_DECISION), cfg)
        guard += 1

    return {
        "cvss_score": result.get("cvss_score"),
        "severity_band": result.get("severity_band"),
        "gate_decision": result.get("gate_decision"),
        "human_decision": result.get("human_decision"),
        "action_result": result.get("action_result"),
        "on_kev": result.get("on_kev"),
        "cve_id": result.get("cve_id"),
        "report": result.get("report"),
    }


def main():
    print(f"Running baseline experiment over '{DATASET}' "
          f"(HITL resume = {RESUME_DECISION})...\n")
    results = evaluate(
        target,
        data=DATASET,
        evaluators=ALL_EVALUATORS,
        experiment_prefix="baseline",
        max_concurrency=1,            # sequential: safe with the sqlite checkpointer + interrupts
        metadata={"phase": "day3-baseline", "resume": RESUME_DECISION},
    )

    # Latency summary (p50/p95) from the collected results.
    lat = []
    for r in results:
        for ev in (r.get("evaluation_results", {}) or {}).get("results", []):
            if getattr(ev, "key", None) == "latency_s" and ev.score is not None:
                lat.append(ev.score)
    if lat:
        lat.sort()
        p95 = lat[max(0, round(0.95 * len(lat)) - 1)]
        print(f"\nLatency  p50={statistics.median(lat):.2f}s  "
              f"p95={p95:.2f}s  max={max(lat):.2f}s  (n={len(lat)})")

    print("\nBaseline done. Open the experiment in LangSmith to read per-metric "
          "averages and to slice by the `scenario` metadata. The experiment link "
          "is printed just above this summary.")


if __name__ == "__main__":
    main()
