"""
Day 3 · step 4 — cluster the failures from the latest baseline experiment.

Reads the most recent experiment over the `soc-triage-golden` dataset straight
from LangSmith (no re-running the agent), then prints every row that scored 0 on
any evaluator, grouped by scenario, with the LLM judge's reason for each
faithfulness miss. That grouping is the failure-cluster table for the report.

Usage:
    python -m eval.show_failures
    EXPERIMENT=baseline-1a2b3c python -m eval.show_failures   # pin a specific run
"""
__import__("dotenv").load_dotenv(override=True)

import os
from collections import defaultdict

from langsmith import Client

DATASET = "soc-triage-golden"


def main():
    client = Client()
    ds = client.read_dataset(dataset_name=DATASET)

    # Pick the experiment: env override, else the newest one over this dataset.
    want = os.getenv("EXPERIMENT")
    sessions = list(client.list_projects(reference_dataset_id=ds.id))
    if not sessions:
        print("No experiments found for this dataset. Run eval.run_langsmith_eval first.")
        return
    if want:
        sessions = [s for s in sessions if s.name == want] or sessions
    exp = sorted(sessions, key=lambda s: s.start_time, reverse=True)[0]
    print(f"Experiment: {exp.name}\n")

    # Map example_id -> (alert_id, scenario) for labelling failures.
    ex_meta = {}
    for ex in client.list_examples(dataset_id=ds.id):
        m = ex.metadata or {}
        ex_meta[str(ex.id)] = (m.get("alert_id", "?"), m.get("scenario", "?"))

    runs = list(client.list_runs(project_name=exp.name, is_root=True))
    run_ids = [r.id for r in runs]
    ex_of = {r.id: str(r.reference_example_id) for r in runs}

    # Pull all feedback for these runs in one sweep.
    fb = defaultdict(dict)          # run_id -> {metric: (score, comment)}
    for f in client.list_feedback(run_ids=run_ids):
        fb[f.run_id][f.key] = (f.score, f.comment)

    clusters = defaultdict(list)
    for rid in run_ids:
        aid, scen = ex_meta.get(ex_of.get(rid, ""), ("?", "?"))
        for metric, (score, comment) in fb.get(rid, {}).items():
            if metric == "latency_s":
                continue
            if score is not None and score < 1:
                clusters[scen].append((aid, metric, comment))

    if not clusters:
        print("No sub-1.0 failures found. Clean sweep.")
        return

    print("FAILURES BY SCENARIO")
    print("=" * 60)
    for scen in ("happy", "edge", "known_failure", "adversarial"):
        rows = sorted(clusters.get(scen, []))
        if not rows:
            continue
        print(f"\n[{scen}]  ({len(rows)} failing checks)")
        for aid, metric, comment in rows:
            line = f"  {aid:11s} {metric}=0"
            if comment:
                line += f"   reason: {str(comment)[:140]}"
            print(line)
    print("\n" + "=" * 60)
    total = sum(len(v) for v in clusters.values())
    print(f"{total} failing checks across {len(clusters)} scenario cluster(s).")


if __name__ == "__main__":
    main()
