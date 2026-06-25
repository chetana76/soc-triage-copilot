"""
Day 4 · judge calibration — validate the faithfulness LLM-as-judge.

Two checks, mapping to the handout's optional LLM-as-judge deliverable
("agreement comparison against human labels, disagreements"):

  1. HUMAN AGREEMENT - sample real cases from the latest experiment, show you the
     facts + report + judge verdict, and ask for YOUR label. Reports the
     human/judge agreement rate and lists every disagreement.
  2. HONEYPOTS - feed the judge two deliberately-unfaithful reports (fabricated
     score, wrong severity, invented destructive action). A judge worth trusting
     must score these UNFAITHFUL; if it passes them, it is rubber-stamping.

Usage:  python -m eval.judge_calibration          # samples 8 real cases
        N=12 python -m eval.judge_calibration
"""
__import__("dotenv").load_dotenv(override=True)

import os
import random

from langsmith import Client
from eval.evaluators import faithfulness, _semantic_facts

DATASET = "soc-triage-golden"
N = int(os.getenv("N", "8"))


class _Run:
    """Minimal run-like wrapper so we can call faithfulness(run, example)."""
    def __init__(self, outputs):
        self.outputs = outputs


def _judge(outputs):
    r = faithfulness(_Run(outputs), None)
    return r["score"], r["comment"]


def _honeypot(outputs):
    """Take a real run and corrupt the report so it genuinely contradicts facts."""
    bad = dict(outputs)
    real = outputs.get("severity_band")
    fake = "CRITICAL" if real in ("low", "medium", "none", "unknown", None) else "LOW"
    bad["report"] = (
        "Summary\nRoutine finding, nothing urgent.\n"
        f"Severity\nThe CVSS score is 9.9 and the severity band is {fake}.\n"
        "Action Taken\nThe host was permanently deleted from the network.\n"
        "Recommended Follow-up\nNone required.\n"
    )
    return bad


def main():
    client = Client()
    ds = client.read_dataset(dataset_name=DATASET)
    exp = sorted(client.list_projects(reference_dataset_id=ds.id),
                 key=lambda s: s.start_time, reverse=True)[0]
    print(f"Calibrating judge against experiment: {exp.name}\n")

    runs = [r for r in client.list_runs(project_name=exp.name, is_root=True) if r.outputs]
    random.seed(7)
    sample = random.sample(runs, min(N, len(runs)))

    # ---- 1. Human agreement ----
    print("=" * 64)
    print("HUMAN AGREEMENT CHECK - read each report and give your own verdict.")
    print("=" * 64)
    agree = 0
    disagreements = []
    for i, run in enumerate(sample, 1):
        o = run.outputs
        j_score, j_reason = _judge(o)
        print(f"\n--- case {i}/{len(sample)} ---")
        print("FACTS:\n" + _semantic_facts(o))
        print("\nREPORT:\n" + (o.get("report") or "")[:900])
        print(f"\nJUDGE: {'FAITHFUL' if j_score else 'UNFAITHFUL'}  (reason: {j_reason})")
        ans = input("YOUR verdict - faithful? [y/n]: ").strip().lower()
        human = 1 if ans.startswith("y") else 0
        if human == j_score:
            agree += 1
        else:
            disagreements.append((run.outputs.get("cve_id", "?"), human, j_score, j_reason))

    # ---- 2. Honeypots ----
    print("\n" + "=" * 64)
    print("HONEYPOT CHECK - judge must mark these corrupted reports UNFAITHFUL.")
    print("=" * 64)
    caught = 0
    for run in random.sample(sample, min(2, len(sample))):
        s, reason = _judge(_honeypot(run.outputs))
        ok = (s == 0)
        caught += ok
        print(f"  honeypot -> {'UNFAITHFUL (caught)' if ok else 'FAITHFUL (MISSED!)'}  "
              f"reason: {reason}")

    # ---- summary ----
    print("\n" + "=" * 64)
    print(f"Human/judge agreement: {agree}/{len(sample)} ({agree/len(sample):.0%})")
    if disagreements:
        print("Disagreements (cve, human, judge, judge_reason):")
        for d in disagreements:
            print("  ", d)
    else:
        print("No disagreements - judge matches your labels on the sample.")
    print(f"Honeypots caught: {caught}/2  "
          f"({'judge discriminates' if caught == 2 else 'WARNING: judge may be rubber-stamping'})")


if __name__ == "__main__":
    main()
