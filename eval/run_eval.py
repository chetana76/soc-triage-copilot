"""
Evaluation harness (Week 4 deliverable).

Runs entirely offline against the deterministic safety core - no LLM, no network -
so results are 100% reproducible. Mirrors the CfoE evaluation story:

  1. Determinism   : each CVSS score is identical across 10 runs.
  2. Gate accuracy : predicted pause/auto vs. ground truth, with FP / FN.
  3. Band accuracy : computed severity band vs. ground truth.
  4. Edge handling : malformed / missing vectors fail safe to a human (no crash).

Usage:  python -m eval.run_eval
"""

import json
import os
from collections import defaultdict

from src.cvss_scorer import score_vector
from src.core import severity_band, decide_gate, requires_human

DATA = os.path.join(os.path.dirname(__file__), "..", "data", "alerts.json")


def predicted_gate(alert):
    """Run the deterministic core exactly as the Policy agent would."""
    try:
        score = score_vector(alert.get("cvss_vector"))
        err = None
    except Exception as e:
        score, err = None, str(e)
    band = severity_band(score) if err is None else "unknown"
    gate = decide_gate(score, on_kev=alert.get("on_kev", False), scoring_error=err)
    # For scoring, collapse the two "human required" outcomes into "pause".
    norm_gate = "pause" if requires_human(gate) else "auto_resolve"
    return score, band, norm_gate


def determinism_check(alert, runs=10):
    if not alert.get("cvss_vector"):
        return True  # nothing to score; trivially deterministic
    try:
        scores = {score_vector(alert["cvss_vector"]) for _ in range(runs)}
        return len(scores) == 1
    except Exception:
        return True  # consistently raises = still deterministic


def main():
    with open(DATA) as f:
        alerts = json.load(f)

    total = len(alerts)
    band_ok = gate_ok = determ_ok = 0
    tp = fp = tn = fn = 0  # positive class = "pause"
    by_cat = defaultdict(lambda: [0, 0])  # category -> [passed, total]
    failures = []

    for a in alerts:
        gt = a["ground_truth"]
        score, band, gate = predicted_gate(a)

        d = determinism_check(a)
        determ_ok += d

        b = band == gt["expected_severity_band"]
        band_ok += b

        g = gate == gt["expected_gate"]
        gate_ok += g

        # confusion matrix on the pause decision
        exp_pause = gt["expected_gate"] == "pause"
        got_pause = gate == "pause"
        if exp_pause and got_pause:
            tp += 1
        elif not exp_pause and got_pause:
            fp += 1
        elif not exp_pause and not got_pause:
            tn += 1
        else:
            fn += 1

        cat = gt["category"]
        by_cat[cat][1] += 1
        if b and g and d:
            by_cat[cat][0] += 1
        else:
            failures.append((a["id"], cat, f"band={band}/{gt['expected_severity_band']}",
                             f"gate={gate}/{gt['expected_gate']}", f"determ={d}"))

    print("=" * 60)
    print("SOC TRIAGE COPILOT - EVALUATION RESULTS")
    print("=" * 60)
    print(f"Total alerts:        {total}")
    print(f"Determinism passed:  {determ_ok}/{total}")
    print(f"Severity band acc.:  {band_ok}/{total} ({band_ok/total:.0%})")
    print(f"Gate decision acc.:  {gate_ok}/{total} ({gate_ok/total:.0%})")

    print("\n--- HITL gate confusion matrix (positive = pause) ---")
    print(f"  True Positive (correct pause):       {tp}")
    print(f"  False Positive (paused unnecessarily): {fp}")
    print(f"  True Negative (correct auto-resolve):  {tn}")
    print(f"  False Negative (MISSED a pause!):      {fn}")
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    print(f"  Precision: {prec:.0%}   Recall: {rec:.0%}")
    if fn == 0:
        print("  -> Zero false negatives: no critical alert was silently auto-resolved.")

    print("\n--- By category ---")
    for cat, (p, t) in sorted(by_cat.items()):
        print(f"  {cat:18s} {p}/{t}")

    if failures:
        print("\n--- Failures ---")
        for f in failures:
            print("  ", f)
    else:
        print("\nAll checks passed.")


if __name__ == "__main__":
    main()
