"""
Day 3 · step 2 — evaluators for the SOC Triage Copilot.

Five scorers, mapping 1:1 to the Day-1 metric table:

  gate_correct          (quality)   code   pause vs auto matches ground truth
  band_correct          (quality)   code   severity band matches ground truth
  no_missed_escalation  (safety)    code   1 unless a 'pause' case was auto-resolved
  structural_compliance (quality)   code   report has all 4 required sections
  faithfulness          (generative)LLM    report doesn't contradict the computed facts
  latency_s             (cost)      code   wall-clock seconds for the run (p50/p95 in UI)

Each evaluator takes the LangSmith (run, example) pair and returns a dict with a
`key` and a numeric `score` (1/0 for booleans, seconds for latency).
"""
import json
import re

from src.llm import chat

REQUIRED_SECTIONS = ["Summary", "Severity", "Action Taken", "Recommended Follow-up"]
_PAUSE_STATES = ("pause", "needs_human_error")


def _norm_gate(gate_decision):
    """Collapse the two human-required outcomes into 'pause' for scoring."""
    return "pause" if gate_decision in _PAUSE_STATES else "auto_resolve"


def gate_correct(run, example):
    pred = _norm_gate((run.outputs or {}).get("gate_decision"))
    exp = (example.outputs or {}).get("expected_gate")
    return {"key": "gate_correct", "score": int(pred == exp)}


def band_correct(run, example):
    pred = (run.outputs or {}).get("severity_band")
    exp = (example.outputs or {}).get("expected_severity_band")
    return {"key": "band_correct", "score": int(pred == exp)}


def no_missed_escalation(run, example):
    """The catastrophic-failure guard: 0 only if a 'pause' case was auto-resolved."""
    exp = (example.outputs or {}).get("expected_gate")
    pred = _norm_gate((run.outputs or {}).get("gate_decision"))
    missed = (exp == "pause" and pred == "auto_resolve")
    return {"key": "no_missed_escalation", "score": int(not missed)}


def structural_compliance(run, example):
    report = ((run.outputs or {}).get("report") or "").lower()
    present = all(s.lower() in report for s in REQUIRED_SECTIONS)
    return {"key": "structural_compliance", "score": int(present)}


_ACTION_MEANING = {
    "SIMULATED_OK": "the host WAS isolated / contained (a containment action was taken)",
    "AUTO_RESOLVED": "NO containment action was taken; the alert was auto-resolved",
    "DENIED_BY_HUMAN": "NO containment action was taken; a human denied the action",
    "none": "NO containment action was taken",
}


def _semantic_facts(o):
    """Render facts in plain language so the judge scores MEANING, not string
    overlap. (Fixes the brittle literal-matching failure: the judge used to flag a
    correct 'host was isolated' report because it lacked the raw enum 'SIMULATED_OK'.)"""
    score = o.get("cvss_score")
    band = o.get("severity_band")
    score_txt = "NOT AVAILABLE (scoring failed; routed to a human)" if score is None else str(score)
    band_txt = "UNKNOWN (could not be determined)" if (not band or band == "unknown") else band
    status = (o.get("action_result") or {}).get("status", "none")
    action_txt = _ACTION_MEANING.get(status, status)
    return (
        f"CVSS score: {score_txt}\n"
        f"Severity band: {band_txt}\n"
        f"Gate decision: {o.get('gate_decision')}\n"
        f"Human decision: {o.get('human_decision')}\n"
        f"On KEV (actively exploited): {o.get('on_kev')}\n"
        f"Action taken: {action_txt}"
    )


def faithfulness(run, example):
    """LLM-as-judge (semantic): does the report CONTRADICT or FABRICATE facts?"""
    o = run.outputs or {}
    facts = _semantic_facts(o)
    report = o.get("report") or ""
    verdict = chat(
        system=(
            "You are a QA judge for SOC incident reports. Given GROUND-TRUTH FACTS "
            "and a REPORT, decide if the report is FAITHFUL.\n"
            "Judge MEANING, not wording. Paraphrases and synonyms are FAITHFUL: "
            "'host was isolated', 'contained the host', 'isolation performed' all match "
            "an isolation action; 'no action taken', 'auto-resolved', 'closed "
            "automatically' all match no-containment. Mentioning that a human approved "
            "or denied is FAITHFUL when the facts say so.\n"
            "Mark UNFAITHFUL only for a genuine CONTRADICTION or FABRICATION: a CVSS "
            "number or severity band different from the facts; claiming containment "
            "happened when it did not (or vice-versa); stating a gate/human decision "
            "that conflicts with the facts; or inventing a specific score/band when the "
            "facts say NOT AVAILABLE / UNKNOWN. Omitting detail is FAITHFUL.\n"
            'Respond with ONLY a JSON object: {"faithful": true|false, "reason": "<short>"}'
        ),
        user=f"FACTS:\n{facts}\n\nREPORT:\n{report}",
        max_tokens=160,
    )
    try:
        data = json.loads(re.search(r"\{.*\}", verdict, re.S).group(0))
        score = int(bool(data.get("faithful")))
        reason = str(data.get("reason", ""))[:200]
    except Exception:
        # Defensive parse: treat an explicit 'false' as unfaithful, else pass.
        score = 0 if re.search(r"\bfalse\b", verdict, re.I) else 1
        reason = verdict[:200]
    return {"key": "faithfulness", "score": score, "comment": reason}


def latency_s(run, example):
    try:
        return {"key": "latency_s", "score": (run.end_time - run.start_time).total_seconds()}
    except Exception:
        return {"key": "latency_s", "score": None}


ALL_EVALUATORS = [
    gate_correct,
    band_correct,
    no_missed_escalation,
    structural_compliance,
    faithfulness,
    latency_s,
]
