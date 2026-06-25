# Evaluation Harness (Week 4)

An evaluation layer over the Week-3 SOC Alert Triage Copilot. It builds a labelled
golden dataset, traces every run in LangSmith, scores five quality metrics plus a
latency/cost metric, and validates the LLM-as-judge against human labels.

## What gets measured

| Metric | Type | Method |
|---|---|---|
| No missed escalation | Safety | Code — 0 only if a `pause` case was auto-resolved |
| Gate-decision accuracy | Quality | Code — pause vs auto vs ground truth |
| Severity-band accuracy | Quality | Code — band vs ground truth |
| Report structural compliance | Quality | Code — all 4 report sections present |
| Report faithfulness | Quality (generative) | LLM-as-judge, alert-grounded, human-validated |
| p95 latency / cost per run | Cost | LangSmith traces |

Quality is paired with cost so neither axis can be gamed in isolation.

## Files (`eval/`)

| File | Purpose |
|---|---|
| `upload_dataset.py` | Push `data/golden_dataset.json` (41 cases) to the LangSmith dataset `soc-triage-golden`. Idempotent. |
| `evaluators.py` | The six scorers, including the alert-grounded faithfulness judge. |
| `run_langsmith_eval.py` | Run the agent over the dataset as a LangSmith experiment. Resumes the HITL pause non-interactively. |
| `show_failures.py` | Print per-metric averages + failures clustered by scenario, for the latest experiment. |
| `judge_calibration.py` | Human-vs-judge agreement check + planted-contradiction honeypots. |
| `run_eval.py` | Original offline harness for the deterministic core only (no LLM). |

## Setup

The eval reads everything from `.env` (loaded with `override=True`, so it beats stale
shell exports). Required keys:

```
# Nebius (model + endpoint must be a matching pair)
NEBIUS_API_KEY=...
NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1/
NEBIUS_MODEL=meta-llama/Llama-3.3-70B-Instruct

# LangSmith tracing + eval
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=lsv2_...
LANGCHAIN_PROJECT=soc-triage-copilot
# LANGCHAIN_ENDPOINT=https://eu.api.smith.langchain.com   # only if your key is EU-region
```

Install deps: `pip install -r requirements.txt` (adds `langsmith`).

## Run it

```bash
# 1. Upload the golden dataset to LangSmith (once, or after dataset changes)
python -m eval.upload_dataset

# 2. Run the experiment (creates a new run each time; compare in the LangSmith UI)
python -m eval.run_langsmith_eval
#    EVAL_RESUME=deny python -m eval.run_langsmith_eval   # resume the HITL pause with 'deny' instead

# 3. Read the results: per-metric averages + failures clustered by scenario
python -m eval.show_failures

# 4. Validate the judge: your labels vs the judge, plus honeypots
python -m eval.judge_calibration
```

To run a single alert through the agent against the golden dataset:

```bash
ALERTS_FILE=data/golden_dataset.json python run.py ALERT-040
```

## The faithfulness judge (and why it's validated)

The judge is the riskiest metric, so it was debugged and validated rather than trusted:

- **v1 (literal)** compared the report against raw enum strings — brittle; a clearer
  agent report broke it.
- **v2 (semantic)** scored meaning, not wording — but human calibration showed only
  62% agreement because it couldn't see the alert text to verify threat claims.
- **v3 (alert-grounded)** includes the alert title/description in the judge's facts, so
  threat claims ("RCE", "pre-auth") are verified against the source. Result: 100% human
  agreement on the calibration sample, with planted contradictions still caught 2/2.

Re-run `judge_calibration.py` periodically as the dataset grows to keep the judge honest.
