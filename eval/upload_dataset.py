__import__("dotenv").load_dotenv(override=True)
"""
Day 3 · step 1 — upload the golden dataset to LangSmith.

Reads data/golden_dataset.json and creates (or tops up) a LangSmith dataset.
Labels live in `outputs`; the alert (minus its ground_truth) is the `inputs`,
so the agent never sees the answer. Scenario/category ride along as metadata,
which lets you slice metrics by happy/edge/known_failure/adversarial in the UI.

Idempotent: re-running only adds alerts that aren't already in the dataset.

Usage:  python -m eval.upload_dataset
"""
import json
import os

from langsmith import Client

DATA = os.path.join(os.path.dirname(__file__), "..", "data", "golden_dataset.json")
DATASET = "soc-triage-golden"


def main():
    alerts = json.load(open(DATA))
    client = Client()

    if client.has_dataset(dataset_name=DATASET):
        ds = client.read_dataset(dataset_name=DATASET)
        existing = {
            (ex.metadata or {}).get("alert_id")
            for ex in client.list_examples(dataset_id=ds.id)
        }
        print(f"Dataset '{DATASET}' exists with {len(existing)} examples.")
    else:
        ds = client.create_dataset(
            DATASET,
            description="SOC Alert Triage Copilot golden set: 41 labelled cases "
                        "(happy/edge/known_failure/adversarial). Labels computed "
                        "from the deterministic cvss_scorer + core.",
        )
        existing = set()
        print(f"Created dataset '{DATASET}'.")

    inputs, outputs, metadata = [], [], []
    for a in alerts:
        if a["id"] in existing:
            continue
        gt = a["ground_truth"]
        alert_no_labels = {k: v for k, v in a.items() if k != "ground_truth"}
        inputs.append({"alert": alert_no_labels})
        outputs.append({
            "expected_gate": gt["expected_gate"],
            "expected_severity_band": gt["expected_severity_band"],
        })
        metadata.append({
            "alert_id": a["id"],
            "scenario": gt["scenario"],
            "category": gt["category"],
        })

    if not inputs:
        print("Nothing to add — dataset already up to date.")
    else:
        client.create_examples(
            inputs=inputs, outputs=outputs, metadata=metadata, dataset_id=ds.id
        )
        print(f"Added {len(inputs)} new examples.")

    total = sum(1 for _ in client.list_examples(dataset_id=ds.id))
    print(f"Dataset '{DATASET}' now holds {total} examples.")
    print(f"View it: https://smith.langchain.com  ->  Datasets  ->  {DATASET}")


if __name__ == "__main__":
    main()
