import csv
import json
import sys
from pathlib import Path

def evaluate():
    repo_root = Path(__file__).resolve().parent.parent.parent
    dataset_dir = repo_root / "dataset"
    sample_requests_file = dataset_dir / "sample_deletion_requests.csv"
    sample_ground_truth_file = dataset_dir / "sample_output.csv"

    if not sample_ground_truth_file.exists():
        print(f"Ground truth {sample_ground_truth_file} not found.")
        sys.exit(1)

    # Load ground truth
    ground_truth = {}
    with open(sample_ground_truth_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ground_truth[row["case_id"]] = {
                "deletion_status": row["deletion_status"],
                "steps": json.loads(row["steps_json"])
            }

    # Run pipeline on sample requests
    sys.path.insert(0, str(repo_root / "code"))
    from audit_pipeline import AuditPipeline
    pipeline = AuditPipeline(dataset_dir)

    total = len(ground_truth)
    status_matches = 0
    step_count_matches = 0

    with open(sample_requests_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = row["case_id"]
            if cid not in ground_truth:
                continue
            pred_status, pred_steps_json = pipeline.audit_case(row)
            pred_steps = json.loads(pred_steps_json)
            truth = ground_truth[cid]

            if pred_status == truth["deletion_status"]:
                status_matches += 1
            if len(pred_steps) == len(truth["steps"]):
                step_count_matches += 1
            else:
                print(f"\n[MISMATCH: {cid}]")
                print(f"  Predicted ({len(pred_steps)} steps): {[s['operation'] for s in pred_steps]}")
                print(f"  Expected  ({len(truth['steps'])} steps): {[s['operation'] for s in truth['steps']]}")
                for s in truth["steps"]:
                    print(f"    -> {s['phase']} | {s['operation']} | {s['system_id']} | {s['resource_id']}")
    status_acc = (status_matches / total) * 100 if total else 0
    step_acc = (step_count_matches / total) * 100 if total else 0

    print(f"Sample Evaluation Results (Total: {total}):")
    print(f"  Deletion Status Accuracy: {status_acc:.2f}% ({status_matches}/{total})")
    print(f"  Step Count Match:         {step_acc:.2f}% ({step_count_matches}/{total})")

if __name__ == "__main__":
    evaluate()
