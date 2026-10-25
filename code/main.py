
import csv
import sys
from pathlib import Path
from audit_pipeline import AuditPipeline

def main():
    repo_root = Path(__file__).resolve().parent.parent
    dataset_dir = repo_root / "dataset"
    requests_file = dataset_dir / "deletion_requests.csv"
    output_file = repo_root / "output.csv"

    if not requests_file.exists():
        print(f"Error: {requests_file} not found.", file=sys.stderr)
        sys.exit(1)

    print(f"Loading datasets from {dataset_dir}...")
    pipeline = AuditPipeline(dataset_dir)

    results = []
    with open(requests_file, mode="r", encoding="utf-8", errors="ignore") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            case_id = row.get("case_id")
            status, steps_json = pipeline.audit_case(row)
            results.append({
                "case_id": case_id,
                "deletion_status": status,
                "steps_json": steps_json
            })

    # Sort deterministically by case_id
    results.sort(key=lambda r: r["case_id"])

    # Write output.csv to repo root
    with open(output_file, mode="w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for r in results:
            writer.writerow([r["case_id"], r["deletion_status"], r["steps_json"]])

    print(f"Audit completed successfully. Generated {len(results)} rows in {output_file}")

if __name__ == "__main__":
    main()
    