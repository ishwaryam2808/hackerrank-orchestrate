import csv
from pathlib import Path

class PolicyEngine:
    def __init__(self, dataset_dir: Path):
        self.rules = {}
        rules_file = dataset_dir / "deletion_rules.csv"
        if rules_file.exists():
            with open(rules_file, mode="r", encoding="utf-8", errors="ignore") as fp:
                reader = csv.reader(fp)
                for row in reader:
                    if not row or len(row) < 4:
                        continue
                    rule_id = row[0].strip()
                    category = row[1].strip()
                    condition = row[2].strip()
                    action = row[3].strip()
                    self.rules[category.upper()] = {
                        "rule_id": rule_id,
                        "condition": condition,
                        "action": action.upper()
                    }

    def get_action(self, category: str) -> str:
        rule = self.rules.get(category.upper())
        if rule:
            return rule["action"]
        return "DELETE"