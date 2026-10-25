import sys
from pathlib import Path

# Ensure 'code/' directory is on sys.path regardless of where the test is run from
CODE_DIR = Path(__file__).resolve().parent.parent
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

import json
import unittest
from classifier import classify_request
from audit_pipeline import OP_ORDER, PHASE_ORDER

class TestDeletionAgent(unittest.TestCase):
    def test_intent_classification(self):
        self.assertEqual(classify_request("Please delete my account and personal data."), "DELETION")
        self.assertEqual(classify_request("Export my data for GDPR compliance"), "NOT_APPLICABLE")
        self.assertEqual(classify_request("Update my phone number to +1-555-0199"), "NOT_APPLICABLE")
        self.assertEqual(classify_request("I want to unsubscribe from marketing"), "NOT_APPLICABLE")

    def test_operation_sorting_order(self):
        steps = [
            {"phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT", "system_id": "sys_b", "resource_id": "res_1"},
            {"phase": "FINDING", "operation": "REPORT_ACTIVE_DATA_FLOW", "system_id": "sys_a", "resource_id": "res_2"},
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "sys_a", "resource_id": "res_1"},
            {"phase": "REMEDIATION", "operation": "DISABLE_DATA_FLOW", "system_id": "sys_a", "resource_id": "res_2"},
        ]

        def sort_key(s):
            return (
                PHASE_ORDER.get(s["phase"], 99),
                OP_ORDER.get(s["operation"], 99),
                s["system_id"],
                s["resource_id"]
            )

        sorted_steps = sorted(steps, key=sort_key)
        self.assertEqual(sorted_steps[0]["operation"], "REPORT_REMAINING_RECORD")
        self.assertEqual(sorted_steps[1]["operation"], "REPORT_ACTIVE_DATA_FLOW")
        self.assertEqual(sorted_steps[2]["operation"], "DISABLE_DATA_FLOW")
        self.assertEqual(sorted_steps[3]["operation"], "VERIFY_RECORD_ABSENT")

if __name__ == "__main__":
    unittest.main()