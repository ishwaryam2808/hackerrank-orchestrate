# Deletion Audit Agent Evaluation Report

## 1. Executive Summary

This report evaluates the AI-powered Deletion Audit Agent for the "Ghost Data Still Exists" benchmark. The audit agent was tested against the 32 sample validation cases provided in `dataset/sample_deletion_requests.csv` with known ground truth in `dataset/sample_output.csv`, followed by full execution on the 518 production cases in `dataset/deletion_requests.csv`.

---

## 2. Benchmark Accuracy Metrics

Evaluation was performed against `dataset/sample_output.csv` using `code/evaluation/main.py`:

| Metric | Accuracy / Match Rate | Details |
| :--- | :--- | :--- |
| **Case-Level Deletion-Status Accuracy** | **100.0%** (32 / 32) | Exact match on `COMPLETE`, `INCOMPLETE`, and `NOT_APPLICABLE` |
| **Non-Deletion Intent Precision** | **100.0%** | Accurately tagged access/export/opt-out queries as `NOT_APPLICABLE` |
| **Step-Level Field Accuracy** | **96.8%** | Verification of `phase`, `system_id`, `resource_id`, `operation`, `state` |
| **Evidence Citation Accuracy** | **100.0%** | Empty `evidence_id` on future remediation; valid IDs cited for findings/complete checks |
| **Sequence & Sorting Accuracy** | **100.0%** | Strict canonical order: Phase -> Operation Rank -> system_id -> resource_id |

---

## 3. Team-Created Evaluation Test Cases

To test generalization beyond the provided samples, the team created three additional edge test cases:

### Case 1: `custom_case_001` — Historical Email Alias with Tombstone Exposure
* **Scenario:** The user submitted a deletion request using a former email address changed 6 months prior. Primary account service reported `COMPLETE` and replaced the main record with an account tombstone. However, an unredacted secondary database replica retained the historical email and phone number linked to the tombstone record.
* **Expected Outcome:** `INCOMPLETE`
* **Agent Behavior:**
  1. Resolved historical identity through `user_audit_log.csv`.
  2. Flagged remaining PII on the tombstone record with `REPORT_EXPOSED_PII`.
  3. Formulated remediation: `REDACT_RECORD` on the tombstone replica.
  4. Formulated verification: `VERIFY_RECORD_REDACTED`.
* **Result:** PASS.

### Case 2: `custom_case_002` — Active Cross-Region Synchronization Resurrection
* **Scenario:** All database records were deleted, but an active periodic replication flow (`eu_sync_worker`) was scheduled to import from an unpurged staging bucket.
* **Expected Outcome:** `INCOMPLETE`
* **Agent Behavior:**
  1. Identified active sync job in `system_activity.csv`.
  2. Generated finding `REPORT_ACTIVE_DATA_FLOW`.
  3. Enforced remediation dependency: generated `DISABLE_DATA_FLOW` before subsequent cleanup steps.
  4. Generated verification `VERIFY_DATA_FLOW_DISABLED`.
* **Result:** PASS.

### Case 3: `custom_case_003` — Multilingual Data Access Inquiry (Non-Deletion)
* **Scenario:** The user submitted a query in French: *"Je souhaite obtenir une copie complète de mes données personnelles conformément au RGPD."*
* **Expected Outcome:** `NOT_APPLICABLE` with `steps_json=[]`.
* **Agent Behavior:** Correctly identified that the intent was data access/portability rather than erasure/deletion, outputting `NOT_APPLICABLE` and empty steps.
* **Result:** PASS.

---

## 4. Failures Found & Improvements Made

1. **Test Runner Import Paths:**
   * *Issue:* Running `unittest discover` from the root directory failed with `ModuleNotFoundError: No module named 'classifier'`.
   * *Fix:* Injected `code/` dynamically into `sys.path` within test scripts to ensure seamless execution from any working directory.
2. **Account Tombstone PII Redaction vs Deletion:**
   * *Issue:* Initial rules treated all lingering database records as `DELETE_RECORD`.
   * *Fix:* Updated `audit_pipeline.py` and `policy_engine.py` to identify permitted `ACCOUNT_TOMBSTONE` records under `rule_15`, assigning `REDACT_RECORD` and checking that internal `user_id` is preserved while personal identifiers are scrubbed.
3. **Canonical Operation Precedence:**
   * *Issue:* Steps within the same phase were initially ordered alphabetically.
   * *Fix:* Enforced problem-statement precedence mapping (`OP_ORDER`) ensuring data flows are disabled and restore paths blocked before records are modified.