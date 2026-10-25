import csv
from pathlib import Path

class IdentityResolver:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = Path(dataset_dir)
        self.identities = {}
        self.audit_log = []
        self._load()

    def _load(self):
        # 1. Load user_identities.csv
        ident_file = self.dataset_dir / "user_identities.csv"
        if ident_file.exists():
            with open(ident_file, mode="r", encoding="utf-8", errors="ignore") as fp:
                reader = csv.DictReader(fp)
                for row in reader:
                    uid = row.get("user_id", "")
                    email = (row.get("email") or "").lower().strip()
                    phone = (row.get("phone") or "").strip()
                    h = (row.get("email_hash") or "").strip()

                    self.identities[uid] = row
                    if email:
                        self.identities[email] = row
                    if phone:
                        self.identities[phone] = row
                    if h:
                        self.identities[h] = row

        # 2. Load user_audit_log.csv
        audit_file = self.dataset_dir / "user_audit_log.csv"
        if audit_file.exists():
            with open(audit_file, mode="r", encoding="utf-8", errors="ignore") as fp:
                reader = csv.DictReader(fp)
                for row in reader:
                    self.audit_log.append(row)

    def resolve(self, case_row: dict, audit_at: str) -> dict:
        # Extract direct fields safely as strings
        raw_uid = case_row.get("user_id") or ""
        raw_email = case_row.get("email") or ""
        raw_phone = case_row.get("phone") or ""

        # Normalize to plain strings if dictionaries/objects were passed
        uid = str(raw_uid).strip() if not isinstance(raw_uid, dict) else ""
        email = str(raw_email).lower().strip() if not isinstance(raw_email, dict) else ""
        phone = str(raw_phone).strip() if not isinstance(raw_phone, dict) else ""

        matched_record = {}
        if uid and uid in self.identities:
            matched_record = self.identities[uid]
        elif email and email in self.identities:
            matched_record = self.identities[email]
        elif phone and phone in self.identities:
            matched_record = self.identities[phone]

        resolved_uid = matched_record.get("user_id", uid)
        emails = set()
        phones = set()
        hashes = set()

        if email:
            emails.add(email)
        if matched_record.get("email"):
            emails.add(matched_record["email"].lower().strip())
        if phone:
            phones.add(phone)
        if matched_record.get("phone"):
            phones.add(matched_record["phone"].strip())
        if matched_record.get("email_hash"):
            hashes.add(matched_record["email_hash"].strip())

        # Collect historical aliases from audit log up to audit_at
        if resolved_uid:
            for log_entry in self.audit_log:
                log_time = log_entry.get("timestamp", "")
                if audit_at and log_time and log_time > audit_at:
                    continue

                if log_entry.get("user_id") == resolved_uid:
                    old_val = (log_entry.get("old_value") or "").strip()
                    new_val = (log_entry.get("new_value") or "").strip()
                    attr = (log_entry.get("attribute") or "").lower()

                    if "email" in attr:
                        if old_val:
                            emails.add(old_val.lower())
                        if new_val:
                            emails.add(new_val.lower())
                    elif "phone" in attr:
                        if old_val:
                            phones.add(old_val)
                        if new_val:
                            phones.add(new_val)

        return {
            "user_id": resolved_uid,
            "emails": emails,
            "phones": phones,
            "hashes": hashes
        }