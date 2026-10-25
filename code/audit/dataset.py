"""Dataset loading and identity resolution.

The agent resolves the person behind a request using both the current identity
snapshot (user_identities.csv) and the historical identity changes recorded in
user_audit_log.csv.  Historical emails may appear in old databases, exports and
support records long after the account email changed.
"""
from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set


def parse_ts(value: str) -> Optional[datetime]:
    """Parse the ISO-8601 timestamps used throughout the dataset."""
    if not value:
        return None
    value = value.strip()
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1] + "+00:00")
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def norm_email(value: str) -> str:
    return (value or "").strip().strip('"').lower()


def norm_phone(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def norm_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def norm_hash(value: str) -> str:
    return (value or "").strip().strip('"').lower()


def load_csv(path: str) -> List[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@dataclass
class Person:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: str
    aliases: Dict[str, Set[str]] = field(default_factory=dict)  # kind -> values

    def identifiers(self) -> Dict[str, Set[str]]:
        ids = {
            "email": {norm_email(self.email)} - {""},
            "phone": {norm_phone(self.phone)} - {""},
            "email_hash": {norm_hash(self.email_hash)} - {""},
            "name": {norm_name(self.name)} - {""},
        }
        for kind, values in self.aliases.items():
            ids.setdefault(kind, set()).update(values)
        return ids


class Dataset:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.dataset_dir = os.path.join(self.root, "dataset")
        self.evidence_dir = os.path.join(self.dataset_dir, "evidence")

        self.requests = load_csv(os.path.join(self.dataset_dir, "deletion_requests.csv"))
        self.sample_requests = load_csv(
            os.path.join(self.dataset_dir, "sample_deletion_requests.csv")
        )
        self.identities = load_csv(os.path.join(self.dataset_dir, "user_identities.csv"))
        self.audit_log = load_csv(os.path.join(self.dataset_dir, "user_audit_log.csv"))
        self.activity = load_csv(os.path.join(self.dataset_dir, "system_activity.csv"))
        self.rules = load_csv(os.path.join(self.dataset_dir, "deletion_rules.csv"))
        self.evidence_files = load_csv(os.path.join(self.dataset_dir, "evidence_files.csv"))
        self.sample_output = {
            row["case_id"]: row
            for row in load_csv(os.path.join(self.dataset_dir, "sample_output.csv"))
        }

        self.people: Dict[str, Person] = {}
        self.email_index: Dict[str, str] = {}
        self.phone_index: Dict[str, str] = {}
        self.hash_index: Dict[str, str] = {}
        self._build_identity_index()
        self._index_activity()

    # ------------------------------------------------------------------
    # identity
    # ------------------------------------------------------------------
    def _build_identity_index(self) -> None:
        for row in self.identities:
            person = Person(
                user_id=row["user_id"],
                name=row.get("name", ""),
                email=row.get("email", ""),
                phone=row.get("phone", ""),
                email_hash=row.get("email_hash", ""),
                updated_at=row.get("updated_at", ""),
            )
            self.people[person.user_id] = person

        for row in self.audit_log:
            person = self.people.get(row["user_id"])
            if person is None:
                continue
            kind = row.get("field_name", "")
            old, new = row.get("old_value", ""), row.get("new_value", "")
            if kind == "email":
                self.email_index.setdefault(norm_email(old), person.user_id)
                self.email_index.setdefault(norm_email(new), person.user_id)
                person.aliases.setdefault("email", set()).update(
                    v for v in (norm_email(old), norm_email(new)) if v
                )
            elif kind == "phone":
                self.phone_index.setdefault(norm_phone(old), person.user_id)
                self.phone_index.setdefault(norm_phone(new), person.user_id)
                person.aliases.setdefault("phone", set()).update(
                    v for v in (norm_phone(old), norm_phone(new)) if v
                )
            elif kind == "email_hash":
                self.hash_index.setdefault(norm_hash(old), person.user_id)
                self.hash_index.setdefault(norm_hash(new), person.user_id)
                person.aliases.setdefault("email_hash", set()).update(
                    v for v in (norm_hash(old), norm_hash(new)) if v
                )
            elif kind == "name":
                person.aliases.setdefault("name", set()).add(norm_name(old))
                person.aliases.setdefault("name", set()).add(norm_name(new))

        for user_id, person in self.people.items():
            self.email_index.setdefault(norm_email(person.email), user_id)
            self.phone_index.setdefault(norm_phone(person.phone), user_id)
            self.hash_index.setdefault(norm_hash(person.email_hash), user_id)

    def resolve_email(self, email: str) -> Optional[str]:
        return self.email_index.get(norm_email(email))

    def match_identifiers(
        self,
        *,
        emails: Iterable[str] = (),
        phones: Iterable[str] = (),
        hashes: Iterable[str] = (),
        user_refs: Iterable[str] = (),
    ) -> Set[str]:
        """Resolve every identifier to user ids (current and historical)."""
        found: Set[str] = set()
        for user_id in user_refs:
            if user_id in self.people:
                found.add(user_id)
        for email in emails:
            e = norm_email(email)
            if e and e != "null" and e in self.email_index:
                found.add(self.email_index[e])
        for phone in phones:
            p = norm_phone(phone)
            if p and len(p) >= 7 and p in self.phone_index:
                found.add(self.phone_index[p])
        for value in hashes:
            h = norm_hash(value)
            if h and h in self.hash_index:
                found.add(self.hash_index[h])
        return found

    def identify(self, *, user_id=None, email=None, name=None, hash_value=None, phone=None) -> Set[str]:
        return self.match_identifiers(
            user_refs=[user_id] if user_id else [],
            emails=[email] if email else [],
            phones=[phone] if phone else [],
            hashes=[hash_value] if hash_value else [],
        )

    # ------------------------------------------------------------------
    # activity
    # ------------------------------------------------------------------
    def _index_activity(self) -> None:
        by_resource: Dict[str, List[dict]] = {}
        for row in self.activity:
            row["_ts"] = parse_ts(row.get("event_time", ""))
            by_resource.setdefault(row.get("resource_id", ""), []).append(row)
        for rows in by_resource.values():
            rows.sort(key=lambda r: r["_ts"] or datetime.min.replace(tzinfo=timezone.utc))
        self.activity_by_resource = by_resource

        classified = []
        for row in self.activity:
            if row.get("event_type") == "CLASSIFY_REQUEST":
                classified.append(row)
        self.classified_requests = classified

    def evidence_manifest(self) -> Dict[str, dict]:
        manifest = {}
        for row in self.evidence_files:
            path = os.path.join(self.dataset_dir, row["file_path"])
            row["_abs_path"] = path
            row["_ts"] = parse_ts(row.get("captured_at", ""))
            manifest[row["file_id"]] = row
        return manifest

    def evidence_id_for(self, path: str) -> Optional[str]:
        rel = os.path.relpath(path, self.dataset_dir)
        for row in self.evidence_files:
            if row["file_path"] == rel:
                return row["file_id"]
        return None


def case_rows(dataset: Dataset, source: str = "eval") -> List[dict]:
    rows = dataset.requests if source == "eval" else dataset.sample_requests
    out = []
    for row in rows:
        row = dict(row)
        row["_requested_at"] = parse_ts(row.get("requested_at", ""))
        row["_reported_at"] = parse_ts(row.get("reported_at", ""))
        row["_audit_at"] = parse_ts(row.get("audit_at", ""))
        out.append(row)
    out.sort(key=lambda r: r["case_id"])
    return out
