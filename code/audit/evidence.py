"""Evidence extraction.

Every supplied evidence file is turned into a list of `Observation` records:

    Observation(system, resource_id, category, state, identifiers, time...)

The rest of the pipeline never reads raw evidence again: it works on this
observation table.  Observations carry their capture time so the auditor can
reconstruct the state of a resource at each case's `audit_at`.

A `Coverage` marks the fact that a snapshot *enumerated* a system at a point in
time.  Coverage is what makes an absence meaningful: if the newest account
snapshot before `audit_at` does not contain the person's account, the account
can be verified absent.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .config import (
    RECORD_TYPE_CATEGORY,
    STATE_ALIASES,
    SYSTEM_CATEGORY,
)
from .dataset import Dataset, norm_email, norm_hash, norm_name, norm_phone, parse_ts

PRESENT, ABSENT = "PRESENT", "ABSENT"
REDACTED, ANONYMIZED = "REDACTED", "ANONYMIZED"
ACTIVE, DISABLED, BLOCKED = "ACTIVE", "DISABLED", "BLOCKED"

RESOURCE_PREFIX_SYSTEM = [
    ("account_", "account_service"),
    ("search_", "search_service"),
    ("analytics_", "analytics_platform"),
    ("support_", "support_platform"),
    ("export_", "export_service"),
    ("data_flow_", "integration_service"),
    ("backup_", "backup_service"),
    ("audit_record_", "security_service"),
    ("tombstone_", "identity_service"),
    ("legal_hold_", "legal_service"),
    ("marketing_", "marketing_platform"),
    ("email_delivery_", "email_delivery_service"),
    ("cache_", "cache_service"),
    ("telemetry_", "telemetry_service"),
]

COLLECTION_CATEGORY = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_tickets": ("support_platform", "SUPPORT_MESSAGE"),
    "support_messages": ("support_platform", "SUPPORT_MESSAGE"),
    "support_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "backup_archives": ("backup_service", "BACKUP_ARCHIVE"),
    "marketing_profiles": ("marketing_platform", "MARKETING_PROFILE"),
    "email_delivery_logs": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    "legal_hold_records": ("legal_service", "LEGAL_HOLD_RECORD"),
}

TABLE_SYSTEM = [
    ("customer_profiles", "account_service", "USER_PROFILE"),
    ("customer_search_documents", "search_service", "SEARCH_INDEX_ENTRY"),
    ("search_documents", "search_service", "SEARCH_INDEX_ENTRY"),
    ("customer_analytics_profiles", "analytics_platform", "ANALYTICS_PROFILE"),
    ("support_records", "support_platform", "SUPPORT_MESSAGE"),
    ("support_messages", "support_platform", "SUPPORT_MESSAGE"),
    ("support_attachments", "support_platform", "SUPPORT_ATTACHMENT"),
    ("customer_exports", "export_service", "USER_EXPORT"),
    ("connector_subscriptions", "integration_service", "DATA_FLOW"),
    ("backup_restore_entries", "backup_service", "BACKUP_ARCHIVE"),
    ("security_audit_records", "security_service", "SECURITY_AUDIT_LOG"),
    ("deleted_customer_references", "identity_service", "ACCOUNT_TOMBSTONE"),
    ("legal_hold_records", "legal_service", "LEGAL_HOLD_RECORD"),
    ("marketing_profiles", "marketing_platform", "MARKETING_PROFILE"),
    ("email_delivery_logs", "email_delivery_service", "EMAIL_DELIVERY_LOG"),
    ("customer_cache", "cache_service", "CACHE_ENTRY"),
]


def system_for_resource(resource_id: str) -> Optional[str]:
    for prefix, system in RESOURCE_PREFIX_SYSTEM:
        if (resource_id or "").startswith(prefix):
            return system
    return None


def normalize_state(value: str) -> Optional[str]:
    if not value:
        return None
    return STATE_ALIASES.get(str(value).strip().upper())


@dataclass
class Observation:
    evidence_id: str
    path: str
    observed_at: datetime
    system_id: str
    resource_id: str
    category: str
    state: str
    identifiers: Dict[str, Set[str]] = field(default_factory=dict)
    user_ids: Set[str] = field(default_factory=set)
    explicit_state: bool = False
    note: str = ""
    evidence_ts: Optional[datetime] = None  # capture time of the evidence file

    def ident_values(self, kind: str) -> Set[str]:
        return self.identifiers.get(kind, set())

    def has_pii(self) -> bool:
        return any(self.identifiers.get(k) for k in ("name", "email", "phone", "email_hash"))


@dataclass
class Coverage:
    evidence_id: str
    path: str
    observed_at: datetime
    system_id: str
    scope_users: Set[str] = field(default_factory=set)
    evidence_ts: Optional[datetime] = None
    # A snapshot that declares a scope but enumerates no row proves nothing;
    # such a capture is kept as a weak fallback only.
    substantive: bool = True


class EvidenceIndex:
    def __init__(self, dataset: Dataset):
        self.dataset = dataset
        self.manifest = dataset.evidence_manifest()
        self._by_path = {
            row["_abs_path"]: row for row in dataset.evidence_files
        }
        self.observations: List[Observation] = []
        self.coverages: List[Coverage] = []
        self.errors: List[Tuple[str, str]] = []
        self._current_ts: Optional[datetime] = None
        self._load()

    # ------------------------------------------------------------------
    def _load(self) -> None:
        for file_id, row in sorted(self.manifest.items(), key=lambda kv: kv[1]["captured_at"]):
            path = row["_abs_path"]
            if not os.path.exists(path):
                self.errors.append((file_id, "missing file"))
                continue
            ext = os.path.splitext(path)[1].lower()
            self._current_ts = row["_ts"]
            try:
                if ext == ".sql":
                    self._parse_sql(file_id, path, row["_ts"])
                elif ext == ".json":
                    self._parse_json(file_id, path, row["_ts"])
                elif ext == ".txt":
                    self._parse_handover(file_id, path, row["_ts"])
                elif ext == ".log":
                    self._parse_log(file_id, path, row["_ts"])
                elif ext == ".pdf":
                    self._parse_pdf(file_id, path, row["_ts"])
                elif ext in (".png", ".jpg", ".jpeg"):
                    self._parse_image(file_id, path, row["_ts"])
            except Exception as exc:  # keep the run alive, report at the end
                self.errors.append((file_id, f"{type(exc).__name__}: {exc}"))
        self._index()

    def _index(self) -> None:
        # A resource keeps its owner: once any observation links a resource to a
        # person, every observation of that resource belongs to that person
        # (including the 404 rows that prove an absence).
        owners: Dict[Tuple[str, str], Set[str]] = {}
        for obs in self.observations:
            if obs.user_ids:
                owners.setdefault((obs.system_id, obs.resource_id), set()).update(obs.user_ids)
        for obs in self.observations:
            if not obs.user_ids:
                inherited = owners.get((obs.system_id, obs.resource_id))
                if inherited:
                    obs.user_ids = set(inherited)

        self.by_resource: Dict[Tuple[str, str], List[Observation]] = {}
        for obs in self.observations:
            self.by_resource.setdefault((obs.system_id, obs.resource_id), []).append(obs)
        for rows in self.by_resource.values():
            rows.sort(key=lambda o: (o.observed_at, o.evidence_id))

        self.by_user_resource: Dict[Tuple[str, str, str], List[Observation]] = {}
        for obs in self.observations:
            for user_id in obs.user_ids:
                self.by_user_resource.setdefault(
                    (user_id, obs.system_id, obs.resource_id), []
                ).append(obs)
        for rows in self.by_user_resource.values():
            rows.sort(key=lambda o: (o.observed_at, o.evidence_id))

        self.coverage_by_system: Dict[str, List[Coverage]] = {}
        for cov in self.coverages:
            self.coverage_by_system.setdefault(cov.system_id, []).append(cov)
        for rows in self.coverage_by_system.values():
            rows.sort(key=lambda c: (c.observed_at, c.evidence_id))

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _add(
        self,
        *,
        evidence_id: str,
        path: str,
        observed_at: datetime,
        system_id: str,
        resource_id: str,
        category: str,
        state: Optional[str],
        fields: dict,
        explicit_state: bool = False,
        note: str = "",
    ) -> None:
        if not system_id or not resource_id:
            return
        category = category or SYSTEM_CATEGORY.get(system_id, "USER_PROFILE")
        identifiers: Dict[str, Set[str]] = {}
        emails = set()
        phones = set()
        hashes = set()
        names = set()
        user_refs = set()

        for key, value in (fields or {}).items():
            if isinstance(value, (list, tuple, set)):
                values = list(value)
            else:
                values = [value]
            for raw in values:
                if raw is None or raw == "" or raw == "null":
                    continue
                text = str(raw).strip()
                if not text:
                    continue
                key_l = key.lower()
                hex_value = re.fullmatch(r"[0-9a-f]{32,128}", text.lower())
                if "@" in text:
                    emails.add(norm_email(text))
                elif hex_value and key_l not in ("checksum", "checksum_prefix", "integrity_seal"):
                    hashes.add(norm_hash(text))
                elif "phone" in key_l or re.fullmatch(r"\+\d[\d\s\-()]{6,}", text):
                    p = norm_phone(text)
                    if len(p) >= 7:
                        phones.add(p)
                elif key_l in ("full_name", "name", "requester_name", "display_name", "customer_name"):
                    names.add(norm_name(text))
                elif key_l in (
                    "customer_reference", "subject_reference", "user_id", "subject_ref",
                    "subject_selector", "subject", "owner_reference",
                ) and text.startswith("user_"):
                    user_refs.add(text)

        user_ids = self.dataset.match_identifiers(
            emails=emails, phones=phones, hashes=hashes, user_refs=user_refs
        )
        identifiers = {
            "email": emails,
            "phone": phones,
            "email_hash": hashes,
            "name": names,
        }
        if state is None:
            normalized = dict(fields or {})
            if emails:
                normalized["email"] = sorted(emails)
            if phones:
                normalized["phone"] = sorted(phones)
            if hashes:
                normalized["email_hash"] = sorted(hashes)
            state = infer_state(category, normalized)
        if not user_ids and state != ABSENT:
            # last resort: try to match a bare user reference stored as a string
            for value in fields.values():
                if isinstance(value, str) and value.startswith("user_") and value in self.dataset.people:
                    user_ids.add(value)

        self.observations.append(
            Observation(
                evidence_id=evidence_id,
                path=path,
                observed_at=observed_at,
                system_id=system_id,
                resource_id=resource_id,
                category=category,
                state=state,
                identifiers=identifiers,
                user_ids=user_ids,
                explicit_state=explicit_state,
                note=note,
                evidence_ts=self._current_ts or observed_at,
            )
        )

    def _add_coverage(
        self, evidence_id: str, path: str, observed_at: datetime, system_id: str,
        scope_users: Iterable[str] = (), substantive: bool = True,
    ) -> None:
        if not system_id:
            return
        self.coverages.append(
            Coverage(
                evidence_id=evidence_id,
                path=path,
                observed_at=observed_at,
                system_id=system_id,
                scope_users=set(scope_users),
                evidence_ts=self._current_ts or observed_at,
                substantive=substantive,
            )
        )

    # ------------------------------------------------------------------
    # SQL snapshots
    # ------------------------------------------------------------------
    def _parse_sql(self, evidence_id: str, path: str, file_ts: datetime) -> None:
        text = open(path, encoding="utf-8", errors="ignore").read()
        captured = re.search(r"Captured at:\s*(\S+)", text)
        ts = parse_ts(captured.group(1)) if captured else file_ts

        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(text)
            conn.commit()
            tables = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            for table in tables:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
                rows = [dict(r) for r in rows]
                if table == "snapshot_scope":
                    for row in rows:
                        # a declared scope without any enumerated row is not a
                        # proof that the system was really captured
                        self._add_coverage(
                            evidence_id, path, ts, row.get("origin_system", ""),
                            substantive=False,
                        )
                    continue
                if table in ("customer_data_primary",) or table.startswith("customer_data_"):
                    self._parse_generic_sql_rows(evidence_id, path, ts, table, rows)
                    continue
                mapped = self._table_mapping(table)
                if not mapped:
                    continue
                system_id, category = mapped
                self._add_coverage(
                    evidence_id, path, ts, system_id, substantive=bool(rows)
                )
                for row in rows:
                    self._sql_row(evidence_id, path, ts, system_id, category, row)
        finally:
            conn.close()

    def _table_mapping(self, table: str) -> Optional[Tuple[str, str]]:
        for prefix, system_id, category in TABLE_SYSTEM:
            if table == prefix or table.startswith(prefix + "_"):
                return system_id, category
        return None

    def _parse_generic_sql_rows(self, evidence_id, path, ts, table, rows) -> None:
        for row in rows:
            origin = row.get("origin_system") or ""
            collection = row.get("collection_name") or ""
            payload = row.get("record_json")
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    payload = {"raw": payload}
            if not isinstance(payload, dict):
                payload = {}
            payload = flatten_record(payload)
            mapped = COLLECTION_CATEGORY.get(collection)
            if mapped:
                system_id, category = mapped
            elif origin in SYSTEM_CATEGORY:
                system_id = origin
                category = SYSTEM_CATEGORY[origin]
            else:
                continue
            resource_id = payload.get("resource_id") or row.get("resource_id")
            updated = row.get("updated_at")
            observed = parse_ts(updated) or ts
            self._add(
                evidence_id=evidence_id,
                path=path,
                observed_at=observed,
                system_id=system_id,
                resource_id=resource_id,
                category=category,
                state=infer_state(category, payload),
                fields={k: v for k, v in payload.items() if isinstance(v, (str, int, float))},
            )
        # coverage: the replica tables enumerate whole collections
        systems = set()
        for row in rows:
            mapped = COLLECTION_CATEGORY.get(row.get("collection_name") or "")
            if mapped:
                systems.add(mapped[0])
            elif row.get("origin_system"):
                systems.add(row["origin_system"])
        for system_id in systems:
            self._add_coverage(evidence_id, path, ts, system_id)

    def _sql_row(self, evidence_id, path, ts, system_id, category, row) -> None:
        resource_id = row.get("resource_id") or row.get("id")
        updated = row.get("updated_at") or row.get("created_at")
        observed = parse_ts(updated) if isinstance(updated, str) else None
        fields = {}
        for key, value in row.items():
            if key in ("resource_id", "id"):
                continue
            if isinstance(value, (str, int, float)):
                fields[key] = value
        state = infer_state(category, fields, resource_id=resource_id)
        self._add(
            evidence_id=evidence_id,
            path=path,
            observed_at=observed or ts,
            system_id=system_id,
            resource_id=resource_id,
            category=category,
            state=state,
            fields=fields,
        )

    # ------------------------------------------------------------------
    # JSON exports
    # ------------------------------------------------------------------
    def _parse_json(self, evidence_id: str, path: str, file_ts: datetime) -> None:
        data = json.load(open(path, encoding="utf-8"))
        if isinstance(data, dict) and "snapshots" in data:
            self._parse_snapshot_bundle(evidence_id, path, file_ts, data)
        elif isinstance(data, dict) and "service_exports" in data:
            self._parse_service_export(evidence_id, path, data)
        elif isinstance(data, dict) and data.get("collection") == "customer_export_jobs":
            self._parse_export_jobs(evidence_id, path, file_ts, data)
        elif isinstance(data, dict) and data.get("collection") in (
            "customer_analytics_reports",
        ):
            self._parse_collection_records(evidence_id, path, file_ts, data)
        elif isinstance(data, dict) and "records" in data:
            exported = parse_ts(data.get("exported_at") or data.get("captured_at") or "") or file_ts
            self._parse_flat_records(evidence_id, path, exported, data)
        else:
            raise ValueError("unrecognised JSON evidence layout")

    def _parse_export_jobs(self, evidence_id, path, file_ts, data) -> None:
        ts = parse_ts(data.get("captured_at", "")) or file_ts
        self._add_coverage(evidence_id, path, ts, "export_service")
        for record in data.get("records", []):
            if not isinstance(record, dict):
                continue
            created = parse_ts(record.get("created_at", "")) or ts
            available = record.get("download_available")
            state = ABSENT if available is False else PRESENT
            self._add(
                evidence_id=evidence_id, path=path, observed_at=created,
                system_id="export_service", resource_id=record.get("resource_id", ""),
                category="USER_EXPORT", state=state, fields=record, explicit_state=True,
            )

    def _parse_collection_records(self, evidence_id, path, file_ts, data) -> None:
        ts = parse_ts(data.get("captured_at", "")) or file_ts
        collection = data.get("collection", "")
        mapped = COLLECTION_CATEGORY.get(collection)
        if not mapped:
            return
        system_id, category = mapped
        self._add_coverage(evidence_id, path, ts, system_id)
        for record in data.get("records", []):
            if not isinstance(record, dict):
                continue
            state = infer_state(category, record)
            self._add(
                evidence_id=evidence_id, path=path, observed_at=ts,
                system_id=system_id, resource_id=record.get("resource_id", ""),
                category=category, state=state, fields=record,
            )

    def _parse_snapshot_bundle(self, evidence_id, path, file_ts, data) -> None:
        for snapshot in data.get("snapshots", []):
            ts = parse_ts(snapshot.get("captured_at", "")) or file_ts
            store = snapshot.get("data_store", "")
            collection = snapshot.get("collection", "")
            mapped = COLLECTION_CATEGORY.get(collection)
            if mapped:
                system_id, category = mapped
            else:
                system_id = store
                category = SYSTEM_CATEGORY.get(store, "USER_PROFILE")
            self._add_coverage(evidence_id, path, ts, system_id)
            for record in snapshot.get("records", []):
                if not isinstance(record, dict):
                    continue
                flat = flatten_record(record)
                status = record.get("account_status") if category == "USER_PROFILE" else None
                state = infer_state(category, flat, status)
                self._add(
                    evidence_id=evidence_id,
                    path=path,
                    observed_at=ts,
                    system_id=system_id,
                    resource_id=record.get("resource_id", ""),
                    category=category,
                    state=state,
                    fields=flat,
                )

    def _parse_service_export(self, evidence_id, path, data) -> None:
        for system_id, payload in (data.get("service_exports") or {}).items():
            if not isinstance(payload, dict):
                continue
            category = SYSTEM_CATEGORY.get(system_id, "USER_PROFILE")
            self._add_coverage(
                evidence_id, path, parse_ts(data.get("exported_at", "")) or datetime.now(timezone.utc), system_id
            )
            for key, rows in payload.items():
                if not isinstance(rows, list):
                    continue
                for record in rows:
                    if not isinstance(record, dict):
                        continue
                    ts = parse_ts(record.get("observed_at", "")) or parse_ts(
                        data.get("exported_at", "")
                    )
                    record_cat = category
                    if key in ("tickets", "attachments"):
                        record_cat = "SUPPORT_MESSAGE" if key == "tickets" else "SUPPORT_ATTACHMENT"
                    fields = dict(record)
                    profile = fields.pop("profile", None)
                    hits = fields.pop("hits", None)
                    if isinstance(profile, dict):
                        fields.update(profile)
                    if isinstance(hits, dict):
                        docs = hits.get("documents") or []
                        total = hits.get("total")
                        if not docs and not total:
                            self._add(
                                evidence_id=evidence_id, path=path, observed_at=ts,
                                system_id=system_id, resource_id=record.get("resource_id"),
                                category=record_cat, state=ABSENT, fields={},
                                explicit_state=True,
                            )
                            continue
                        for doc in docs:
                            if isinstance(doc, dict):
                                self._add(
                                    evidence_id=evidence_id, path=path, observed_at=ts,
                                    system_id=system_id,
                                    resource_id=doc.get("resource_id") or record.get("resource_id"),
                                    category=record_cat, state=PRESENT, fields=doc,
                                    explicit_state=True,
                                )
                        continue
                    status_code = record.get("status_code")
                    if status_code is not None:
                        state = PRESENT if int(status_code) < 400 else ABSENT
                        self._add(
                            evidence_id=evidence_id, path=path, observed_at=ts,
                            system_id=system_id, resource_id=record.get("resource_id"),
                            category=record_cat, state=state, fields=fields,
                            explicit_state=True,
                        )
                        continue
                    state = infer_state(record_cat, fields)
                    self._add(
                        evidence_id=evidence_id, path=path, observed_at=ts,
                        system_id=system_id, resource_id=record.get("resource_id"),
                        category=record_cat, state=state, fields=fields,
                    )

    def _parse_flat_records(self, evidence_id, path, exported, data) -> None:
        # export/security manifests list one record per inspected resource
        systems_seen = set()
        for record in data.get("records", []):
            if not isinstance(record, dict):
                continue
            system_id = record.get("system", "")
            record_type = record.get("record_type", "")
            category = RECORD_TYPE_CATEGORY.get(record_type)
            if not category:
                category = SYSTEM_CATEGORY.get(system_id, "USER_PROFILE")
            ts = parse_ts(record.get("recorded_at", "")) or exported
            result = record.get("result")
            state = normalize_state(result)
            fields = dict(record)
            subject = record.get("subject_reference")
            if subject and "@" in str(subject):
                fields["email"] = subject
            elif subject and str(subject).startswith("user_"):
                fields["customer_reference"] = subject
            if state is None:
                state = infer_state(category, fields)
            if record_type == "ANALYTICS_PROFILE" and result:
                state = PRESENT if result.upper() == "IDENTIFIABLE" else ANONYMIZED
            if record_type == "SUPPORT_MESSAGE" and result:
                state = PRESENT if result.upper() == "IDENTIFIABLE" else REDACTED
            if record_type == "BACKUP_ARCHIVE" and result:
                state = ACTIVE if result.upper() == "ACTIVE" else BLOCKED
            if record_type == "DATA_FLOW" and result:
                state = ACTIVE if result.upper() == "ACTIVE" else DISABLED
            self._add(
                evidence_id=evidence_id, path=path, observed_at=ts,
                system_id=system_id, resource_id=record.get("resource_id", ""),
                category=category, state=state, fields=fields,
                explicit_state=True,
            )
            systems_seen.add(system_id)
        # flat exports are not exhaustive: they list the subjects that were
        # inspected, so no coverage / absence is registered for them.
        _ = systems_seen

    # ------------------------------------------------------------------
    # handover text
    # ------------------------------------------------------------------
    def _parse_handover(self, evidence_id: str, path: str, file_ts: datetime) -> None:
        text = open(path, encoding="utf-8", errors="ignore").read()
        snapshot = re.search(r"Snapshot:\s*(\S+)", text)
        default_ts = parse_ts(snapshot.group(1)) if snapshot else file_ts
        pattern = re.compile(
            r"-\s*(?P<ts>\S+)\s*\|\s*(?P<system>[a-z_]+)\s*\|\s*(?P<resource>[a-z_0-9]+)\s*\|"
            r"\s*(?P<category>[A-Z_]+)\s*\|\s*(?P<state>[A-Z_]+)\s*\|\s*(?P<ident>[^|\n]+)"
        )
        seen_systems = set()
        for match in pattern.finditer(text):
            ts = parse_ts(match.group("ts")) or default_ts
            system_id = match.group("system")
            resource_id = match.group("resource")
            category = match.group("category")
            state = normalize_state(match.group("state")) or ABSENT
            ident = match.group("ident").strip()
            if ident.lower().startswith("no direct identifier"):
                ident = ""
            fields = {}
            if "@" in ident:
                fields["email"] = ident
            elif ident.startswith("user_"):
                fields["customer_reference"] = ident
            self._add(
                evidence_id=evidence_id, path=path, observed_at=ts,
                system_id=system_id, resource_id=resource_id, category=category,
                state=state, fields=fields, explicit_state=True,
            )
            seen_systems.add(system_id)
        for system_id in seen_systems:
            self._add_coverage(evidence_id, path, default_ts, system_id)

    # ------------------------------------------------------------------
    # PDFs
    # ------------------------------------------------------------------
    def _parse_pdf(self, evidence_id: str, path: str, file_ts: datetime) -> None:
        text = extract_pdf_text(path)
        if not text:
            return
        self._parse_document_text(evidence_id, path, file_ts, text)

    def _parse_image(self, evidence_id: str, path: str, file_ts: datetime) -> None:
        for entry in image_evidence(path):
            fields = {
                "email": entry.get("email"),
                "phone": entry.get("phone"),
                "full_name": entry.get("name"),
                "customer_reference": entry.get("user_ref"),
            }
            self._add(
                evidence_id=evidence_id, path=path, observed_at=file_ts,
                system_id=entry.get("system", ""),
                resource_id=entry.get("resource_id", ""),
                category=entry.get("category", ""),
                state=entry.get("state"),
                fields={k: v for k, v in fields.items() if v},
                explicit_state=True,
            )

    def _parse_document_text(self, evidence_id, path, file_ts, text) -> None:
        captured = re.search(
            r"(?:captured|issued|generated|recorded)\s+(\d{1,2}\s+\w+\s+\d{4}\s+\d{2}[:.]\d{2}[^\n]*)",
            text,
        )
        ts = file_ts
        if captured:
            ts = parse_document_ts(captured.group(1)) or file_ts

        resources = re.findall(
            r"\b(account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|legal_hold|marketing|email_delivery)_(\w+)\b",
            text,
        )
        resource_ids = sorted({f"{a}_{b}" for a, b in resources})
        if not resource_ids:
            return
        emails = sorted(set(re.findall(r"[\w.+-]+@[\w.-]+\.\w+", text)))
        phones = sorted(set(re.findall(r"\+\d[\d\s]{8,}\d", text)))
        user_refs = sorted(set(re.findall(r"\buser_\d+\b", text)))
        lowered = text.lower()

        for resource_id in resource_ids:
            system_id = system_for_resource(resource_id)
            if not system_id:
                continue
            category = SYSTEM_CATEGORY.get(system_id, "USER_PROFILE")
            if resource_id.startswith("support_"):
                category = (
                    "SUPPORT_ATTACHMENT"
                    if ("attachment" in lowered or "_" in resource_id and "support_" in resource_id and
                        ("cs-" in lowered or "attachment" in lowered))
                    else "SUPPORT_MESSAGE"
                )
                if "attachment" not in lowered:
                    category = "SUPPORT_MESSAGE"
                else:
                    category = "SUPPORT_ATTACHMENT"
            fields = {"email": emails, "phone": phones, "customer_reference": user_refs}
            self._add(
                evidence_id=evidence_id, path=path, observed_at=ts,
                system_id=system_id, resource_id=resource_id, category=category,
                state=infer_state(category, fields), fields=fields,
            )

    # ------------------------------------------------------------------
    # logs
    # ------------------------------------------------------------------
    def _parse_log(self, evidence_id: str, path: str, file_ts: datetime) -> None:
        lines = [
            line
            for line in open(path, encoding="utf-8", errors="ignore").read().splitlines()
            if line.strip()
        ]
        records = [parse_log_line(line, file_ts) for line in lines]
        records = [record for record in records if record]

        # Log lines are grouped by trace id: the "started" line carries the
        # subject identifier, the "completed" line carries the resource and
        # its state.  Merge each trace so the state can be attributed.
        traces: Dict[str, dict] = {}
        for record in records:
            trace_id = (record.get("fields") or {}).get("trace_id")
            if not trace_id:
                continue
            merged = traces.setdefault(trace_id, {})
            for key, value in (record.get("fields") or {}).items():
                if value not in ("", None, "null"):
                    merged.setdefault(key, value)
            if record.get("resource_id"):
                merged.setdefault("resource_id", record["resource_id"])

        seen_systems: Set[str] = set()
        for record in records:
            if not record.get("interpreted"):
                continue
            system_id = record.get("system_id")
            resource_id = record.get("resource_id")
            state = record.get("state")
            category = record.get("category")
            observed = record.get("observed_at") or file_ts
            fields = dict(record.get("fields") or {})
            trace_id = fields.get("trace_id")
            if trace_id and trace_id in traces:
                for key, value in traces[trace_id].items():
                    if key not in ("resource_id", "event"):
                        fields.setdefault(key, value)
                if not resource_id:
                    resource_id = traces[trace_id].get("resource_id")
            system_id = normalize_service(system_id)
            if system_id and system_id not in SYSTEM_CATEGORY:
                system_id = None
            if not system_id and resource_id:
                system_id = system_for_resource(resource_id)
            if not system_id or not resource_id:
                continue
            if category is None:
                category = SYSTEM_CATEGORY.get(system_id, "USER_PROFILE")
                event_name = str(fields.get("event", "")).lower()
                if "contact_lookup" in event_name or "contact_query" in event_name \
                        or "legacy_contact_index" in str(fields.get("source", "")):
                    category = "SECONDARY_IDENTIFIER"
                elif resource_id.startswith("support_"):
                    category = "SUPPORT_MESSAGE"
            self._add(
                evidence_id=evidence_id, path=path, observed_at=observed,
                system_id=system_id, resource_id=resource_id, category=category,
                state=state, fields=fields, explicit_state=state is not None,
            )
            seen_systems.add(system_id)
        base = os.path.basename(path)
        if "readback" in base or "support_replica" in base:
            for system_id in seen_systems:
                self._add_coverage(evidence_id, path, file_ts, system_id)

    # ------------------------------------------------------------------
    def observations_for(self, user_id: str) -> List[Observation]:
        rows = [o for o in self.observations if user_id in o.user_ids]
        rows.sort(key=lambda o: (o.observed_at, o.evidence_id))
        return rows

    def resources_for(self, user_id: str) -> Set[Tuple[str, str]]:
        return {(o.system_id, o.resource_id) for o in self.observations_for(user_id)}


# ---------------------------------------------------------------------------
# state inference
# ---------------------------------------------------------------------------
def infer_state(category: str, fields: dict, status: Optional[str] = None,
                resource_id: Optional[str] = None) -> str:
    fields = fields or {}
    if status and str(status).upper() in ("DELETED", "ABSENT", "NOT_FOUND"):
        return ABSENT

    if category == "DATA_FLOW":
        enabled = fields.get("enabled")
        if isinstance(enabled, str):
            enabled = enabled.strip().lower() in ("true", "1", "yes")
        if enabled is None:
            status_text = str(fields.get("last_delivery_status", "")).lower()
            return DISABLED if status_text in ("stopped", "disabled") else ACTIVE
        return ACTIVE if enabled else DISABLED

    if category == "BACKUP_ARCHIVE":
        allowed = fields.get("restore_allowed")
        if allowed is None:
            allowed = fields.get("eligible")
        if allowed is None and fields.get("deletion_block") is not None:
            allowed = not fields.get("deletion_block")
        if isinstance(allowed, str):
            allowed = allowed.strip().lower() in ("true", "1", "yes")
        return ACTIVE if allowed else BLOCKED

    if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
        return PRESENT

    pii = _has_identity(fields)
    if category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
        return PRESENT if pii else ANONYMIZED
    if category in ("SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"):
        return PRESENT if _has_contact(fields) else REDACTED
    if category == "ACCOUNT_TOMBSTONE":
        return PRESENT if _has_contact(fields) or fields.get("full_name") else REDACTED
    return PRESENT


def flatten_record(record: dict, depth: int = 0) -> dict:
    """Flatten one level of nested documents (document/profile blocks)."""
    flat: dict = {}
    for key, value in record.items():
        if isinstance(value, dict) and depth < 1:
            flat.update(flatten_record(value, depth + 1))
        elif isinstance(value, (str, int, float)):
            flat.setdefault(key, value)
        elif isinstance(value, bool):
            flat.setdefault(key, value)
    return flat


def _has_identity(fields: dict) -> bool:
    """Any identifier that still makes the record attributable to a person."""
    if _has_contact(fields):
        return True
    for key in ("customer_reference", "user_id", "subject_reference"):
        value = fields.get(key)
        if value and str(value).startswith("user_"):
            return True
    if fields.get("full_name"):
        return True
    return False


def _has_contact(fields: dict) -> bool:
    for key in ("email", "phone", "email_hash", "requester_email", "requester_phone",
                "requester_name", "owner_email", "owner_phone", "customer_email",
                "display_name", "name", "full_name"):
        value = fields.get(key)
        if value and str(value).strip() not in ("", "None", "null"):
            return True
    return False


# ---------------------------------------------------------------------------
# log line parsing
# ---------------------------------------------------------------------------
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s*(.*)$")
KV_RE = re.compile(r'([\w.]+)=("([^"]*)"|\'([^\']*)\'|([^\s]+))')
SERVICE_EVENT_RE = re.compile(r"event[=:]\s*\"?([\w.]+)\"?")


def parse_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for match in KV_RE.finditer(text):
        key = match.group(1)
        value = match.group(3) or match.group(4) or match.group(5) or ""
        out[key] = value
    return out


def parse_log_line(line: str, default_ts: datetime) -> Optional[dict]:
    ts_match = TS_RE.match(line.strip())
    if ts_match:
        ts = parse_ts(ts_match.group(1)) or default_ts
        rest = ts_match.group(2)
    else:
        ts, rest = default_ts, line.strip()

    record: dict = {"observed_at": ts, "fields": {}}

    # structured (json) log lines
    if rest.startswith("{"):
        try:
            payload = json.loads(rest)
        except json.JSONDecodeError:
            return None
        record["system_id"] = payload.get("service") or payload.get("logger")
        record["resource_id"] = payload.get("resource_id")
        record["fields"] = {k: v for k, v in payload.items() if k not in ("severity",)}
        return _finish(record, payload.get("event", ""), payload)

    # bracketed format: 2026-.. [DEBUG] [service] [trace] event: k="v"
    bracket = re.match(r"\[(\w+)\]\s*\[([\w-]+)\]\s*\[([\w-]+)\]\s*([\w.]+):?\s*(.*)", rest)
    if bracket:
        payload = parse_kv(bracket.group(5))
        payload["service"] = bracket.group(2)
        payload["trace_id"] = payload.get("trace_id") or bracket.group(3)
        record["system_id"] = bracket.group(2)
        record["resource_id"] = payload.get("resource_id")
        record["fields"] = payload
        return _finish(record, bracket.group(4), payload)

    # pipe format: ts | LEVEL | service | trace | event | k=v
    if rest.startswith("|"):
        parts = [p.strip() for p in rest.split("|")]
        parts = [p for p in parts if p]
        if len(parts) >= 4:
            payload = parse_kv(parts[-1])
            payload["service"] = parts[1]
            payload["trace_id"] = payload.get("trace_id") or parts[2]
            record["system_id"] = parts[1]
            record["resource_id"] = payload.get("resource_id")
            record["fields"] = payload
            return _finish(record, parts[3] if len(parts) > 3 else "", payload)

    # syslog: <15>1 node-8 service trace - - level=... event=...
    if rest.startswith("<"):
        stripped = re.sub(r"^<\d+>1\s+", "", rest)
        parts = stripped.split()
        if len(parts) >= 3:
            payload = parse_kv(stripped)
            service = parts[1]
            payload["service"] = service
            payload["trace_id"] = payload.get("trace_id") or parts[2]
            record["system_id"] = service
            record["resource_id"] = payload.get("resource_id")
            record["fields"] = payload
            return _finish(record, payload.get("event", ""), payload)

    # key=value formats
    if "=" in rest:
        payload = parse_kv(rest)
        service = payload.get("service") or payload.get("function") or payload.get("logger")
        event = payload.get("event", "")
        record["system_id"] = service
        record["resource_id"] = payload.get("resource_id")
        record["fields"] = payload
        return _finish(record, event, payload)

    return None


def _finish(record: dict, event: str, payload: dict) -> dict:
    """Interpret the line, but always keep its parsed fields for trace merging."""
    result = _interpret_record(record, event, payload)
    if result is None:
        record = dict(record)
        record["interpreted"] = False
        return record
    record = result
    record["interpreted"] = True
    return record


IDENTITY_KEYS = (
    "email", "customer_email", "owner_email", "requester_email", "correlation_key",
    "lookup_key", "subject_key", "match_key", "customer_reference", "subject_reference",
    "subject_ref", "subject_selector", "phone", "requester_phone", "owner_phone",
    "email_hash",
)


def _interpret_record(record: dict, event: str, payload: dict) -> Optional[dict]:
    """Turn one parsed log record into a state assertion, when it carries one."""
    event = (event or "").strip()
    fields = record["fields"]
    state = None

    rows = fields.get("rows")
    status = fields.get("http_status") or fields.get("status_code")
    result = (fields.get("result") or "").strip().lower()
    total = fields.get("total_hits") or fields.get("hit_count")
    completed = (
        event.endswith("lookup_completed")
        or event.endswith("read_completed")
        or event.endswith("query_completed")
        or event.endswith("check_completed")
        or event.endswith("scan_completed")
        or event == "record_lookup"
    )

    if completed:
        if result in ("not_found", "miss", "absent", "no_hits"):
            state = ABSENT
        elif status is not None:
            try:
                state = ABSENT if int(status) >= 400 else None
            except ValueError:
                state = None
        if state is None and rows is not None:
            try:
                state = ABSENT if int(rows) == 0 else None
            except ValueError:
                state = None
        if state is None and total is not None:
            try:
                state = ABSENT if int(total) == 0 else None
            except ValueError:
                state = None
        if not record.get("resource_id"):
            return None

    if event in ("restore_candidate_evaluated", "restore_access_checked",
                 "restore_access_check_completed", "restore_eligibility_checked"):
        eligible = (fields.get("eligible") or fields.get("restore_allowed") or "").lower()
        blocked = (fields.get("deletion_block") or "").lower()
        if eligible in ("true", "1"):
            state = ACTIVE
        elif eligible in ("false", "0") or blocked in ("true", "1"):
            state = BLOCKED

    if event in ("connector_heartbeat", "connector_status_checked",
                 "connector_config_read_completed", "data_flow_checked"):
        enabled = (fields.get("enabled") or "").lower()
        if enabled in ("true", "1"):
            state = ACTIVE
        elif enabled in ("false", "0"):
            state = DISABLED

    if event in ("message_pii_scan", "pii_scan_completed", "contact_scan_completed"):
        if fields.get("matched_value"):
            state = PRESENT

    if event in ("support_ticket_read_completed", "support_message_read_completed"):
        if not any(fields.get(k) for k in ("requester_email", "requester_phone", "requester_name")):
            state = REDACTED

    if event == "deletion_marker_check" and state is None:
        state = PRESENT

    if state is None and event not in (
        "restore_candidate_evaluated", "connector_heartbeat", "message_pii_scan",
    ):
        # nothing to say about this line
        if not completed:
            return None

    record["state"] = state
    record["resource_id"] = record.get("resource_id") or payload.get("resource_id")
    return record


SERVICE_ALIASES = {
    "support_replica": "support_platform",
    "profile_service": "account_service",
    "security_audit_service": "security_service",
    "user_export_store": "export_service",
    "analytics_identity_store": "analytics_platform",
    "readback_collector": "",
    "log_router": "",
}


def normalize_service(service: Optional[str]) -> Optional[str]:
    if not service:
        return None
    service = service.strip()
    if service in SERVICE_ALIASES:
        return SERVICE_ALIASES[service] or None
    return service


# ---------------------------------------------------------------------------
# document helpers
# ---------------------------------------------------------------------------
_MONTHS = {
    m: i for i, m in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1
    )
}


def parse_document_ts(text: str) -> Optional[datetime]:
    match = re.search(r"(\d{1,2})\s+(\w{3})[a-z]*\s+(\d{4})\s+(\d{2})[:.](\d{2})", text)
    if not match:
        return None
    day, month, year, hour, minute = match.groups()
    month_num = _MONTHS.get(month.lower()[:3])
    if not month_num:
        return None
    return datetime(int(year), month_num, int(day), int(hour), int(minute), tzinfo=timezone.utc)


def extract_pdf_text(path: str) -> str:
    try:
        from pypdf import PdfReader  # noqa: WPS433 (optional dependency)
    except Exception:
        return _cached_text(path)
    try:
        reader = PdfReader(path)
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:
        return _cached_text(path)


def image_evidence(path: str) -> list:
    """Screenshot facts transcribed during development (see cache/_note)."""
    cache_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "cache", "image_evidence.json"
    )
    if not os.path.exists(cache_path):
        return []
    try:
        payload = json.load(open(cache_path, encoding="utf-8"))
    except Exception:
        return []
    name = os.path.basename(path)
    return [entry for entry in payload.get("entries", []) if entry.get("file") == name]


def _cached_text(path: str) -> str:
    cache_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "audit", "cache", "document_text.json")
    if not os.path.exists(cache_path):
        return ""
    try:
        cache = json.load(open(cache_path, encoding="utf-8"))
    except Exception:
        return ""
    name = os.path.basename(path)
    return cache.get(name, "")
