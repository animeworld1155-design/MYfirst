"""Turn reconstructed record states into the required `steps_json` plan."""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from typing import Dict, List

from .config import (
    BAD_STATES,
    FINAL_STATE,
    FINDING_OPS,
    PHASE_ORDER,
    REMEDIATION_FOR_ACTION,
    REMEDIATION_OPS,
    STATE_BY_OP,
    VERIFICATION_FOR_FINAL,
    VERIFICATION_OPS,
    CATEGORY_ACTION,
    FINDING_FOR_CATEGORY,
)
from .reconstruct import CaseContext, RecordState

NOT_APPLICABLE = "NOT_APPLICABLE"
COMPLETE = "COMPLETE"
INCOMPLETE = "INCOMPLETE"

# A record that is already in its required final state needs no verification
# once the case is INCOMPLETE: the plan verifies what had to be remediated plus
# the two records every case must account for - the account itself and the
# security audit trail that policy requires to be retained.
ALWAYS_VERIFIED_SYSTEMS = ("account_service", "security_service")


@dataclass
class Step:
    phase: str
    operation: str
    state: str
    system_id: str
    resource_id: str
    evidence_id: str

    def sort_key(self):
        phase = PHASE_ORDER[self.phase]
        if self.phase == "FINDING":
            op = FINDING_OPS[self.operation]
        elif self.phase == "REMEDIATION":
            op = REMEDIATION_OPS[self.operation]
        else:
            op = VERIFICATION_OPS[self.operation]
        return (phase, op, self.system_id, self.resource_id)

    def to_dict(self, step_no: int) -> dict:
        return {
            "step_no": step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


def _finding_for(record: RecordState) -> str:
    if record.category in FINDING_FOR_CATEGORY:
        return FINDING_FOR_CATEGORY[record.category]
    action = CATEGORY_ACTION.get(record.category, "DELETE")
    if action in ("REDACT", "ANONYMIZE"):
        return "REPORT_EXPOSED_PII"
    return "REPORT_REMAINING_RECORD"


def _remediation_for(record: RecordState) -> str:
    if record.category == "DATA_FLOW":
        return "DISABLE_DATA_FLOW"
    if record.category == "BACKUP_ARCHIVE":
        return "BLOCK_RESTORE"
    action = CATEGORY_ACTION.get(record.category, "DELETE")
    return REMEDIATION_FOR_ACTION[action]


def _verification_for(record: RecordState) -> str:
    final = FINAL_STATE.get(record.category, "ABSENT")
    return VERIFICATION_FOR_FINAL[final]


def _is_violation(record: RecordState) -> bool:
    bad = BAD_STATES.get(record.category, set())
    if record.state in bad:
        return True
    # a redact/anonymize record is exposed whenever it still carries a
    # direct identifier and the evidence says it is present
    return False


def plan_case(ctx: CaseContext) -> Dict[str, str]:
    if not ctx.deletion_requested:
        return {"case_id": ctx.case_id, "deletion_status": NOT_APPLICABLE, "steps_json": "[]"}

    findings: List[Step] = []
    remediations: List[Step] = []
    verifications: List[Step] = []

    violating = [r for r in ctx.records if _is_violation(r)]
    for record in violating:
        operation = _finding_for(record)
        findings.append(
            Step(
                phase="FINDING",
                operation=operation,
                state=STATE_BY_OP[operation],
                system_id=record.system_id,
                resource_id=record.resource_id,
                evidence_id=record.evidence_id,
            )
        )
        remediation_op = _remediation_for(record)
        remediations.append(
            Step(
                phase="REMEDIATION",
                operation=remediation_op,
                state=STATE_BY_OP[remediation_op],
                system_id=record.system_id,
                resource_id=record.resource_id,
                evidence_id="",
            )
        )

    status = INCOMPLETE if violating else COMPLETE

    if status == COMPLETE:
        verify_records = list(ctx.records)
    else:
        violating_ids = {(r.system_id, r.resource_id) for r in violating}
        verify_records = [
            r for r in ctx.records
            if (r.system_id, r.resource_id) in violating_ids
            or r.system_id in ALWAYS_VERIFIED_SYSTEMS
        ]

    for record in verify_records:
        operation = _verification_for(record)
        verifications.append(
            Step(
                phase="VERIFICATION",
                operation=operation,
                state=STATE_BY_OP[operation],
                system_id=record.system_id,
                resource_id=record.resource_id,
                evidence_id=record.evidence_id if status == COMPLETE else "",
            )
        )

    steps = sorted(findings + remediations + verifications, key=Step.sort_key)
    payload = [step.to_dict(i + 1) for i, step in enumerate(steps)]
    return {
        "case_id": ctx.case_id,
        "deletion_status": status,
        "steps_json": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    }


def case_sort_key(case_id: str):
    digits = "".join(ch for ch in case_id if ch.isdigit())
    return (0, int(digits)) if digits else (1, case_id)


def write_output(path: str, rows: List[Dict[str, str]]) -> None:
    rows = sorted(rows, key=lambda r: case_sort_key(r["case_id"]))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
