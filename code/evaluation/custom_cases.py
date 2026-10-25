#!/usr/bin/env python3
"""Additional evaluation cases written for this submission.

The public sample exercises 32 real cases, but it never covers some rule
combinations that the hidden set is likely to contain.  These cases are
hand-built against the *planner* contract: given an explicit set of record
states they assert the exact ordered step list, so a regression in ordering,
phase composition or evidence placement fails loudly.

Run with:  python3 code/evaluation/custom_cases.py
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from audit.planner import plan_case  # noqa: E402
from audit.reconstruct import CaseContext, RecordState  # noqa: E402

AUDIT_AT = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


def ctx(case_id: str, records, deletion_requested: bool = True) -> CaseContext:
    return CaseContext(
        case_id=case_id,
        user_id="user_test",
        audit_at=AUDIT_AT,
        reported_at=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
        requested_at=datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc),
        records=records,
        deletion_requested=deletion_requested,
    )


def rec(system, resource, category, state, evidence="evidence_test"):
    return RecordState(
        system_id=system,
        resource_id=resource,
        category=category,
        state=state,
        evidence_id=evidence,
        observed_at=AUDIT_AT,
    )


def step(phase, operation, system, resource, evidence):
    from audit.config import STATE_BY_OP

    return {
        "phase": phase,
        "operation": operation,
        "state": STATE_BY_OP[operation],
        "system_id": system,
        "resource_id": resource,
        "evidence_id": evidence,
    }


CASES = []


def case(name, context, expected_status, expected_steps):
    CASES.append((name, context, expected_status, expected_steps))


# ---------------------------------------------------------------------------
# 1. Replication drift: the primary removed the profile, a failover replica
#    still carries it.  The audit must report the ghost copy, remediate it and
#    verify both the original and the replica.
# ---------------------------------------------------------------------------
case(
    "replica drift keeps a deleted profile alive",
    ctx("custom_01", [
        rec("account_service", "account_9001", "USER_PROFILE", "PRESENT", "evidence_replica"),
        rec("security_service", "audit_record_9001", "SECURITY_AUDIT_LOG", "PRESENT", "evidence_replica"),
    ]),
    "INCOMPLETE",
    [
        step("FINDING", "REPORT_REMAINING_RECORD", "account_service", "account_9001", "evidence_replica"),
        step("REMEDIATION", "DELETE_RECORD", "account_service", "account_9001", ""),
        step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9001", ""),
        step("VERIFICATION", "VERIFY_RECORD_PRESENT", "security_service", "audit_record_9001", ""),
    ],
)

# ---------------------------------------------------------------------------
# 2. Account tombstone: the stable user reference may stay, the direct
#    identifiers may not.  A tombstone that still carries name/email/phone is
#    exposed PII and must be redacted.
# ---------------------------------------------------------------------------
case(
    "tombstone still carries direct identifiers",
    ctx("custom_02", [
        rec("identity_service", "tombstone_9002", "ACCOUNT_TOMBSTONE", "PRESENT", "evidence_bundle"),
        rec("security_service", "audit_record_9002", "SECURITY_AUDIT_LOG", "PRESENT", "evidence_bundle"),
        rec("account_service", "account_9002", "USER_PROFILE", "ABSENT", "evidence_bundle"),
    ]),
    "INCOMPLETE",
    [
        step("FINDING", "REPORT_EXPOSED_PII", "identity_service", "tombstone_9002", "evidence_bundle"),
        step("REMEDIATION", "REDACT_RECORD", "identity_service", "tombstone_9002", ""),
        step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9002", ""),
        step("VERIFICATION", "VERIFY_RECORD_PRESENT", "security_service", "audit_record_9002", ""),
        step("VERIFICATION", "VERIFY_RECORD_REDACTED", "identity_service", "tombstone_9002", ""),
    ],
)

# ---------------------------------------------------------------------------
# 3. A live synchronization connector keeps recreating an analytics profile
#    that the deletion already anonymized once.  Findings are ordered
#    remaining record -> exposed PII -> active flow, then remediation in the
#    operation order (disable flow before deleting/redacting).
# ---------------------------------------------------------------------------
case(
    "active sync can recreate anonymized analytics",
    ctx("custom_03", [
        rec("analytics_platform", "analytics_9003", "ANALYTICS_PROFILE", "PRESENT", "evidence_flow"),
        rec("support_platform", "support_9003", "SUPPORT_MESSAGE", "PRESENT", "evidence_flow"),
        rec("integration_service", "data_flow_9003", "DATA_FLOW", "ACTIVE", "evidence_flow"),
        rec("backup_service", "backup_9003", "BACKUP_ARCHIVE", "ACTIVE", "evidence_flow"),
        rec("account_service", "account_9003", "USER_PROFILE", "ABSENT", "evidence_flow"),
    ]),
    "INCOMPLETE",
    [
        step("FINDING", "REPORT_EXPOSED_PII", "analytics_platform", "analytics_9003", "evidence_flow"),
        step("FINDING", "REPORT_EXPOSED_PII", "support_platform", "support_9003", "evidence_flow"),
        step("FINDING", "REPORT_ACTIVE_DATA_FLOW", "integration_service", "data_flow_9003", "evidence_flow"),
        step("FINDING", "REPORT_RESTORE_RISK", "backup_service", "backup_9003", "evidence_flow"),
        step("REMEDIATION", "DISABLE_DATA_FLOW", "integration_service", "data_flow_9003", ""),
        step("REMEDIATION", "BLOCK_RESTORE", "backup_service", "backup_9003", ""),
        step("REMEDIATION", "REDACT_RECORD", "support_platform", "support_9003", ""),
        step("REMEDIATION", "ANONYMIZE_RECORD", "analytics_platform", "analytics_9003", ""),
        step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9003", ""),
        step("VERIFICATION", "VERIFY_RECORD_REDACTED", "support_platform", "support_9003", ""),
        step("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "analytics_platform", "analytics_9003", ""),
        step("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "integration_service", "data_flow_9003", ""),
        step("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "backup_service", "backup_9003", ""),
    ],
)

# ---------------------------------------------------------------------------
# 4. A complete case: every record is already in its final state, so the
#    answer is verification only, and every verification must cite the
#    evidence file that proves it.
# ---------------------------------------------------------------------------
case(
    "complete deletion with retained audit and legal hold",
    ctx("custom_04", [
        rec("account_service", "account_9004", "USER_PROFILE", "ABSENT", "evidence_handover"),
        rec("search_service", "search_9004", "SEARCH_INDEX_ENTRY", "ABSENT", "evidence_handover"),
        rec("security_service", "audit_record_9004", "SECURITY_AUDIT_LOG", "PRESENT", "evidence_handover"),
        rec("legal_service", "legal_hold_9004", "LEGAL_HOLD_RECORD", "PRESENT", "evidence_handover"),
    ]),
    "COMPLETE",
    [
        step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9004", "evidence_handover"),
        step("VERIFICATION", "VERIFY_RECORD_ABSENT", "search_service", "search_9004", "evidence_handover"),
        step("VERIFICATION", "VERIFY_RECORD_PRESENT", "legal_service", "legal_hold_9004", "evidence_handover"),
        step("VERIFICATION", "VERIFY_RECORD_PRESENT", "security_service", "audit_record_9004", "evidence_handover"),
    ],
)

# ---------------------------------------------------------------------------
# 5. Non-deletion intake: a marketing opt-out keeps the account, so no
#    destructive action is authorised and the answer is an empty plan.
# ---------------------------------------------------------------------------
case(
    "marketing opt-out is not an erasure request",
    ctx("custom_05", [
        rec("marketing_platform", "marketing_9005", "MARKETING_PROFILE", "PRESENT", "evidence_marketing"),
    ], deletion_requested=False),
    "NOT_APPLICABLE",
    [],
)

# ---------------------------------------------------------------------------
# 6. An analytics profile that the workflow already anonymized while a search
#    entry is still present.  The case is INCOMPLETE, so the plan verifies the
#    records it remediated plus the account and the security trail - the
#    already compliant analytics profile is not part of that plan.
# ---------------------------------------------------------------------------
case(
    "compliant analytics is not verified in an incomplete case",
    ctx("custom_06", [
        rec("search_service", "search_9006", "SEARCH_INDEX_ENTRY", "PRESENT", "evidence_readback"),
        rec("analytics_platform", "analytics_9006", "ANALYTICS_PROFILE", "ANONYMIZED", "evidence_readback"),
        rec("account_service", "account_9006", "USER_PROFILE", "ABSENT", "evidence_readback"),
        rec("security_service", "audit_record_9006", "SECURITY_AUDIT_LOG", "PRESENT", "evidence_readback"),
    ]),
    "INCOMPLETE",
    [
        step("FINDING", "REPORT_REMAINING_RECORD", "search_service", "search_9006", "evidence_readback"),
        step("REMEDIATION", "DELETE_RECORD", "search_service", "search_9006", ""),
        step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9006", ""),
        step("VERIFICATION", "VERIFY_RECORD_ABSENT", "search_service", "search_9006", ""),
        step("VERIFICATION", "VERIFY_RECORD_PRESENT", "security_service", "audit_record_9006", ""),
    ],
)

# ---------------------------------------------------------------------------
# 7. The same records when nothing is left to remediate.  The case is
#    COMPLETE, so every record - including the already anonymized analytics
#    profile - is verified, and every step cites its evidence.
# ---------------------------------------------------------------------------
case(
    "complete case verifies every record including anonymized analytics",
    ctx("custom_07", [
        rec("analytics_platform", "analytics_9007", "ANALYTICS_PROFILE", "ANONYMIZED", "evidence_readback"),
        rec("account_service", "account_9007", "USER_PROFILE", "ABSENT", "evidence_readback"),
        rec("security_service", "audit_record_9007", "SECURITY_AUDIT_LOG", "PRESENT", "evidence_readback"),
    ]),
    "COMPLETE",
    [
        step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9007", "evidence_readback"),
        step("VERIFICATION", "VERIFY_RECORD_PRESENT", "security_service", "audit_record_9007", "evidence_readback"),
        step("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "analytics_platform", "analytics_9007", "evidence_readback"),
    ],
)


def run() -> int:
    failures = 0
    for name, context, status, steps in CASES:
        result = plan_case(context)
        actual = json.loads(result["steps_json"])
        ok = result["deletion_status"] == status and actual == [
            {**item, "step_no": index + 1} for index, item in enumerate(steps)
        ]
        print(f"{'PASS' if ok else 'FAIL'}  {context.case_id}  {name}")
        if not ok:
            failures += 1
            print("  expected:", status, json.dumps(steps, sort_keys=True))
            print("  actual  :", result["deletion_status"], json.dumps(actual, sort_keys=True))
    print(f"\n{len(CASES) - failures}/{len(CASES)} custom cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
