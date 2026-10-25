"""Static policy tables for the deletion-audit agent.

Everything here is derived from the participant-facing files:
  * dataset/deletion_rules.csv  (category -> required action)
  * problem_statement.md        (allowed operations and ordering)
"""

# ---------------------------------------------------------------------------
# Operation table (order matters: the grader requires steps to be ordered by
# phase, then by the order of this table, then by system_id / resource_id).
# ---------------------------------------------------------------------------
FINDING_OPS = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_OPS = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}
VERIFICATION_OPS = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

STATE_BY_OP = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

# ---------------------------------------------------------------------------
# Data categories.  action is the treatment required by deletion_rules.csv;
# when a category is conditional the rule text is recorded in the comment.
# ---------------------------------------------------------------------------
DELETE = "DELETE"
REDACT = "REDACT"
ANONYMIZE = "ANONYMIZE"
RETAIN = "RETAIN"

CATEGORY_ACTION = {
    "USER_PROFILE": DELETE,            # rule_01
    "SECONDARY_IDENTIFIER": DELETE,    # rule_02
    "SEARCH_INDEX_ENTRY": DELETE,      # rule_03
    "CACHE_ENTRY": DELETE,             # rule_04
    "SUPPORT_MESSAGE": REDACT,         # rule_05 (conversation context retained)
    "SUPPORT_ATTACHMENT": DELETE,      # rule_06 (attachment belongs only to subject)
    "ANALYTICS_PROFILE": ANONYMIZE,    # rule_07
    "PRODUCT_TELEMETRY": ANONYMIZE,    # rule_08
    "USER_EXPORT": DELETE,             # rule_09
    "MARKETING_PROFILE": DELETE,       # rule_10
    "EMAIL_DELIVERY_LOG": REDACT,      # rule_11
    "SECURITY_AUDIT_LOG": RETAIN,      # rule_12
    "LEGAL_HOLD_RECORD": RETAIN,       # rule_13
    "BACKUP_ARCHIVE": RETAIN,          # rule_14 (restore access can be blocked)
    "ACCOUNT_TOMBSTONE": REDACT,       # rule_15 (stable user_id may remain)
}

# system_id -> default category for a record found in that system
SYSTEM_CATEGORY = {
    "account_service": "USER_PROFILE",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "cache_service": "CACHE_ENTRY",
    "support_platform": "SUPPORT_MESSAGE",
    "analytics_platform": "ANALYTICS_PROFILE",
    "telemetry_service": "PRODUCT_TELEMETRY",
    "export_service": "USER_EXPORT",
    "object_store": "USER_EXPORT",
    "marketing_platform": "MARKETING_PROFILE",
    "email_delivery_service": "EMAIL_DELIVERY_LOG",
    "security_service": "SECURITY_AUDIT_LOG",
    "legal_service": "LEGAL_HOLD_RECORD",
    "backup_service": "BACKUP_ARCHIVE",
    "integration_service": "DATA_FLOW",
}

# record_type strings used by the evidence exports -> category
RECORD_TYPE_CATEGORY = {
    "USER_PROFILE": "USER_PROFILE",
    "SECONDARY_IDENTIFIER": "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY": "CACHE_ENTRY",
    "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT",
    "SUPPORT_TICKET": "SUPPORT_MESSAGE",
    "ANALYTICS_PROFILE": "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY": "PRODUCT_TELEMETRY",
    "USER_EXPORT": "USER_EXPORT",
    "MARKETING_PROFILE": "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG": "EMAIL_DELIVERY_LOG",
    "SECURITY_AUDIT_LOG": "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD": "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",
    "ACCOUNT_TOMBSTONE": "ACCOUNT_TOMBSTONE",
    "DATA_FLOW": "DATA_FLOW",
}

# ---------------------------------------------------------------------------
# State vocabulary used across evidence.  Normalised to a small set:
#   PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
# ---------------------------------------------------------------------------
STATE_ALIASES = {
    "FOUND": "PRESENT",
    "EXISTS": "PRESENT",
    "PRESENT": "PRESENT",
    "IDENTIFIABLE": "PRESENT",
    "NOT_FOUND": "ABSENT",
    "ABSENT": "ABSENT",
    "MISSING": "ABSENT",
    "DELETED": "ABSENT",
    "REDACTED": "REDACTED",
    "ANONYMIZED": "ANONYMIZED",
    "ANONYMISED": "ANONYMIZED",
    "ACTIVE": "ACTIVE",
    "ENABLED": "ACTIVE",
    "RESTORE_ALLOWED": "ACTIVE",
    "ALLOWED": "ACTIVE",
    "DISABLED": "DISABLED",
    "INACTIVE": "DISABLED",
    "STOPPED": "DISABLED",
    "BLOCKED": "BLOCKED",
}

# required final state per category (verification target)
FINAL_STATE = {
    "USER_PROFILE": "ABSENT",
    "SECONDARY_IDENTIFIER": "ABSENT",
    "SEARCH_INDEX_ENTRY": "ABSENT",
    "CACHE_ENTRY": "ABSENT",
    "SUPPORT_ATTACHMENT": "ABSENT",
    "USER_EXPORT": "ABSENT",
    "MARKETING_PROFILE": "ABSENT",
    "SUPPORT_MESSAGE": "REDACTED",
    "EMAIL_DELIVERY_LOG": "REDACTED",
    "ANALYTICS_PROFILE": "ANONYMIZED",
    "PRODUCT_TELEMETRY": "ANONYMIZED",
    "ACCOUNT_TOMBSTONE": "REDACTED",
    "SECURITY_AUDIT_LOG": "PRESENT",
    "LEGAL_HOLD_RECORD": "PRESENT",
    "BACKUP_ARCHIVE": "BLOCKED",
    "DATA_FLOW": "DISABLED",
}

# state of a record that is a policy violation, per category
BAD_STATES = {
    "USER_PROFILE": {"PRESENT"},
    "SECONDARY_IDENTIFIER": {"PRESENT"},
    "SEARCH_INDEX_ENTRY": {"PRESENT"},
    "CACHE_ENTRY": {"PRESENT"},
    "SUPPORT_ATTACHMENT": {"PRESENT"},
    "USER_EXPORT": {"PRESENT"},
    "MARKETING_PROFILE": {"PRESENT"},
    "SUPPORT_MESSAGE": {"PRESENT"},
    "EMAIL_DELIVERY_LOG": {"PRESENT"},
    "ANALYTICS_PROFILE": {"PRESENT"},
    "PRODUCT_TELEMETRY": {"PRESENT"},
    "ACCOUNT_TOMBSTONE": {"PRESENT"},
    "SECURITY_AUDIT_LOG": set(),
    "LEGAL_HOLD_RECORD": set(),
    "BACKUP_ARCHIVE": {"ACTIVE"},
    "DATA_FLOW": {"ACTIVE"},
}

FINDING_FOR_CATEGORY = {
    "DATA_FLOW": "REPORT_ACTIVE_DATA_FLOW",
    "BACKUP_ARCHIVE": "REPORT_RESTORE_RISK",
}
REMEDIATION_FOR_ACTION = {
    DELETE: "DELETE_RECORD",
    REDACT: "REDACT_RECORD",
    ANONYMIZE: "ANONYMIZE_RECORD",
}
VERIFICATION_FOR_FINAL = {
    "ABSENT": "VERIFY_RECORD_ABSENT",
    "PRESENT": "VERIFY_RECORD_PRESENT",
    "REDACTED": "VERIFY_RECORD_REDACTED",
    "ANONYMIZED": "VERIFY_RECORD_ANONYMIZED",
    "DISABLED": "VERIFY_DATA_FLOW_DISABLED",
    "BLOCKED": "VERIFY_RESTORE_BLOCKED",
}

# PII fields that must be removed by REDACT / ANONYMIZE
DIRECT_IDENTIFIERS = ("full_name", "name", "email", "phone", "email_hash")
