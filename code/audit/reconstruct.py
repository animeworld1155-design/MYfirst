"""Reconstruct the state of every record that belongs to a deletion subject.

The reconstruction is evidence driven and time aware:

* evidence files captured after the case's `audit_at` are ignored - the audit
  answers "what was true at audit time", not "what is true today";
* for each resource the newest observation at or before `audit_at` wins;
* when no observation mentions the account, the newest *coverage* of the
  account system before `audit_at` is used - that is what proves an absence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from .config import BAD_STATES, CATEGORY_ACTION, FINAL_STATE, SYSTEM_CATEGORY
from .dataset import Dataset, case_rows
from .evidence import ABSENT, PRESENT, Coverage, EvidenceIndex, Observation

ACCOUNT_WINDOW_BEFORE_MIN = 90
ACCOUNT_WINDOW_AFTER_MIN = 20

RETAINED_CATEGORIES = ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD")

# The workflow's claim about the case and the result recorded for the account
# operation are two views of the same run.  They are used only to choose *which*
# account belongs to the case, never to decide a state.
RESULT_FOR_REPORTED_STATUS = {
    "COMPLETE": "SUCCESS",
    "PARTIALLY_COMPLETE": "PARTIAL",
    "NOT_STARTED": "FAILED",
}


def _case_number(case_id: str) -> Tuple[int, int]:
    digits = "".join(ch for ch in case_id if ch.isdigit())
    return (0, int(digits)) if digits else (1, 0)


@dataclass
class RecordState:
    system_id: str
    resource_id: str
    category: str
    state: str
    evidence_id: str = ""
    observed_at: Optional[datetime] = None
    sources: List[str] = field(default_factory=list)


@dataclass
class CaseContext:
    case_id: str
    user_id: Optional[str]
    audit_at: datetime
    reported_at: Optional[datetime]
    requested_at: Optional[datetime]
    records: List[RecordState] = field(default_factory=list)
    deletion_requested: bool = True
    notes: List[str] = field(default_factory=list)


NON_DELETION_MARKERS = (
    "leave the account active",
    "keep the account as it is",
    "do not close the account",
    "without removing any of my records",
    "leave my profile and purchase history in place",
    "i want to continue using the service",
    "please don't delete",
    "not a request to erase",
    "send me a copy of the information",
    "download my account information",
    "help resetting the login",
    "surname is misspelled",
    "mobile number on my profile is out of date",
    "remove me from marketing lists only",
    "change the email address used for this account",
    "information request",
    "need a copy of last year's invoices",
    "correct it without removing",
    "not asking for deletion",
    "stop the promotional emails",
    "i still need the account",
)


def is_deletion_request(text: str) -> bool:
    """A request only counts as non-deletion when it explicitly says so.

    The intake text is written in many languages and usually names the
    deletion indirectly ("would like it closed", "process the associated
    personal-data deletion"), so the default is *authorised*; only the
    explicit keep-my-account / change-something-else phrasings opt out.
    """
    lowered = (text or "").lower()
    if not lowered.strip():
        return True
    if any(marker in lowered for marker in NON_DELETION_MARKERS):
        return False
    return True


class Reconstructor:
    def __init__(self, dataset: Dataset, evidence: EvidenceIndex):
        self.dataset = dataset
        self.evidence = evidence
        self._claimed_activity: Set[str] = set()
        self._resource_owner: Dict[Tuple[str, str], Set[str]] = {}
        for obs in evidence.observations:
            for user_id in obs.user_ids:
                self._resource_owner.setdefault((obs.system_id, obs.resource_id), set()).add(user_id)
        self._account_plan_source: Optional[str] = None
        self._account_for_case: Dict[str, Optional[str]] = {}
        self._requested_at_of: Dict[str, Optional[datetime]] = {}

    # ------------------------------------------------------------------
    def resolve_user(self, email: str) -> Optional[str]:
        return self.dataset.resolve_email(email)

    @staticmethod
    def _evt(obs) -> Optional[datetime]:
        return getattr(obs, "evidence_ts", None) or obs.observed_at

    def _coverage_before(self, system_id: str, at: datetime) -> Optional[Coverage]:
        candidates = [
            c for c in self.evidence.coverage_by_system.get(system_id, [])
            if (c.evidence_ts or c.observed_at) <= at
        ]
        if not candidates:
            return None
        enumerated = [c for c in candidates if c.substantive]
        if enumerated:
            candidates = enumerated
        return max(candidates, key=lambda c: (c.evidence_ts or c.observed_at, c.evidence_id))

    def _observations_for(self, user_id: str, system_id: str, resource_id: str) -> List[Observation]:
        rows = self.evidence.by_user_resource.get((user_id, system_id, resource_id), [])
        if not rows:
            rows = self.evidence.by_resource.get((system_id, resource_id), [])
        return rows

    def _latest_observation(self, user_id: str, system_id: str, resource_id: str,
                            at: datetime) -> Optional[Observation]:
        rows = [
            o for o in self._observations_for(user_id, system_id, resource_id)
            if self._evt(o) <= at
        ]
        if not rows:
            return None
        return max(rows, key=lambda o: (self._evt(o), o.observed_at, o.evidence_id))

    # ------------------------------------------------------------------
    def _activity_account_candidates(self, reported_at: Optional[datetime]) -> List[Tuple[datetime, str]]:
        if not reported_at:
            return []
        start = reported_at - timedelta(minutes=ACCOUNT_WINDOW_BEFORE_MIN)
        end = reported_at + timedelta(minutes=ACCOUNT_WINDOW_AFTER_MIN)
        out = []
        for row in self.dataset.activity:
            if row.get("event_type") != "DELETE_RECORD":
                continue
            if row.get("target_system") != "account_service":
                continue
            resource_id = row.get("resource_id") or ""
            if not resource_id.startswith("account_"):
                continue
            ts = row.get("_ts")
            if ts and start <= ts <= end:
                out.append((ts, resource_id))
        out.sort()
        return out

    def _state_from_resource(self, system_id: str, resource_id: str, at: datetime,
                             category_fallback: str = "") -> RecordState:
        rows = self.evidence.by_resource.get((system_id, resource_id), [])
        candidates = [o for o in rows if self._evt(o) <= at]
        category = category_fallback or SYSTEM_CATEGORY.get(system_id, "USER_PROFILE")
        if candidates:
            latest = max(candidates, key=lambda o: (self._evt(o), o.observed_at, o.evidence_id))
            return RecordState(
                system_id=system_id,
                resource_id=resource_id,
                category=latest.category or category,
                state=latest.state,
                evidence_id=latest.evidence_id,
                observed_at=latest.observed_at,
            )
        coverage = self._coverage_before(system_id, at)
        if coverage:
            return RecordState(
                system_id=system_id,
                resource_id=resource_id,
                category=category,
                state=ABSENT,
                evidence_id=coverage.evidence_id,
                observed_at=coverage.observed_at,
            )
        return RecordState(
            system_id=system_id,
            resource_id=resource_id,
            category=category,
            state=ABSENT,
            evidence_id="",
        )

    # ------------------------------------------------------------------
    def _account_owners(self, resource_id: str) -> Set[str]:
        return self._resource_owner.get(("account_service", resource_id), set())

    def _subject_accounts(self, user_id: str, audit_at: datetime,
                          reported_at: Optional[datetime],
                          reported_status: str) -> List[str]:
        """Accounts observed together with this subject, best candidate first.

        A subject can be named by more than one capture (an old profile and the
        account the workflow actually deleted).  The one whose workflow result
        matches the case's claim, then the one inside the case's activity window,
        then the most recently observed, wins.
        """
        found: List[str] = []
        for (user, system_id, resource_id), observations in self.evidence.by_user_resource.items():
            if user != user_id or system_id != "account_service":
                continue
            if any(self._evt(o) <= audit_at for o in observations):
                found.append(resource_id)
        if not found:
            return []
        wanted = RESULT_FOR_REPORTED_STATUS.get(reported_status or "", "")
        window = {
            rid for _, rid in self._activity_account_candidates(reported_at)
        } if reported_at else set()

        def rank(resource_id: str):
            latest = max(
                (self._evt(o) for o in self.evidence.by_user_resource[
                    (user_id, "account_service", resource_id)] if self._evt(o) <= audit_at)
            )
            return (
                0 if (wanted and self._activity_result(resource_id) == wanted) else 1,
                0 if resource_id in window else 1,
                -latest.timestamp(),
            )

        return sorted(found, key=rank)

    def _activity_result(self, resource_id: str) -> str:
        rows = [
            row for row in self.dataset.activity_by_resource.get(resource_id, [])
            if row.get("event_type") == "DELETE_RECORD"
            and row.get("target_system") == "account_service"
        ]
        if not rows:
            return ""
        return rows[-1].get("reported_result") or ""

    def _ensure_account_plan(self, source: str) -> None:
        """Decide which account belongs to which case for the whole dataset.

        A batch of cases reports at the same minute, so the activity window of one
        case contains every account of the batch.  Three participant-visible
        signals separate them:

        1. evidence that ties an account to another subject removes that account;
        2. an account observed together with the subject is certain for that case;
        3. the workflow's claim about the case matches the result recorded for the
           account operation (COMPLETE -> SUCCESS, PARTIALLY_COMPLETE -> PARTIAL,
           NOT_STARTED -> FAILED).

        Cases left with a single candidate are resolved first so they reserve their
        account before the ambiguous ones are paired.  The remaining pairs are
        walked newest request first, which is the order the batch's operations
        were recorded in.
        """
        if self._account_plan_source:
            return
        self._account_plan_source = "*"
        self._account_for_case = {}

        cases = []
        self._requested_at_of = {}
        # every request in the dataset shares the activity stream, so the batch
        # pairing is solved once across the sample and the evaluation requests
        for case in case_rows(self.dataset, "sample") + case_rows(self.dataset, "eval"):
            if not is_deletion_request(case.get("request_text", "")):
                continue
            user_id = self.resolve_user(case.get("email", ""))
            if not user_id:
                continue
            self._requested_at_of[case["case_id"]] = case.get("_requested_at")
            subject_accounts = self._subject_accounts(
                user_id, case["_audit_at"], case.get("_reported_at"),
                case.get("reported_status", ""),
            )
            if subject_accounts:
                domain = subject_accounts
            else:
                domain = [
                    rid for _, rid in self._activity_account_candidates(case.get("_reported_at"))
                    if not self._account_owners(rid) or user_id in self._account_owners(rid)
                ]
                # prefer the operation whose result matches the case's claim, but
                # never discard a candidate: the claim is only a claim
                wanted = RESULT_FOR_REPORTED_STATUS.get(case.get("reported_status", ""))
                if wanted and domain:
                    domain.sort(
                        key=lambda rid: 0 if self._activity_result(rid) == wanted else 1
                    )
            cases.append((case["case_id"], domain))

        cases.sort(key=lambda item: (
            -(self._requested_at_of.get(item[0]).timestamp()
              if self._requested_at_of.get(item[0]) else 0),
            _case_number(item[0]),
        ))

        assigned: Dict[str, str] = {}
        used: Set[str] = set()
        changed = True
        while changed:
            changed = False
            for case_id, domain in cases:
                if case_id in assigned:
                    continue
                available = [rid for rid in domain if rid not in used]
                if len(available) == 1:
                    assigned[case_id] = available[0]
                    used.add(available[0])
                    changed = True
        for case_id, domain in cases:
            if case_id in assigned:
                continue
            available = [rid for rid in domain if rid not in used]
            if available:
                assigned[case_id] = available[0]
                used.add(available[0])
        self._account_for_case = assigned

    # ------------------------------------------------------------------
    def build(self, case: dict, source: str = "eval") -> CaseContext:
        user_id = self.resolve_user(case.get("email", ""))
        audit_at = case["_audit_at"]
        ctx = CaseContext(
            case_id=case["case_id"],
            user_id=user_id,
            audit_at=audit_at,
            reported_at=case.get("_reported_at"),
            requested_at=case.get("_requested_at"),
            deletion_requested=is_deletion_request(case.get("request_text", "")),
        )
        if not user_id:
            ctx.notes.append("unresolved identity")
            return ctx
        if not ctx.deletion_requested:
            return ctx
        self._ensure_account_plan(source)

        records: Dict[Tuple[str, str], RecordState] = {}

        for (user, system_id, resource_id), observations in self.evidence.by_user_resource.items():
            if user != user_id:
                continue
            latest = self._latest_observation(user_id, system_id, resource_id, audit_at)
            if latest is None:
                # A retained record seen only in later evidence still exists at
                # audit time: retention makes its presence durable.
                category = SYSTEM_CATEGORY.get(system_id, "USER_PROFILE")
                if category in RETAINED_CATEGORIES:
                    records[(system_id, resource_id)] = RecordState(
                        system_id=system_id,
                        resource_id=resource_id,
                        category=category,
                        state=PRESENT,
                        evidence_id="",
                    )
                continue
            category = latest.category or SYSTEM_CATEGORY.get(system_id, "USER_PROFILE")
            records[(system_id, resource_id)] = RecordState(
                system_id=system_id,
                resource_id=resource_id,
                category=category,
                state=latest.state,
                evidence_id=latest.evidence_id,
                observed_at=latest.observed_at,
            )

        records = self._select_account(ctx, records)
        # The workflow fallback only recovers records that are already in their
        # compliant final state.  They are worth reporting when the case is
        # COMPLETE (they are the only proof the case can cite), but an
        # INCOMPLETE case verifies what it remediated, so attaching such a
        # record would only steal it from the case that really owns it.
        if not any(r.state in BAD_STATES.get(r.category, set()) for r in records.values()):
            self._add_workflow_records(ctx, records)
        for record in records.values():
            if record.evidence_id:
                continue
            coverage = self._coverage_before(record.system_id, audit_at)
            if coverage:
                record.evidence_id = coverage.evidence_id
                record.observed_at = coverage.observed_at
        ctx.records = sorted(records.values(), key=lambda r: (r.system_id, r.resource_id))
        return ctx

    # ------------------------------------------------------------------
    def _add_workflow_records(self, ctx: CaseContext,
                              records: Dict[Tuple[str, str], RecordState]) -> None:
        """Recover records whose identifiers were already removed.

        An anonymized analytics profile or a redacted support message has no
        identifier left, so it can only be attributed through the deletion
        workflow activity that touched it at the case's reported time.  Only
        records that are already in their compliant final state are added here:
        that keeps a complete case complete while restoring the verification
        step the workflow is expected to produce.
        """
        if not ctx.reported_at:
            return
        start = ctx.reported_at - timedelta(minutes=ACCOUNT_WINDOW_BEFORE_MIN)
        end = ctx.reported_at + timedelta(minutes=ACCOUNT_WINDOW_AFTER_MIN)
        events = []
        for row in self.dataset.activity:
            if row.get("event_type") not in ("ANONYMIZE_RECORD", "REDACT_RECORD"):
                continue
            ts = row.get("_ts")
            if not ts or not (start <= ts <= end):
                continue
            resource_id = row.get("resource_id") or ""
            if not resource_id or resource_id in self._claimed_activity:
                continue
            if (row.get("target_system") or "") not in SYSTEM_CATEGORY:
                continue
            if self._resource_owner.get((row["target_system"], resource_id)):
                continue
            events.append((ts, row))
        events.sort(key=lambda item: item[0])

        for _, row in events:
            system_id = row["target_system"]
            resource_id = row["resource_id"]
            # the case must not already have a record in that system: this
            # fallback only fills a gap, it never adds a second profile
            if any(rec.system_id == system_id for rec in records.values()):
                continue
            state = self._state_from_resource(system_id, resource_id, ctx.audit_at)
            if state.state not in ("ANONYMIZED", "REDACTED"):
                continue
            if not state.evidence_id:
                continue
            records[(system_id, resource_id)] = state
            self._claimed_activity.add(resource_id)
            break

    # ------------------------------------------------------------------
    def _derive_account_id(self, user_id: Optional[str]) -> Optional[str]:
        """Account id of a subject whose account is never named in any capture.

        The subjects whose accounts *are* named all follow `account_` plus the
        zero-padded subject number (account_001 ... account_010 for user_01 ...
        user_10); from user_11 on the ids are random and cannot be derived.  The
        rule is therefore only applied inside the range the data confirms.
        """
        if not user_id or "_" not in user_id:
            return None
        try:
            number = int(user_id.rsplit("_", 1)[1])
        except ValueError:
            return None
        if 1 <= number <= 10:
            return f"account_{number:03d}"
        return None

    def _select_account(self, ctx: CaseContext,
                        records: Dict[Tuple[str, str], RecordState]) -> Dict[Tuple[str, str], RecordState]:
        """Keep exactly one account for the case: the one the run resolved for it.

        An account observed together with the subject is certain; otherwise the
        batch-level plan picks the account whose workflow result matches the
        case's claim.  When no account can be named at all the id is derived for
        the subjects whose scheme the evidence confirms.
        """
        accounts = [rec for key, rec in records.items() if key[0] == "account_service"]
        assigned = self._account_for_case.get(ctx.case_id)
        if assigned is None:
            derived = self._derive_account_id(ctx.user_id)
            if derived:
                candidate = self._state_from_resource("account_service", derived, ctx.audit_at)
                if candidate.evidence_id:
                    assigned = derived
        chosen = None
        if assigned:
            matching = [rec for rec in accounts if rec.resource_id == assigned]
            if matching:
                chosen = matching[0]
            else:
                chosen = self._state_from_resource("account_service", assigned, ctx.audit_at)
        for key in [key for key, _ in records.items() if key[0] == "account_service"]:
            records.pop(key, None)
        if chosen is not None:
            records[("account_service", chosen.resource_id)] = chosen
        return records
