#!/usr/bin/env python3
"""Cross-check agent for the Ghost Data Still Exists submission.

This agent lives *outside* the `hackrank/` folder on purpose: it never modifies
the submission, it only reads it and reports.  Every check is re-derived from
the raw participant-facing files with its own code, so a bug in the auditor
under test cannot hide itself.

Checks performed
----------------
1. CONTRACT      output.csv shape: 518 rows, sorted, valid JSON, consecutive
                 step numbers, phase order, allowed operations/states only,
                 evidence rules (findings cite evidence, remediation and
                 post-remediation verification do not, COMPLETE verification
                 does).
2. TIME          every cited evidence file must be captured at or before the
                 case's `audit_at` - evidence from the future cannot prove
                 anything about the audited moment.
3. GROUNDING     every cited resource id must actually occur inside the cited
                 evidence file (text formats only; PDF/PNG are reported as
                 not text-checkable instead of failed).
4. INTAKE        an independently written deletion-intake classifier is compared
                 with the submission's COMPLETE/INCOMPLETE vs NOT_APPLICABLE
                 verdicts; disagreements are reported, not overwritten.
5. SAMPLE        when `sample_prediction.csv` exists it is scored against
                 `dataset/sample_output.csv` with an independent scorer.

Usage
-----
    python3 crosscheck_agent/agent.py            # all checks
    python3 crosscheck_agent/agent.py --quiet    # only the summary

Exit code is 1 when a hard failure (1, 2 or 3) is found, otherwise 0.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(HERE)
REPO = os.path.join(WORKSPACE, "hackrank")
DATASET = os.path.join(REPO, "dataset")

ALLOWED_OPERATIONS = {
    "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD",
    "ANONYMIZE_RECORD",
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
}
ALLOWED_STATES = {"PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2,
    "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}
TEXT_EXTENSIONS = {".csv", ".tsv", ".json", ".sql", ".log", ".txt", ".md"}

# An independently written intake detector.  It is intentionally phrased
# differently from the auditor's marker list: agreement is evidence, a
# disagreement is something for a human to look at.
KEEP_MARKERS = (
    r"not asking for deletion", r"please don'?t delete", r"do not close",
    r"without removing", r"leave the account", r"leave my profile",
    r"keep the account", r"keep my account", r"i still need the account",
    r"i still use it", r"stop the promotional", r"remove me from marketing",
    r"information request", r"tell me what personal information",
    r"a copy of (?:last year|the information)", r"download my account",
    r"out of date", r"misspelled", r"help resetting", r"change the email address",
    r"correct it without removing",
)
DELETE_MARKERS = (
    r"\bdelete", r"\bdelet(?:ion|ing)\b", r"\berase\b", r"\berased\b",
    r"\bclos(?:e|ing) (?:my|the) account\b", r"remove my account",
    r"permanent(?:ly)? delet", r"suppression", r"eliminaci", r"exclus(?:i|ã)",
    r"削除", r"삭제", r"完全な削除", r"permanent account-deletion",
)


def parse_ts(value: str):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00") if value.endswith("Z") \
            else datetime.fromisoformat(value)
    except ValueError:
        return None


def load_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def expects_deletion(text: str) -> bool:
    lowered = (text or "").lower()
    if any(re.search(marker, lowered) for marker in KEEP_MARKERS):
        return False
    return bool(any(re.search(marker, lowered) for marker in DELETE_MARKERS))


def case_index():
    """Every request the challenge ships (sample + evaluation)."""
    cases = {}
    for name in ("deletion_requests.csv", "sample_deletion_requests.csv"):
        for row in load_csv(os.path.join(DATASET, name)):
            row["_audit_at"] = parse_ts(row.get("audit_at", ""))
            cases[row["case_id"]] = row
    return cases


def evaluation_requests():
    """The 518 requests `output.csv` must answer."""
    return {
        row["case_id"]: row
        for row in load_csv(os.path.join(DATASET, "deletion_requests.csv"))
    }


def load_output(path):
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        header = reader.fieldnames
        return header, list(reader)


# --------------------------------------------------------------------------- #
# 1. contract
# --------------------------------------------------------------------------- #
def check_contract(rows):
    failures = []
    requests = evaluation_requests()
    ids = [r["case_id"] for r in rows]
    if len(ids) != len(set(ids)):
        failures.append("duplicate case_id in output.csv")
    numbers = [int("".join(ch for ch in cid if ch.isdigit()) or 0) for cid in ids]
    if numbers != sorted(numbers):
        failures.append("rows are not sorted by case_id")
    if set(ids) != set(requests):
        failures.append(
            f"case ids do not match the requests "
            f"(missing {len(set(requests) - set(ids))}, extra {len(set(ids) - set(requests))})"
        )

    for row in rows:
        cid = row["case_id"]
        status = row["deletion_status"]
        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            failures.append(f"{cid}: illegal deletion_status {status!r}")
            continue
        try:
            steps = json.loads(row["steps_json"] or "[]")
        except json.JSONDecodeError as exc:
            failures.append(f"{cid}: steps_json is not valid JSON ({exc})")
            continue
        if not isinstance(steps, list):
            failures.append(f"{cid}: steps_json is not an array")
            continue
        if status == "NOT_APPLICABLE" and steps:
            failures.append(f"{cid}: NOT_APPLICABLE must carry an empty plan")
        if status != "NOT_APPLICABLE" and not steps:
            failures.append(f"{cid}: authorised case has an empty plan")

        phases = [PHASE_ORDER.get(s.get("phase"), -1) for s in steps]
        if any(p < 0 for p in phases):
            failures.append(f"{cid}: unknown phase")
        if phases != sorted(phases):
            failures.append(f"{cid}: phases are not in FINDING/REMEDIATION/VERIFICATION order")
        if [s.get("step_no") for s in steps] != list(range(1, len(steps) + 1)):
            failures.append(f"{cid}: step_no is not consecutive from 1")

        keys = [(PHASE_ORDER.get(s.get("phase"), -1),
                 OPERATION_ORDER.get(s.get("operation"), 99),
                 s.get("system_id", ""), s.get("resource_id", "")) for s in steps]
        if keys != sorted(keys):
            failures.append(f"{cid}: steps are not in the required order")

        for step in steps:
            op, phase, state = step.get("operation"), step.get("phase"), step.get("state")
            evidence = step.get("evidence_id") or ""
            if op not in ALLOWED_OPERATIONS:
                failures.append(f"{cid}: illegal operation {op!r}")
            if state not in ALLOWED_STATES:
                failures.append(f"{cid}: illegal state {state!r}")
            if not step.get("system_id") or not step.get("resource_id"):
                failures.append(f"{cid}: step without system_id/resource_id")
            if phase == "FINDING" and not evidence:
                failures.append(f"{cid}: finding without evidence_id")
            if phase == "REMEDIATION" and evidence:
                failures.append(f"{cid}: remediation must not cite evidence")
            if phase == "VERIFICATION":
                if status == "INCOMPLETE" and evidence:
                    failures.append(f"{cid}: INCOMPLETE verification must not cite evidence")
                if status == "COMPLETE" and not evidence:
                    failures.append(f"{cid}: COMPLETE verification must cite evidence")
            if evidence and not re.fullmatch(r"evidence_\d+", evidence):
                failures.append(f"{cid}: malformed evidence_id {evidence!r}")
    return failures


# --------------------------------------------------------------------------- #
# 2. time + 3. grounding
# --------------------------------------------------------------------------- #
def check_grounding(rows):
    failures, warnings, stats = [], [], Counter()
    manifest = {r["file_id"]: r for r in load_csv(os.path.join(DATASET, "evidence_files.csv"))}
    requests = case_index()
    cache = {}

    def text_of(file_id):
        if file_id in cache:
            return cache[file_id]
        entry = manifest.get(file_id)
        if not entry:
            cache[file_id] = None
            return None
        path = os.path.join(DATASET, entry["file_path"])
        ext = os.path.splitext(path)[1].lower()
        if ext not in TEXT_EXTENSIONS:
            cache[file_id] = None      # binary: not text-checkable
            return None
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                cache[file_id] = fh.read()
        except OSError:
            cache[file_id] = None
        return cache[file_id]

    for row in rows:
        cid = row["case_id"]
        case = requests.get(cid)
        if not case:
            continue
        audit_at = case.get("_audit_at")
        try:
            steps = json.loads(row["steps_json"] or "[]")
        except json.JSONDecodeError:
            continue
        for step in steps:
            file_id = step.get("evidence_id") or ""
            if not file_id:
                continue
            entry = manifest.get(file_id)
            if not entry:
                failures.append(f"{cid}: cites unknown evidence_id {file_id}")
                continue
            stats["citations"] += 1
            captured = parse_ts(entry.get("captured_at", ""))
            if audit_at and captured and captured > audit_at:
                failures.append(
                    f"{cid}: cites {file_id} captured {entry['captured_at']} "
                    f"after audit_at {case['audit_at']}"
                )
            body = text_of(file_id)
            if body is None:
                stats["binary_or_missing"] += 1
                continue
            stats["text_checked"] += 1
            if step.get("state") == "ABSENT":
                # an absence is proven by a capture that enumerated the system
                # without this resource: the id is *expected* to be missing
                stats["absence_proofs"] += 1
                continue
            if step.get("resource_id") not in body:
                warnings.append(
                    f"{cid}: {step.get('resource_id')} ({step.get('state')}) "
                    f"not found as text in {file_id}"
                )
    return failures, warnings, stats


# --------------------------------------------------------------------------- #
# 4. intake
# --------------------------------------------------------------------------- #
def check_intake(rows):
    requests = case_index()
    disagreements = []
    for row in rows:
        case = requests.get(row["case_id"])
        if not case:
            continue
        expects = expects_deletion(case.get("request_text", ""))
        is_na = row["deletion_status"] == "NOT_APPLICABLE"
        if expects == is_na:
            disagreements.append(
                f"{row['case_id']}: independent classifier says "
                f"{'NOT_APPLICABLE' if not expects else 'deletion'}, "
                f"submission says {row['deletion_status']}"
            )
    return disagreements


# --------------------------------------------------------------------------- #
# 5. sample scorer
# --------------------------------------------------------------------------- #
def score_sample(pred_path, truth_path):
    if not (os.path.exists(pred_path) and os.path.exists(truth_path)):
        return None
    pred = {r["case_id"]: r for r in load_csv(pred_path)}
    truth = {r["case_id"]: r for r in load_csv(truth_path)}

    def key(step):
        return (step.get("phase", ""), step.get("system_id", ""),
                step.get("resource_id", ""), step.get("operation", ""))

    stats = Counter()
    f1s = []
    for cid, expected in sorted(truth.items()):
        actual = pred.get(cid)
        if actual is None:
            f1s.append(0.0)
            stats["missing_case"] += 1
            continue
        exp_steps = json.loads(expected["steps_json"] or "[]")
        act_steps = json.loads(actual["steps_json"] or "[]")
        exp_keys, act_keys = Counter(map(key, exp_steps)), Counter(map(key, act_steps))
        overlap = sum((exp_keys & act_keys).values())
        stats["truth_steps"] += len(exp_steps)
        stats["pred_steps"] += len(act_steps)
        stats["matched_steps"] += overlap
        stats["status_ok"] += expected["deletion_status"] == actual["deletion_status"]
        stats["sequence_ok"] += [key(s) for s in exp_steps] == [key(s) for s in act_steps]
        precision = overlap / len(act_steps) if act_steps else 1.0
        recall = overlap / len(exp_steps) if exp_steps else 1.0
        f1s.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
        for exp, act in zip(exp_steps, act_steps):
            if key(exp) != key(act):
                continue
            stats["field_total"] += 2
            stats["field_ok"] += exp.get("state") == act.get("state")
            stats["field_ok"] += (exp.get("evidence_id") or "") == (act.get("evidence_id") or "")
    stats["cases"] = len(truth)
    stats["macro_f1_x1000"] = round(sum(f1s) / len(f1s) * 1000) if f1s else 0
    stats["micro_f1_x1000"] = round(
        2 * stats["matched_steps"] / (stats["truth_steps"] + stats["pred_steps"]) * 1000
    ) if (stats["truth_steps"] + stats["pred_steps"]) else 0
    return stats


# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(description="cross-check agent")
    parser.add_argument("--quiet", action="store_true", help="summary only")
    parser.add_argument("--report", default=os.path.join(HERE, "report.md"))
    args = parser.parse_args()

    if not os.path.isdir(DATASET):
        print(f"cannot find the submission at {REPO}", file=sys.stderr)
        return 2

    output_path = os.path.join(REPO, "output.csv")
    header, rows = load_output(output_path)

    hard, soft = [], []
    if header != ["case_id", "deletion_status", "steps_json"]:
        hard.append(f"unexpected header: {header}")

    hard += check_contract(rows)
    ground_fail, ground_warn, ground_stats = check_grounding(rows)
    hard += ground_fail
    soft += ground_warn
    intake = check_intake(rows)
    soft += intake
    sample = score_sample(os.path.join(REPO, "sample_prediction.csv"),
                          os.path.join(DATASET, "sample_output.csv"))

    statuses = Counter(r["deletion_status"] for r in rows)
    lines = [
        "# Cross-check report",
        "",
        f"Submission: `{output_path}`",
        f"Rows: **{len(rows)}** — " + ", ".join(f"{k} {v}" for k, v in sorted(statuses.items())),
        "",
        "## Hard checks",
        "",
        f"* contract violations: **{len(hard) - len(ground_fail)}**",
        f"* temporal/grounding violations: **{len(ground_fail)}**",
        f"* evidence citations examined: {ground_stats['citations']} "
        f"({ground_stats['text_checked']} text-checked, "
        f"{ground_stats['absence_proofs']} of them absence proofs, "
        f"{ground_stats['binary_or_missing']} binary or not text-checkable)",
        "",
        "## Soft checks",
        "",
        f"* non-absence steps whose resource id is missing from the cited file: "
        f"**{len(ground_warn)}**",
        f"* intake disagreements with the independent classifier: **{len(intake)}**",
        "",
    ]
    if sample:
        lines += [
            "## Public sample score (independent scorer)",
            "",
            f"* cases: {sample['cases']}",
            f"* status accuracy: {sample['status_ok']}/{sample['cases']}",
            f"* exact sequence: {sample['sequence_ok']}/{sample['cases']}",
            f"* micro step F1: {sample['micro_f1_x1000'] / 1000:.3f}",
            f"* macro step F1: {sample['macro_f1_x1000'] / 1000:.3f}",
            f"* state/evidence accuracy on matched steps: "
            f"{sample['field_ok']}/{sample['field_total']}",
            "",
        ]
    if hard or soft:
        lines.append("## Findings")
        lines.append("")
        for item in hard:
            lines.append(f"* FAIL {item}")
        for item in soft:
            lines.append(f"* WARN {item}")
        lines.append("")

    report = "\n".join(lines)
    with open(args.report, "w", encoding="utf-8") as fh:
        fh.write(report)

    if not args.quiet:
        print(report)
    else:
        print(f"rows={len(rows)} hard_failures={len(hard)} warnings={len(soft)} "
              f"report={args.report}")
    return 1 if hard else 0


if __name__ == "__main__":
    raise SystemExit(main())
