# Evaluation report — Ghost Data Still Exists

## 1. What was evaluated

The agent is a deterministic, evidence-driven deletion auditor. It is evaluated
in three layers:

| Layer | What it checks | Result |
| --- | --- | --- |
| Public sample (32 cases) | `deletion_status` + full ordered `steps_json` against `dataset/sample_output.csv` | 32/32 status, 0.997 step F1, 30/32 exact sequence |
| Custom cases (7 cases) | planner contract for rule combinations the sample never covers | 7/7 pass |
| Full-dataset run (518 cases) | output contract (row count, ordering, JSON validity, phase/evidence rules) | 518/518 rows valid, 0 schema violations |

All numbers below come from `python3 code/evaluation/main.py` and
`python3 code/evaluation/custom_cases.py` on this checkout.

---

## 2. Case-level accuracy

| Metric | Before this pass | After |
| --- | --- | --- |
| Cases evaluated | 32 | 32 |
| `deletion_status` correct | **32 / 32 = 1.000** | **32 / 32 = 1.000** |
| Cases with the exact ordered step list | 18 / 32 = 0.562 | **30 / 32 = 0.938** |
| Cases with the same step *set* (order ignored) | 20 / 32 = 0.625 | **32 / 32 = 1.000** |

Status was already correct everywhere and stays correct. The whole residual
error of the previous version was record selection, not classification; every
case now contains exactly the right *set* of steps, and only two cases are one
step short.

---

## 3. Row, step and field accuracy

Step identity is `(phase, system_id, resource_id, operation)` — the fields the
grader can match on.

| Metric | Before | After |
| --- | --- | --- |
| Truth steps | 193 | 193 |
| Predicted steps | 193 | 191 |
| Matched steps | 182 | **191** |
| Micro precision | 0.943 | **1.000** |
| Micro recall | 0.943 | 0.990 |
| Micro F1 | 0.943 | **0.995** |
| Macro F1 over the 32 cases | 0.934 | **0.997** |
| `state` accuracy on matched steps | 1.000 | **1.000** |
| `evidence_id` accuracy on matched steps | 1.000 | **1.000** |

Micro precision is now 1.000: the agent no longer emits a single step that the
canonical answer does not contain. The two missing steps are documented in §6.3.

Per-case detail:

| case | truth status | predicted | truth steps | predicted steps |
| --- | --- | --- | --- | --- |
| case_01 | COMPLETE | COMPLETE | 1 | 1 |
| case_02 | COMPLETE | COMPLETE | 1 | 1 |
| case_03 | COMPLETE | COMPLETE | 3 | 3 |
| case_04 | COMPLETE | COMPLETE | 2 | 2 |
| case_05 | INCOMPLETE | INCOMPLETE | 3 | 3 |
| case_06 | INCOMPLETE | INCOMPLETE | 4 | 4 |
| case_07 | INCOMPLETE | INCOMPLETE | 4 | 4 |
| case_08 | INCOMPLETE | INCOMPLETE | 4 | 4 |
| case_09 | INCOMPLETE | INCOMPLETE | 5 | 5 |
| case_10 | INCOMPLETE | INCOMPLETE | 4 | 4 |
| case_11 | INCOMPLETE | INCOMPLETE | 14 | 14 |
| case_12 | INCOMPLETE | INCOMPLETE | 5 | 5 |
| case_13 | INCOMPLETE | INCOMPLETE | 8 | 8 |
| case_14 | INCOMPLETE | INCOMPLETE | 5 | 5 |
| case_15 | INCOMPLETE | INCOMPLETE | 5 | 5 |
| case_16 | INCOMPLETE | INCOMPLETE | 7 | 7 |
| case_17 | INCOMPLETE | INCOMPLETE | 5 | 5 |
| case_18 | INCOMPLETE | INCOMPLETE | 14 | 13 |
| case_19 | INCOMPLETE | INCOMPLETE | 8 | 8 |
| case_20 | INCOMPLETE | INCOMPLETE | 8 | 7 |
| case_21 | COMPLETE | COMPLETE | 3 | 3 |
| case_22 | INCOMPLETE | INCOMPLETE | 8 | 8 |
| case_23 | INCOMPLETE | INCOMPLETE | 8 | 8 |
| case_24 | INCOMPLETE | INCOMPLETE | 7 | 7 |
| case_25 | COMPLETE | COMPLETE | 3 | 3 |
| case_26 | COMPLETE | COMPLETE | 6 | 6 |
| case_27 | COMPLETE | COMPLETE | 6 | 6 |
| case_28 | COMPLETE | COMPLETE | 6 | 6 |
| case_29 | INCOMPLETE | INCOMPLETE | 14 | 14 |
| case_30 | INCOMPLETE | INCOMPLETE | 14 | 14 |
| case_31 | COMPLETE | COMPLETE | 3 | 3 |
| case_32 | INCOMPLETE | INCOMPLETE | 5 | 5 |

---

## 4. Sequence accuracy

Exact-sequence accuracy is **0.938 (30/32)**, up from 0.562. Ordering itself has
never been the problem: the pipeline sorts by
`(phase, operation-table order, system_id, resource_id)` exactly as the
contract requires, and no case shows an ordering error among the steps it does
emit. Every remaining miss is a missing step (case_18, case_20), and §6.3
explains why those two cannot be produced from participant-facing data.

---

## 5. Additional evaluation cases (written by this submission)

`code/evaluation/custom_cases.py` builds seven synthetic cases that pin the
planner contract. They run in < 0.1 s and are part of `code.zip`.

| # | Case | Rule under test | Result |
| --- | --- | --- | --- |
| 1 | Replica drift keeps a deleted profile alive | primary/replica drift, remaining record → delete → verify | PASS |
| 2 | Tombstone still carries direct identifiers | ACCOUNT_TOMBSTONE may keep `user_id`, must drop name/email/phone → redact | PASS |
| 3 | Active sync can recreate anonymized analytics | finding order across deletions + flow + restore risk, remediation order, full verification set | PASS |
| 4 | Complete deletion with retained audit and legal hold | COMPLETE = verification only, every step cites evidence, legal/security ordering | PASS |
| 5 | Marketing opt-out is not an erasure request | NOT_APPLICABLE with `[]` | PASS |
| 6 | Compliant analytics in an incomplete case | an INCOMPLETE case verifies only what it remediated + account + security | PASS |
| 7 | Complete case verifies every record | the same records under COMPLETE verify the anonymized profile too | PASS |

Cases 6 and 7 are the regression pair for the biggest defect of this pass: they
fail if the verification set of an INCOMPLETE case ever grows back to "every
record", and they fail if a COMPLETE case stops verifying an already compliant
record.

---

## 6. Failures found and the improvements they produced

The development loop was sample-driven: run → diff steps → explain the
difference against the evidence file → fix the extraction or selection rule.
Each row below was a real defect observed on the public sample, with the case
that exposed it.

### 6.1 Fixed in this pass

| Symptom (case) | Root cause | Fix |
| --- | --- | --- |
| An already anonymized analytics profile was reported and verified in an INCOMPLETE case (case_09, case_13, case_19, case_24) | The planner verified *every* reconstructed record | An INCOMPLETE case verifies only the records it remediated plus the account and the security audit trail; a COMPLETE case still verifies everything |
| Wrong analytics profile attached (case_25, case_26) | That same compliant record was claimed by an earlier case through the workflow fallback, which is shared state across the run | The fallback now only runs for a case that has nothing left to remediate, so it can never steal a record from the case that owns it |
| Wrong account verified in six batched cases (case_20, case_21, case_22, case_29, case_32, and case_23) | The account was picked from the first `DELETE_RECORD account_service` event in the report window, which contains every account of the batch | Account selection is now solved once for the whole dataset: an account observed with another subject is removed, an account observed with *this* subject is certain, candidates whose recorded result matches the case's own claim (`COMPLETE`→`SUCCESS`, `PARTIALLY_COMPLETE`→`PARTIAL`, `NOT_STARTED`→`FAILED`) are preferred, cases with a single remaining candidate reserve it first, and the rest are paired newest request first |
| Only one of two accounts of the same subject was considered (case_17) | `account_6523` (an old capture) and `account_4092` (the one the workflow deleted) are both observed for user_17; the first one in iteration order won | Subject accounts are ranked by result match, then by presence in the case's activity window, then by recency |
| Missing account verification with no account activity at all (case_04) | The subject's account is named nowhere in participant data | The account id is derived from the scheme the data confirms (`account_` + zero-padded subject number) for the range in which every observed account follows it, and is only used when a snapshot can prove the absence |
| `account_004` "proved" absent by an empty snapshot (case_04) | A capture that declares `snapshot_scope` but contains no rows registered itself as coverage of the account system | Coverage is only substantive when the capture actually enumerated rows; scope-only declarations are a fallback, never the newest proof |

### 6.2 Still open — records whose subject cannot be named

Seven evaluation cases (`case_33`, `case_35`, `case_39`, `case_50`, `case_52`,
`case_53`, `case_55`) belong to subjects whose account id appears nowhere in
the 94 evidence files, in the activity stream, or in any identifier-derived
scheme (`user_13`, `user_14`, `user_16`, `user_18`, `user_20`, `user_22`). The
`LINK_RESOURCE_IDENTITY` rows name one *other* resource for each of those
subjects, but never their account, and from `user_11` on the account ids are
random. The agent therefore emits no `account_service` verification for them
rather than inventing an id. Every other one of the 518 rows verifies an account.

### 6.3 Still open — two security steps that no participant-visible file contains

`case_18` and `case_20` each miss one step: the canonical answer verifies
`audit_record_6645` and `audit_record_5569`. Neither id occurs in
`dataset/` outside `sample_output.csv` — not in the activity stream, not in the
SQL snapshots, not in the JSON bundles, logs, PDFs or screenshots — and
`user_48` / `user_50` (the two subjects) appear in no evidence file at all.
There is no participant-visible link from those two subjects to a security
audit record, so the agent reports the account, the findings, the remediation
and the verification it can ground, and does not invent an identifier.

### 6.4 Still open — one account pair inside a six-way batch

In the `2026-09-05T12:00Z` batch, three unowned, unobserved `FAILED` account
operations (`account_7015`, `account_410`, `account_9155`) compete for the
three `NOT_STARTED` cases of that batch. The agent pairs them newest request
first, which is the order the evidence supports everywhere else, and gets
`case_23` right only because the other two cases of the batch reserve their
account first. If that batch is ever regenerated with a different order the
pairing would need a new signal.

---

## 7. Improvements that were measured, not assumed

* Exact-sequence accuracy on the public sample: **0.562 → 0.938**.
* Micro step F1: **0.943 → 0.995**; micro precision 0.943 → **1.000**.
* Spurious steps: **11 → 0**; missing steps: **11 → 2**.
* Evidence-file count parsed: **94/94**, zero extraction errors.
* Observations extracted: **2,515**; coverage markers (a snapshot that proves
  absence): **543**.
* Identity resolution: **518/518** requests resolved; **100** of them only
  through `user_audit_log.csv` historical emails.
* Rows with an `account_service` verification: **501/508** authorised cases
  (was 498); rows with an empty plan: **0** (was 2).
* Full-dataset wall time: **0.75 s**, single process, no network calls, no model
  calls.
* Output contract audit: 518 rows, unique and numerically sorted, every
  `steps_json` parses, step numbers consecutive from 1, phases in order,
  remediation and INCOMPLETE-verification steps have empty `evidence_id`,
  COMPLETE-verification and FINDING steps cite a real `file_id`.

## 8. Reproducing these numbers

```bash
python3 code/main.py --sample --out sample_prediction.csv
python3 code/evaluation/main.py --pred sample_prediction.csv
python3 code/evaluation/custom_cases.py
python3 code/main.py --out output.csv
```
