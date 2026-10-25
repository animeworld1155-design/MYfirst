# Ghost Data Still Exists — deletion-audit agent

A deterministic auditor that answers, for every request, whether the customer's
personal data is really gone. It reconstructs the state of each record at the
case's `audit_at`, applies `deletion_rules.csv`, and emits the ordered
findings → remediation → verification plan.

## Run it

```bash
# audit all 518 evaluation requests -> ./output.csv
python3 code/main.py

# audit the 32 public sample cases -> ./sample_prediction.csv
python3 code/main.py --sample

# print the record reconstruction for one case
python3 code/main.py --explain case_105

# score a prediction file against the public answers
python3 code/evaluation/main.py --pred sample_prediction.csv

# planner contract tests (5 hand-built cases)
python3 code/evaluation/custom_cases.py
```

Requirements: **Python 3.10+**, standard library only.
`pypdf` is optional (see "PDF and image evidence" below); if it is installed the
four PDF documents are re-parsed from source, otherwise the committed text cache
is used. Nothing else is installed, no network access is used, and no API key is
required.

Typical runtime for the full 518-case dataset: **under one second**.

## Output

`output.csv` — `case_id,deletion_status,steps_json`, one row per request,
numerically sorted by `case_id`. `steps_json` is an ordered JSON array of
`{step_no, phase, system_id, resource_id, operation, state, evidence_id}`.

Ordering follows the contract: phase (FINDING → REMEDIATION → VERIFICATION),
then the operation order of the problem statement, then `system_id`, then
`resource_id`.

## How it works

```
code/
├── main.py                 CLI: build -> reconstruct -> plan -> output.csv
├── audit/
│   ├── config.py           operation table, category → action, state vocabulary
│   ├── dataset.py          CSV loading, identity index (current + historical)
│   ├── evidence.py         94 evidence files → Observation / Coverage table
│   ├── reconstruct.py      per-case record state at audit_at
│   ├── planner.py          findings/remediation/verification + CSV writer
│   └── cache/
│       ├── document_text.json    extracted text of the four PDFs
│       └── image_evidence.json   structured transcription of the screenshots
└── evaluation/
    ├── main.py             sample scorer (status, step F1, fields, sequence)
    ├── custom_cases.py     five hand-built planner tests
    ├── evaluation_report.md
    └── usage_report.md
```

1. **Identity resolution.** The request email is resolved against the current
   snapshot (`user_identities.csv`) and against every historical email in
   `user_audit_log.csv`; phone and `email_hash` changes are indexed the same
   way. A record is linked to a person by any of: `user_*` reference, email,
   phone, email hash. 100 of the 518 requests resolve only through history.

2. **Evidence extraction.** Each file becomes observations
   `(evidence, time, system, resource, category, state, identifiers)`:
   * SQL snapshots are executed in an in-memory SQLite database, so primary,
     read, reporting, regional and failover replicas are all queried directly
     (replication drift becomes visible as a record that is present in one
     replica only).
   * JSON snapshot bundles, service resource exports, export manifests,
     connector configurations and audit ledgers are parsed structurally.
   * Logs (five different formats, including embedded JSON and syslog) are
     parsed into key/value records; lines are grouped by `trace_id` so the
     identifier from the "started" line can be attached to the resource and
     state of the "completed" line.
   * PDFs and screenshots are read through the committed caches described
     below.
   * A *coverage* marker records the systems a snapshot enumerated; coverage is
     what turns "the record is not in this account capture" into a provable
     absence.

3. **Reconstruction at `audit_at`.** Evidence captured after the case's
   `audit_at` is ignored. For each resource the newest observation at or before
   `audit_at` wins; if the account was never observed, the newest capture that
   really enumerated the account system before `audit_at` proves the absence (a
   file that only declares a `snapshot_scope` and contains no rows proves
   nothing). Records that only appear in later evidence are kept when their
   category is a retention category (security audit log, legal hold).

   **Account resolution.** Cases of a batch report at the same minute, so a
   single case's activity window holds every account of the batch. Which account
   belongs to the case is decided once for the whole dataset:

   * an account observed together with *another* subject is removed;
   * an account observed together with *this* subject is certain for it
     (ranked by workflow-result match, presence in the window, recency);
   * candidates whose recorded operation result matches the case's own claim
     (`COMPLETE`→`SUCCESS`, `PARTIALLY_COMPLETE`→`PARTIAL`,
     `NOT_STARTED`→`FAILED`) are preferred — used as a tie-break only, never to
     discard a candidate;
   * cases with a single remaining candidate reserve it first, the rest are
     paired newest request first;
   * when no capture ever names the account, the id is derived from the scheme
     the data confirms (`account_` + zero-padded subject number, `user_01` …
     `user_10`) and only kept if a snapshot can prove the absence.

4. **Policy.** `deletion_rules.csv` is encoded as category → action:
   DELETE / REDACT / ANONYMIZE for profiles, search entries, exports, caches,
   support attachments, marketing profiles; REDACT for support messages, email
   delivery logs and account tombstones; ANONYMIZE for analytics and telemetry;
   RETAIN for security audit, legal hold and backups (with restore blocking).

5. **Plan.** A record in a non-compliant state becomes a finding; its action
   becomes the remediation. A `COMPLETE` case then verifies **every** record it
   reconstructed and cites the evidence that proves each state. An `INCOMPLETE`
   case verifies what it remediated plus the two records every case must account
   for — the account itself and the retained security audit trail — because a
   record that is already in its required final state is not part of a plan that
   still has work to do. INCOMPLETE cases cite evidence on findings and leave
   remediation/verification empty. NOT_APPLICABLE requests (an information
   request, an opt-out that keeps the account, a data correction) produce `[]`.

## PDF and image evidence

The runtime may not have `pypdf`, and it has no OCR engine. Both gaps are
handled with committed caches that are part of this archive:

* `code/audit/cache/document_text.json` — the text of the four supplied PDFs.
  If `pypdf` is importable the documents are parsed live and the cache is only
  a fallback.
* `code/audit/cache/image_evidence.json` — record-level facts transcribed from
  the eleven console screenshots (system, resource id, state and the visible
  identifiers). Each entry is one visible record; the provenance is the file
  named in the entry and its `captured_at` in `evidence_files.csv`.

Neither cache contains guessed data: a fact is only recorded when it is visible
in the supplied file.

## Design decisions worth calling out

* **Reported status is a claim.** `reported_status` and activity
  `reported_result` are never used as proof of a state; the reported status is
  only used as a tie-break when several accounts of a batch could belong to a
  case, and the workflow window is only used to recover an account id when no
  capture ever shows it.
* **Replicas are first-class.** A row present in any replica is present, even
  if the primary has already removed it.
* **Tombstones keep the stable reference.** `ACCOUNT_TOMBSTONE` is redacted
  (name/email/phone/hash removed) rather than deleted; the retained `user_id`
  is expected to remain.
* **Not-applicable is decided from the request text**, not from the reported
  status: only explicit keep-my-account / information-request / opt-out
  phrasings opt out of a deletion; everything else is treated as authorised.

See `code/evaluation/evaluation_report.md` for measured accuracy, the custom
test cases, and the known limitations.
