# Cross-check report

Submission: `/workspace/chats/04a25cf7243f281d86726e36/hackrank/output.csv`
Rows: **518** — COMPLETE 167, INCOMPLETE 341, NOT_APPLICABLE 10

## Hard checks

* contract violations: **0**
* temporal/grounding violations: **0**
* evidence citations examined: 1194 (1183 text-checked, 167 of them absence proofs, 11 binary or not text-checkable)

## Soft checks

* non-absence steps whose resource id is missing from the cited file: **1**
* intake disagreements with the independent classifier: **0**

## Public sample score (independent scorer)

* cases: 32
* status accuracy: 32/32
* exact sequence: 30/32
* micro step F1: 0.995
* macro step F1: 0.997
* state/evidence accuracy on matched steps: 374/374

## Findings

* WARN case_46: audit_record_1797 (PRESENT) not found as text in evidence_66
