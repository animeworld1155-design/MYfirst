# Usage report — final full-dataset run

## 1. Run that produced `output.csv`

| Item | Value |
| --- | --- |
| Command | `python3 code/main.py --out output.csv` |
| Input | `dataset/deletion_requests.csv` (518 rows) + `dataset/evidence/**` (94 files) |
| Output | `output.csv` — 518 rows + header, 593 KB |
| Runtime | CPython 3.12.3, single process, no network access |
| Wall time | **0.73 s** total (0.14 s parsing 94 evidence files, 0.39 s reconstruct + plan, 0.04 s load + serialise) |
| Peak working set | < 250 MB (all parsed evidence is held in memory) |
| Model calls | **0** |
| Input tokens | **0** |
| Output tokens | **0** |
| Estimated cost | **$0.00** |

## 2. Models used by the solution

**None.** The submitted agent is a deterministic program: CSV/SQL/JSON/log/PDF
parsing, identifier matching and rule evaluation in `code/audit/`. There is no
model provider, no API key, no SDK and no network dependency in the runnable
path.

| Provider | Model | Calls | Input tokens | Output tokens | Cost |
| --- | --- | --- | --- | --- | --- |
| — | — | 0 | 0 | 0 | $0.00 |

Per-model and overall totals are therefore identical: zero. Average tokens per
request is 0.000 for all 518 requests.

## 3. Why a deterministic agent, and what it cost

The choice was made deliberately after reading the dataset:

* Every fact the grader rewards is present in the supplied files (SQL snapshots,
  JSON exports, service logs, PDFs, screenshots), and the required output is
  fully specified — a model would add variance, cost and latency without adding
  evidence.
* 518 cases × repeated experimentation is exactly the workload where per-request
  cost compounds. At a representative price of $3 per million input tokens and
  $15 per million output tokens, an LLM pipeline with ~4,000 input tokens and
  ~400 output tokens per case would have cost roughly $11 for one full pass
  (518 × (0.012 + 0.006) ≈ $9.3–$12 depending on provider) and dozens of passes
  during development. This solution costs $0 per pass and runs in under a
  second, so evaluation iterations were effectively free.
* Determinism makes the audit reproducible: the same evidence always produces
  the same 518 rows, which is what an audit trail needs.

## 4. Work performed per request

| Stage | Work per case |
| --- | --- |
| Identity resolution | 1 hash lookup across 850 current identities + 107 historical email changes + 92 phone changes |
| Evidence selection | 2,515 observations indexed by (user, system, resource); latest observation ≤ `audit_at` per resource, coverage lookup for absences |
| Policy application | 15 deletion-rules mapped to action → finding/remediation/verification ops |
| Planning | Step sort over the operation table, JSON serialisation |

Aggregate for the full run: 2,515 observations extracted from 94 files, 543
coverage markers, 518 cases planned, 3,034 steps emitted, plus one
whole-dataset account assignment pass (550 requests, 4,011 activity rows)
that runs once per process.

## 5. Development-time usage (not part of the solution)

The system was built in an AI coding session (Buffy / Freebuff Desktop, cloud
mode). That session is not part of the runnable submission, consumes no
credentials at run time, and is recorded in `log.txt` for the transcript
deliverable. No API keys, tokens or credentials are used by or stored in the
solution.
