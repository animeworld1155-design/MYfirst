#!/usr/bin/env python3
"""Ghost Data Still Exists - deletion audit agent.

Usage:
    python3 code/main.py                 # audit dataset/deletion_requests.csv -> output.csv
    python3 code/main.py --sample        # audit the public sample -> sample_prediction.csv
    python3 code/main.py --explain case_105
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
for _deps in (
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".deps"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".deps"),
):
    if os.path.isdir(_deps):
        sys.path.insert(0, _deps)

from audit.dataset import Dataset, case_rows  # noqa: E402
from audit.evidence import EvidenceIndex  # noqa: E402
from audit.planner import plan_case, write_output  # noqa: E402
from audit.reconstruct import Reconstructor  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build(root: str):
    dataset = Dataset(root)
    evidence = EvidenceIndex(dataset)
    return dataset, evidence, Reconstructor(dataset, evidence)


def run(root: str, source: str, out_path: str) -> int:
    dataset, evidence, reconstructor = build(root)
    rows = case_rows(dataset, source)
    predictions = []
    for case in rows:
        ctx = reconstructor.build(case, source)
        predictions.append(plan_case(ctx))
    write_output(out_path, predictions)
    if evidence.errors:
        print("evidence warnings:", file=sys.stderr)
        for file_id, message in evidence.errors:
            print(f"  {file_id}: {message}", file=sys.stderr)
    print(f"wrote {len(predictions)} rows to {out_path}")
    return 0


def explain(root: str, case_id: str) -> int:
    dataset, evidence, reconstructor = build(root)
    rows = [row for row in case_rows(dataset, "eval") + case_rows(dataset, "sample")
            if row["case_id"] == case_id]
    if not rows:
        print(f"unknown case {case_id}", file=sys.stderr)
        return 1
    ctx = reconstructor.build(rows[0])
    print(json.dumps({
        "case_id": ctx.case_id,
        "user_id": ctx.user_id,
        "deletion_requested": ctx.deletion_requested,
        "records": [
            {
                "system": r.system_id,
                "resource": r.resource_id,
                "category": r.category,
                "state": r.state,
                "evidence": r.evidence_id,
                "observed_at": r.observed_at.isoformat() if r.observed_at else None,
            }
            for r in ctx.records
        ],
    }, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists")
    parser.add_argument("--root", default=REPO_ROOT)
    parser.add_argument("--sample", action="store_true", help="run the public sample cases")
    parser.add_argument("--out", default=None)
    parser.add_argument("--explain", default=None)
    args = parser.parse_args()

    if args.explain:
        return explain(args.root, args.explain)
    source = "sample" if args.sample else "eval"
    out_path = args.out or os.path.join(
        args.root, "sample_prediction.csv" if args.sample else "output.csv"
    )
    return run(args.root, source, out_path)


if __name__ == "__main__":
    raise SystemExit(main())
