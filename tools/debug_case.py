#!/usr/bin/env python3
"""Print reconstruction + predicted steps next to the sample truth for a case."""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "code"))

from audit.dataset import Dataset, case_rows  # noqa: E402
from audit.evidence import EvidenceIndex  # noqa: E402
from audit.planner import plan_case  # noqa: E402
from audit.reconstruct import Reconstructor  # noqa: E402


def main(case_ids):
    dataset = Dataset(ROOT)
    evidence = EvidenceIndex(dataset)
    rec = Reconstructor(dataset, evidence)
    rows = {r["case_id"]: r for r in case_rows(dataset, "sample")}
    for case_id in case_ids:
        case = rows[case_id]
        ctx = rec.build(case)
        print(f"=== {case_id} user={ctx.user_id} requested={ctx.deletion_requested}")
        print("records:")
        for r in ctx.records:
            print(f"   {r.system_id:22s} {r.resource_id:20s} {r.category:20s} {r.state:10s} {r.evidence_id}")
        expected = dataset.sample_output[case_id]
        print("expected:")
        for step in json.loads(expected["steps_json"]):
            print(f"   {step['phase'][:4]:4s} {step['operation'][:26]:26s} {step['system_id']:22s} "
                  f"{step['resource_id']:20s} {step['evidence_id']}")
        predicted = plan_case(ctx)
        print("predicted:", predicted["deletion_status"])
        for step in json.loads(predicted["steps_json"]):
            print(f"   {step['phase'][:4]:4s} {step['operation'][:26]:26s} {step['system_id']:22s} "
                  f"{step['resource_id']:20s} {step['evidence_id']}")
        print()
    if evidence.errors:
        print("errors:", evidence.errors)


if __name__ == "__main__":
    main(sys.argv[1:] or ["case_03"])
