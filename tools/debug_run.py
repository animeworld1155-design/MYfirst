#!/usr/bin/env python3
"""Print reconstruction for selected sample cases when the whole sample is run
in order (so cross-case state such as claimed activity matches a real run)."""
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
    rows = case_rows(dataset, "sample")
    for case in rows:
        ctx = rec.build(case, "sample")
        if case["case_id"] not in case_ids:
            continue
        print(f"=== {case['case_id']} user={ctx.user_id} "
              f"requested={ctx.deletion_requested} reported_at={ctx.reported_at}")
        for r in ctx.records:
            print(f"   {r.system_id:22s} {r.resource_id:20s} {r.category:20s} "
                  f"{r.state:10s} {r.evidence_id}")
        expected = dataset.sample_output[case["case_id"]]
        exp = json.loads(expected["steps_json"])
        pred = json.loads(plan_case(ctx)["steps_json"])
        ek = [(s["phase"], s["system_id"], s["resource_id"], s["operation"]) for s in exp]
        pk = [(s["phase"], s["system_id"], s["resource_id"], s["operation"]) for s in pred]
        for s in exp:
            if (s["phase"], s["system_id"], s["resource_id"], s["operation"]) not in pk:
                print(f"   MISSING {s['phase'][:4]} {s['operation']:26s} {s['system_id']:22s} "
                      f"{s['resource_id']:20s} {s['state']:10s} {s['evidence_id']}")
        for s in pred:
            if (s["phase"], s["system_id"], s["resource_id"], s["operation"]) not in ek:
                print(f"   EXTRA   {s['phase'][:4]} {s['operation']:26s} {s['system_id']:22s} "
                      f"{s['resource_id']:20s} {s['state']:10s} {s['evidence_id']}")
        print()
    print("claimed:", sorted(rec._claimed_activity))
    if evidence.errors:
        print("errors:", evidence.errors)


if __name__ == "__main__":
    main(set(sys.argv[1:] or ["case_04"]))
