#!/usr/bin/env python3
"""Deep inspection of one case: identity, activity window, linked evidence."""
from __future__ import annotations

import os
import sys
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "code"))

from audit.dataset import Dataset, case_rows  # noqa: E402
from audit.evidence import EvidenceIndex  # noqa: E402
from audit.reconstruct import Reconstructor  # noqa: E402


def main(case_ids):
    dataset = Dataset(ROOT)
    evidence = EvidenceIndex(dataset)
    rec = Reconstructor(dataset, evidence)
    rows = {r["case_id"]: r for r in case_rows(dataset, "sample")}
    for case_id in case_ids:
        case = rows[case_id]
        ctx = rec.build(case, "sample")
        print(f"=== {case_id} email={case['email']} user={ctx.user_id}")
        print(f"    requested={case['requested_at']} reported={case['reported_at']} "
              f"audit={case['audit_at']} status={case['reported_status']}")
        print(f"    text: {case['request_text'][:160]}")
        person = dataset.people.get(ctx.user_id)
        ident = {k: sorted(v) for k, v in person.identifiers().items()} if person else {}
        print(f"    identifiers: {ident}")
        start = ctx.reported_at - timedelta(minutes=90)
        end = ctx.reported_at + timedelta(minutes=20)
        print("    activity in window:")
        for row in sorted(dataset.activity, key=lambda r: r["_ts"]):
            if row["_ts"] and start <= row["_ts"] <= end:
                print(f"      {row['activity_id']} {row['_ts']} {row['event_type']:18s} "
                      f"{row['source_system']:20s}->{row['target_system']:22s} "
                      f"{row['resource_id']:20s} {row['reported_result']:10s} "
                      f"{(row.get('details') or '')[:90]}")
        print("    observations linked to user:")
        for (user, system, resource), obs in sorted(evidence.by_user_resource.items()):
            if user != ctx.user_id:
                continue
            for o in obs:
                print(f"      {o.evidence_id} {(o.evidence_ts or o.observed_at)} "
                      f"{system:22s} {resource:20s} {o.category:20s} {o.state:10s} ids={sorted(o.user_ids)}")
        print("    reconstructed:")
        for r in ctx.records:
            print(f"      {r.system_id:22s} {r.resource_id:20s} {r.category:20s} {r.state:10s} {r.evidence_id}")
        print()


if __name__ == "__main__":
    main(sys.argv[1:] or ["case_04"])
