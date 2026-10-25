#!/usr/bin/env python3
"""Show every account candidate for a case and where each one is mentioned."""
from __future__ import annotations

import os
import sys

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
        print(f"=== {case_id} user={ctx.user_id} reported={ctx.reported_at} audit={ctx.audit_at}")
        cands = rec._activity_account_candidates(ctx.reported_at)
        print(f"    activity candidates ({len(cands)}):")
        for ts, rid in cands:
            st = rec._state_from_resource("account_service", rid, ctx.audit_at)
            obs = evidence.by_resource.get(("account_service", rid), [])
            mentions = sorted({o.evidence_id for o in obs})
            print(f"      {rid:14s} {ts}  state={st.state:8s} "
                  f"cov={st.evidence_id:11s} obs={mentions}")
        print("    truth:",
              [s["resource_id"] for s in __import__("json").loads(
                  dataset.sample_output[case_id]["steps_json"])
               if s["system_id"] == "account_service"])
        print()


if __name__ == "__main__":
    main(sys.argv[1:] or ["case_21"])
