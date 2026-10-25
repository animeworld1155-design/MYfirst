#!/usr/bin/env python3
"""Diff a prediction file against the public sample answers, step by step."""
from __future__ import annotations

import csv
import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return {r["case_id"]: r for r in csv.DictReader(fh)}


def key(s):
    return (s["phase"], s["system_id"], s["resource_id"], s["operation"])


def fmt(s):
    ev = s.get("evidence_id") or '""'
    return (f"{s['phase'][:4]:4s} {s['operation']:26s} {s['system_id']:22s} "
            f"{s['resource_id']:22s} {s.get('state',''):10s} {ev}")


def main():
    pred_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "sample_prediction.csv")
    truth = load(os.path.join(ROOT, "dataset", "sample_output.csv"))
    pred = load(pred_path)
    only = set(sys.argv[2:])
    for case_id in sorted(truth):
        if only and case_id not in only:
            continue
        exp = json.loads(truth[case_id]["steps_json"] or "[]")
        act = json.loads(pred.get(case_id, {}).get("steps_json") or "[]")
        if exp == act and truth[case_id]["deletion_status"] == pred.get(case_id, {}).get("deletion_status"):
            continue
        ec, ac = Counter(map(key, exp)), Counter(map(key, act))
        missing = list((ec - ac).elements())
        extra = list((ac - ec).elements())
        print(f"=== {case_id}  status exp={truth[case_id]['deletion_status']} "
              f"got={pred.get(case_id, {}).get('deletion_status')} "
              f"n_exp={len(exp)} n_got={len(act)}")
        for k in missing:
            print("  MISSING " + fmt(next(s for s in exp if key(s) == k)))
        for k in extra:
            print("  EXTRA   " + fmt(next(s for s in act if key(s) == k)))
        if not missing and not extra:
            # same set, different order
            print("  ORDER MISMATCH")
            for i, (e, a) in enumerate(zip(exp, act)):
                if key(e) != key(a):
                    print(f"    pos {i}: exp {fmt(e)}")
                    print(f"          got {fmt(a)}")
        print()


if __name__ == "__main__":
    main()
