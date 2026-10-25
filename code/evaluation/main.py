#!/usr/bin/env python3
"""Score a prediction file against the public sample answers.

Metrics mirror what the grader can compute from its canonical rows:

* case accuracy            - deletion_status matches
* step-set F1              - (phase, system, resource, operation) tuples
* field accuracy           - state / evidence_id on matched steps
* sequence accuracy        - the full ordered step list matches exactly
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter
from typing import Dict, List, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "code"))


def load_predictions(path: str) -> Dict[str, dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return {row["case_id"]: row for row in csv.DictReader(fh)}


def parse_steps(row: str) -> List[dict]:
    try:
        steps = json.loads(row or "[]")
    except json.JSONDecodeError:
        return []
    return steps if isinstance(steps, list) else []


def step_key(step: dict) -> Tuple[str, str, str, str]:
    return (
        step.get("phase", ""),
        step.get("system_id", ""),
        step.get("resource_id", ""),
        step.get("operation", ""),
    )


def compare(expected: dict, actual: dict) -> dict:
    exp_steps = parse_steps(expected.get("steps_json", ""))
    act_steps = parse_steps(actual.get("steps_json", ""))
    exp_keys = [step_key(s) for s in exp_steps]
    act_keys = [step_key(s) for s in act_steps]
    exp_counter, act_counter = Counter(exp_keys), Counter(act_keys)
    overlap = sum((exp_counter & act_counter).values())
    precision = overlap / len(act_keys) if act_keys else (1.0 if not exp_keys else 0.0)
    recall = overlap / len(exp_keys) if exp_keys else (1.0 if not act_keys else 0.0)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    matched = 0
    field_hits = 0
    for key, count in (exp_counter & act_counter).items():
        exp_matches = [s for s in exp_steps if step_key(s) == key]
        act_matches = [s for s in act_steps if step_key(s) == key]
        for exp, act in zip(exp_matches, act_matches):
            matched += 1
            if exp.get("state") == act.get("state"):
                field_hits += 1
            if (exp.get("evidence_id") or "") == (act.get("evidence_id") or ""):
                field_hits += 1

    return {
        "case_id": expected["case_id"],
        "status_expected": expected.get("deletion_status"),
        "status_actual": actual.get("deletion_status"),
        "status_ok": expected.get("deletion_status") == actual.get("deletion_status"),
        "step_f1": f1,
        "sequence_ok": exp_keys == act_keys,
        "state_evidence_acc": (field_hits / (2 * matched)) if matched else 0.0,
        "expected_n": len(exp_steps),
        "actual_n": len(act_steps),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pred", default=os.path.join(REPO_ROOT, "sample_prediction.csv"))
    parser.add_argument("--truth", default=os.path.join(REPO_ROOT, "dataset", "sample_output.csv"))
    args = parser.parse_args()

    truth = load_predictions(args.truth)
    pred = load_predictions(args.pred)

    results = []
    for case_id in sorted(truth):
        if case_id not in pred:
            results.append({"case_id": case_id, "status_ok": False, "step_f1": 0.0,
                            "sequence_ok": False, "state_evidence_acc": 0.0,
                            "status_expected": truth[case_id]["deletion_status"],
                            "status_actual": "MISSING", "expected_n": 0, "actual_n": 0})
            continue
        results.append(compare(truth[case_id], pred[case_id]))

    total = len(results)
    case_acc = sum(r["status_ok"] for r in results) / total
    avg_f1 = sum(r["step_f1"] for r in results) / total
    seq_acc = sum(r["sequence_ok"] for r in results) / total
    field_acc = sum(r["state_evidence_acc"] for r in results) / total

    print(f"cases            : {total}")
    print(f"status accuracy  : {case_acc:.3f}")
    print(f"step-set F1      : {avg_f1:.3f}")
    print(f"sequence accuracy: {seq_acc:.3f}")
    print(f"state/evidence   : {field_acc:.3f}")
    print()
    print(f"{'case':10s} {'status exp':18s} {'got':18s} {'f1':6s} {'seq':5s} {'n_exp':6s} {'n_got':6s}")
    for r in results:
        flag = "" if r["status_ok"] and r["sequence_ok"] else "  <--"
        print(f"{r['case_id']:10s} {r['status_expected']:18s} {r['status_actual']:18s} "
              f"{r['step_f1']:.2f}  {str(r['sequence_ok']):5s} {r['expected_n']:6d} {r['actual_n']:6d}{flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
