#!/usr/bin/env python3
"""Diagnostics for two suspicious results in the Phase 2 run.

1. Is the enormous WRITE volume the probe observing its own output?
   Checks which processes (comm) produced the WRITE events.

2. Is the A2 ordering violation a real kernel-ordering problem, or an artefact of
   bpftrace's userspace output ordering? Checks whether the recorded timestamps
   are monotonic in file order, and whether sorting by timestamp recovers the
   true order.
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter

OUT = pathlib.Path(__file__).parent / "out"


def diagnose_write_source(scenario: str) -> None:
    path = OUT / f"observed-{scenario}.jsonl"
    if not path.exists():
        return

    comm_counts: Counter = Counter()
    pid_counts: Counter = Counter()
    total = 0

    with path.open(errors="replace") as fh:
        for line in fh:
            if '"type":"WRITE"' not in line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            comm_counts[rec.get("comm", "?")] += 1
            pid_counts[rec.get("pid", -1)] += 1

    print(f"  [{scenario}] WRITE events: {total:,}")
    print("      top producing processes (comm):")
    for comm, n in comm_counts.most_common(6):
        share = n / total * 100 if total else 0
        marker = "   <-- PROBE'S OWN OUTPUT" if comm in ("bpftrace", "tee", "run_feasibilit") else ""
        print(f"        {comm:<20} {n:>10,}  ({share:5.1f}%){marker}")
    print()


def diagnose_ordering(scenario: str) -> None:
    path = OUT / f"observed-{scenario}.jsonl"
    truth_path = OUT / f"truth-{scenario}.json"
    if not path.exists() or not truth_path.exists():
        return

    truth = json.loads(truth_path.read_text())
    pids = {truth["runner_pid"]} | {e["pid"] for e in truth["events"]}

    records = []
    with path.open(errors="replace") as fh:
        for lineno, line in enumerate(fh):
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("rec") != "event" or rec.get("pid") not in pids:
                continue
            rec["_line"] = lineno
            records.append(rec)

    if not records:
        print(f"  [{scenario}] no workload records")
        return

    ts = [r["ts_ns"] for r in records]
    file_order_inversions = sum(1 for a, b in zip(ts, ts[1:]) if b < a)

    by_ts = sorted(records, key=lambda r: r["ts_ns"])
    lines_after_sort = [r["_line"] for r in by_ts]
    line_inversions = sum(
        1 for a, b in zip(lines_after_sort, lines_after_sort[1:]) if b < a
    )

    # Does sorting by timestamp reproduce the ground-truth alternation?
    truth_types = [e["type"] for e in truth["events"]]
    sorted_types = [r["type"] for r in by_ts]

    print(f"  [{scenario}] workload records: {len(records)}")
    print(f"      timestamps monotonic in FILE order : "
          f"{'YES' if file_order_inversions == 0 else f'NO ({file_order_inversions} inversions)'}")
    print(f"      file lines out of order after SORT : {line_inversions}")
    print(f"      ground-truth type sequence (first 12): {truth_types[:12]}")
    print(f"      observed  type sequence (first 12)  : {sorted_types[:12]}")

    if file_order_inversions > 0 and line_inversions > 0:
        print("      => file order and timestamp order disagree: the output stream is")
        print("         not ordered, but timestamps may still permit reconstruction.")
    elif file_order_inversions == 0:
        print("      => file order already matches timestamp order.")
    print()


def main() -> int:
    print("=" * 64)
    print(" Phase 2 diagnostics: verifying two suspicious results")
    print("=" * 64)
    print()
    print("--- 1. Source of the WRITE volume (feedback loop check) ---")
    print()
    for s in ["attack_chain", "volume"]:
        diagnose_write_source(s)

    print("--- 2. Nature of the A2 ordering violation ---")
    print()
    for s in ["ordering", "interleaved"]:
        diagnose_ordering(s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
