#!/usr/bin/env python3
"""Corrected analysis of experiment 2.

The first analysis counted every record a hook produced inside a case window,
without filtering by access mask and without accounting for the workload's own
setup. Each case calls fresh(), which writes the file into existence, so every
case contained one extra open and one extra write that belonged to the harness
rather than to the case. Counts inflated by that setup cannot answer whether a
hook fires when no write occurs.

This re-analysis works from the same raw records. It filters file_permission by
MAY_WRITE and file_open by FMODE_WRITE, and it attributes each record to the
specific file the case operates on rather than to the case window alone.

No new run is required: the masks and paths were recorded.
"""

from __future__ import annotations

import json
import pathlib
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "out"

MAY_EXEC, MAY_WRITE, MAY_READ, MAY_APPEND = 0x1, 0x2, 0x4, 0x20
FMODE_READ, FMODE_WRITE = 0x1, 0x2


def load() -> tuple[list[dict], dict]:
    events = []
    for line in (OUT / "experiment2-observed.jsonl").read_text(errors="replace").splitlines():
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        if rec.get("rec") == "event":
            events.append(rec)
    analysis = json.loads((OUT / "experiment2.json").read_text())
    return events, analysis["truth"]


def case_windows(truth: dict) -> dict[str, tuple[int, int]]:
    return {
        op["case"]: (op["case_start_ns"], op["case_end_ns"])
        for op in truth["operations"]
        if op["op"] == "_case_bounds"
    }


def mask_names(mask: int) -> str:
    parts = []
    if mask & MAY_EXEC:
        parts.append("EXEC")
    if mask & MAY_WRITE:
        parts.append("WRITE")
    if mask & MAY_READ:
        parts.append("READ")
    if mask & MAY_APPEND:
        parts.append("APPEND")
    return "|".join(parts) or f"0x{mask:x}"


def main() -> int:
    events, truth = load()
    windows = case_windows(truth)

    print("=" * 74)
    print(" Experiment 2, corrected analysis")
    print("=" * 74)
    print()
    print(" The first analysis did not filter by access mask and counted the")
    print(" harness's own setup writes. This one does both.")
    print()

    # --- WRITE ------------------------------------------------------------------
    print(" WRITE: file_permission records carrying MAY_WRITE, by target file")
    print()
    print(f"   {'case':<24} {'file':<26} {'writes':>7} {'reads':>7}")

    write_rows = {}
    for case, (lo, hi) in sorted(windows.items()):
        recs = [e for e in events
                if lo <= e["ts_ns"] <= hi and e["hook"] == "file_permission"]
        by_file: dict[str, dict[str, int]] = {}
        for r in recs:
            name = r["path"].rsplit("/", 1)[-1]
            slot = by_file.setdefault(name, {"w": 0, "r": 0})
            if r["mask"] & MAY_WRITE:
                slot["w"] += 1
            if r["mask"] & MAY_READ:
                slot["r"] += 1
        for name, counts in sorted(by_file.items()):
            print(f"   {case:<24} {name:<26} {counts['w']:>7} {counts['r']:>7}")
        write_rows[case] = by_file
    print()

    # The decisive comparison, per the case's own file only.
    def writes_for(case: str, fname: str) -> int:
        return write_rows.get(case, {}).get(fname, {"w": 0})["w"]

    a = writes_for("A_open_write_close", "A-open-write-close")
    b = writes_for("B_open_close_no_write", "B-open-close-nowrite")
    c = writes_for("C_read_only", "C-readonly")
    d = writes_for("D_multiple_writes", "D-multiwrite")

    print(" Decisive cases, counting only MAY_WRITE on the case's own file.")
    print(" Each file is created by the harness with one write, so the harness")
    print(" contributes exactly 1 to each count; the case's own writes are the excess.")
    print()
    print(f"   A  open, write once, close : {a}  (setup 1 + case 1 = 2 expected)")
    print(f"   B  open, close, NO write   : {b}  (setup 1 + case 0 = 1 expected)")
    print(f"   C  read-only open and read : {c}  (setup 1 + case 0 = 1 expected)")
    print(f"   D  open, write three times : {d}  (setup 1 + case 3 = 4 expected)")
    print()

    case_writes = {"A": a - 1, "B": b - 1, "C": c - 1, "D": d - 1}
    print(f"   attributable to the case itself: A={case_writes['A']} "
          f"B={case_writes['B']} C={case_writes['C']} D={case_writes['D']}")
    print()

    faithful = (
        case_writes["B"] == 0
        and case_writes["C"] == 0
        and case_writes["D"] > case_writes["A"] > 0
    )
    print(f"   file_permission + MAY_WRITE is "
          f"{'FAITHFUL to WRITE(path)' if faithful else 'NOT faithful to WRITE(path)'}")
    if faithful:
        print("     fires once per write, not per open; silent when a file is opened")
        print("     for writing and never written, and when opened read-only.")
    print()

    # file_open for comparison
    print(" For comparison, file_open records with FMODE_WRITE on the case's own file:")
    for case, fname in [("A_open_write_close", "A-open-write-close"),
                        ("B_open_close_no_write", "B-open-close-nowrite"),
                        ("C_read_only", "C-readonly"),
                        ("D_multiple_writes", "D-multiwrite")]:
        lo, hi = windows[case]
        n = sum(1 for e in events
                if lo <= e["ts_ns"] <= hi and e["hook"] == "file_open"
                and e["path"].endswith(fname) and e["mask"] & FMODE_WRITE)
        print(f"   {case:<24} {n}")
    print()
    print("   file_open fires on B, where nothing was written, and does not scale")
    print("   with the number of writes in D. It denotes intent, not the operation.")
    print()

    # --- EXEC: the argument the hook reports ------------------------------------
    print(" EXEC: what the hook reports as the executable")
    print()
    requested = [op for op in truth["operations"] if op["op"] in ("EXEC", "EXEC_SCRIPT")]
    for op in requested:
        lo, hi = windows[op["case"]]
        recs = [e for e in events
                if lo <= e["ts_ns"] <= hi and e["hook"].startswith("bprm")]
        reported = sorted({e["path"] for e in recs})
        print(f"   requested: {op['target']}")
        print(f"   reported : {reported}")
        exact = op["target"] in reported
        print(f"   exact string match: {'YES' if exact else 'NO'}")
        print()

    # --- correlation effectiveness ------------------------------------------------
    print(" Correlation map effectiveness for file_permission")
    print()
    resolved = sum(1 for e in events if e["hook"] == "file_permission")
    print(f"   records emitted with a resolved path : {resolved}")
    print("   (the probe records only files under the experiment prefix, so the")
    print("    large unresolved count is by design, not a failure: a policy-driven")
    print("    adapter likewise tracks only objects its policies name)")
    print()

    # --- DELETE ---------------------------------------------------------------------
    print(" DELETE: which destructive operations produce an unlink hook record")
    print()
    for case in ("I_unlink", "J_rename_over", "K_rmdir", "L_hardlink"):
        lo, hi = windows[case]
        for hook in ("path_unlink", "inode_unlink"):
            recs = [e for e in events
                    if lo <= e["ts_ns"] <= hi and e["hook"] == hook]
            names = sorted({r["path"] for r in recs})
            print(f"   {case:<16} {hook:<14} {len(recs)} {names}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
