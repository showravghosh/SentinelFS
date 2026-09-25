#!/usr/bin/env python3
"""Phase 4, experiment 2: can the candidate BPF LSM hooks faithfully implement the
frozen v1 event alphabet?

Experiment 1 showed that a BPF LSM program can prevent an operation. It used
lsm/file_open, which denies opening a file with write intent - which is not what the
specification calls WRITE(path). This experiment determines, per event type, which
hook means what the specification says, and reports any hook that does not.

The decisive measurements are the negative cases. A hook that fires when a file is
opened for writing and then closed without a write does not implement WRITE.

Observe-only: the probe returns every incoming verdict unchanged and cannot deny
anything. Enforcement per hook is a later question, once the semantics are known.

Must be run as root.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
PHASE4 = HERE.parent
OUT = PHASE4 / "out"
WORKDIR = pathlib.Path("/tmp/sentinel-p4")
TRUTH_FILE = pathlib.Path("/tmp/sentinel-p4-truth.json")

# What the specification says each event means, for comparison against what each
# hook actually does.
SPEC_MEANING = {
    "EXEC": "a program is executed; the argument names the executable",
    "OPEN": "a file is opened; the argument names the file",
    "WRITE": "a file is written; the argument names the file",
    "DELETE": "a file is deleted; the argument names the file",
}


def read_observed(path: pathlib.Path) -> tuple[list[dict], dict, list[dict]]:
    events, counters, failures = [], {}, []
    if not path.exists():
        return events, counters, failures
    for line in path.read_text(errors="replace").splitlines():
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = rec.get("rec")
        if kind == "event":
            events.append(rec)
        elif kind == "counters":
            counters[rec["map"]] = rec["values"]
        elif kind == "attach_failed":
            failures.append(rec)
    return events, counters, failures


def case_windows(truth: dict) -> dict[str, tuple[int, int]]:
    """Time bounds for each case, so observed records attribute unambiguously."""
    windows = {}
    for op in truth["operations"]:
        if op["op"] == "_case_bounds":
            windows[op["case"]] = (op["case_start_ns"], op["case_end_ns"])
    return windows


def events_in(events: list[dict], window: tuple[int, int], hook: str | None = None,
              pids: set[int] | None = None) -> list[dict]:
    lo, hi = window
    out = []
    for e in events:
        if not (lo <= e["ts_ns"] <= hi):
            continue
        if hook and e["hook"] != hook:
            continue
        if pids and e["tgid"] not in pids and e["pid"] not in pids:
            continue
        out.append(e)
    return out


MAY_WRITE = 0x2
MAY_READ = 0x4
FMODE_WRITE = 0x2


def main() -> int:
    if os.geteuid() != 0:
        print("error: must be run as root", file=sys.stderr)
        return 2

    obj = OUT / "mapping.bpf.o"
    collector = OUT / "collector"
    workload = HERE / "workload2.py"
    if not obj.exists() or not collector.exists():
        print(f"error: build first ({obj}, {collector})", file=sys.stderr)
        return 2

    run_as = os.environ.get("SUDO_USER") or "nobody"

    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)
    WORKDIR.mkdir(parents=True)
    shutil.chown(WORKDIR, run_as)

    observed_path = OUT / "experiment2-observed.jsonl"
    collector_log = OUT / "experiment2-collector.log"

    print("=" * 70)
    print(" Phase 4, experiment 2: hook / event-alphabet correspondence")
    print("=" * 70)
    print()
    print(" observe-only: the probe cannot deny anything")
    print(f" workload user: {run_as}")
    print()

    print("[1/4] attaching mapping probe...")
    with observed_path.open("w") as fout, collector_log.open("w") as ferr:
        proc = subprocess.Popen([str(collector), str(obj)], stdout=fout, stderr=ferr)

        ready = False
        deadline = time.time() + 20
        while time.time() < deadline and proc.poll() is None:
            if observed_path.exists() and '"rec":"ready"' in observed_path.read_text(
                    errors="replace"):
                ready = True
                break
            time.sleep(0.1)

        if not ready:
            proc.kill()
            print("      FAILED TO ATTACH")
            print(collector_log.read_text()[:2000])
            return 1

        attached = collector_log.read_text().count("attached")
        print(f"      attached ({attached} hooks)")

        print("[2/4] running workload...")
        r = subprocess.run(
            ["runuser", "-u", run_as, "--", sys.executable, str(workload), str(TRUTH_FILE)],
            capture_output=True, text=True,
        )
        for line in r.stdout.splitlines():
            print(f"      {line}")
        if r.returncode != 0:
            print(f"      workload failed: {r.stderr[:500]}")

        print("[3/4] detaching...")
        time.sleep(1)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

    events, counters, attach_failures = read_observed(observed_path)
    truth = json.loads(TRUTH_FILE.read_text()) if TRUTH_FILE.exists() else None
    if truth is None:
        print("      no ground truth produced")
        return 1

    print(f"      {len(events)} records captured")
    print()

    print("[4/4] analysis")
    print()

    windows = case_windows(truth)
    pids = {truth["runner_pid"]}
    findings: dict = {
        "attach_failures": attach_failures,
        "hook_calls": counters.get("hook_calls", {}),
        "hook_unresolved": counters.get("hook_unresolved", {}),
        "cases": {},
    }

    def summarise(case: str) -> dict:
        if case not in windows:
            return {}
        win = windows[case]
        got = events_in(events, win)
        by_hook: dict[str, list[dict]] = {}
        for e in got:
            by_hook.setdefault(e["hook"], []).append(e)
        return {
            hook: {
                "count": len(recs),
                "paths": sorted({r["path"] for r in recs}),
                "masks": sorted({r["mask"] for r in recs}),
            }
            for hook, recs in by_hook.items()
        }

    for case, _ in [(c["case"], None) for c in truth["operations"]
                    if c["op"] == "_case_bounds"]:
        findings["cases"][case] = summarise(case)

    # --- the decisive WRITE question --------------------------------------------
    print("  WRITE semantics: does the hook mean 'wrote' or 'opened for writing'?")
    print()

    a = findings["cases"].get("A_open_write_close", {})
    b = findings["cases"].get("B_open_close_no_write", {})
    d = findings["cases"].get("D_multiple_writes", {})
    c = findings["cases"].get("C_read_only", {})

    def write_ops(case_data: dict, hook: str) -> int:
        """file_permission records carrying MAY_WRITE; file_open records opened for write."""
        h = case_data.get(hook)
        if not h:
            return 0
        if hook == "file_permission":
            return sum(1 for m in h["masks"] if m & MAY_WRITE)
        if hook == "file_open":
            return sum(1 for m in h["masks"] if m & FMODE_WRITE)
        return h["count"]

    table_rows = []
    for hook in ("file_open", "file_permission"):
        row = {
            "hook": hook,
            "A_wrote": (a.get(hook) or {}).get("count", 0),
            "B_no_write": (b.get(hook) or {}).get("count", 0),
            "C_readonly": (c.get(hook) or {}).get("count", 0),
            "D_three_writes": (d.get(hook) or {}).get("count", 0),
        }
        table_rows.append(row)

    print(f"    {'hook':<18} {'A: wrote':>10} {'B: no write':>13} "
          f"{'C: read-only':>14} {'D: 3 writes':>13}")
    for row in table_rows:
        print(f"    {row['hook']:<18} {row['A_wrote']:>10} {row['B_no_write']:>13} "
              f"{row['C_readonly']:>14} {row['D_three_writes']:>13}")
    print()
    print("    Under the frozen semantics WRITE(p) means the file was written, so a")
    print("    faithful hook must show: B = 0 (opened, never written) and D > A")
    print("    (three writes produce more events than one).")
    print()

    verdicts = {}
    for row in table_rows:
        hook = row["hook"]
        fires_without_write = row["B_no_write"] > 0
        scales_with_writes = row["D_three_writes"] > row["A_wrote"]
        if not fires_without_write and scales_with_writes:
            verdict = "faithful to WRITE"
        elif fires_without_write:
            verdict = "NOT WRITE: fires without a write occurring"
        else:
            verdict = "inconclusive: does not scale with write count"
        verdicts[hook] = verdict
        print(f"    {hook:<18} -> {verdict}")
    findings["write_verdicts"] = verdicts
    print()

    # --- DELETE ------------------------------------------------------------------
    print("  DELETE: which hook fires, and for which destructive operations?")
    print()
    delete_cases = ["I_unlink", "J_rename_over", "K_rmdir", "L_hardlink"]
    delete_hooks = ["path_unlink", "inode_unlink"]
    print(f"    {'case':<16} " + " ".join(f"{h:>14}" for h in delete_hooks))
    for case in delete_cases:
        data = findings["cases"].get(case, {})
        cells = [str((data.get(h) or {}).get("count", 0)) for h in delete_hooks]
        print(f"    {case:<16} " + " ".join(f"{v:>14}" for v in cells))
    print()

    # --- EXEC --------------------------------------------------------------------
    print("  EXEC: which hook names the executable?")
    print()
    for case in ("M_exec", "N_exec_script"):
        data = findings["cases"].get(case, {})
        print(f"    {case}:")
        for hook in ("bprm_check_security", "bprm_creds_for_exec"):
            h = data.get(hook)
            if h:
                print(f"      {hook:<22} {h['count']} record(s): {h['paths']}")
            else:
                print(f"      {hook:<22} no records")
    print()

    # --- non-file writes and A1b ---------------------------------------------------
    g = findings["cases"].get("G_non_file_write", {})
    print("  Non-file writes (pipe, socket): must not appear as WRITE(p) for any p")
    if g:
        print(f"    records within the case window: {g}")
    else:
        print("    no records - consistent with A1b")
    print()

    print("  Per-hook call counters (including calls whose object could not be named):")
    for hook, n in sorted(findings["hook_calls"].items()):
        unresolved = findings["hook_unresolved"].get(hook, 0)
        print(f"    {hook:<22} calls={n:<10} unresolved={unresolved}")
    print()

    if attach_failures:
        print("  Hooks that could not be attached:")
        for f in attach_failures:
            print(f"    {f['program']}: {f['error']}")
        print()

    findings["spec_meaning"] = SPEC_MEANING
    (OUT / "experiment2.json").write_text(json.dumps(
        {"truth": truth, "findings": findings}, indent=2) + "\n")

    print("=" * 70)
    print(f" raw records : {observed_path}")
    print(f" analysis    : {OUT / 'experiment2.json'}")
    print("=" * 70)
    print()
    print(" These are measurements. Whether a hook is an acceptable implementation")
    print(" of an event is a judgement for the findings report, and a hook that does")
    print(" not mean what the specification says is a result, not a problem to be")
    print(" worked around.")

    shutil.rmtree(WORKDIR, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
