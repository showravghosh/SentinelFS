#!/usr/bin/env python3
"""Phase 4B: event identity and coverage.

Two questions, both left open by Phase 4:

  EXEC   - can the enforcement hook recover the pathname passed to the exec
           syscall, which is what the frozen semantics appear to name, rather
           than only the resolved object path?

  DELETE - which mechanisms for destroying an object produce an event, and
           which destroy an object silently?

The analysis compares, per case, the exact string the workload passed to the
syscall against every notion of the object the hook exposed. It does not decide
which notion is correct; it reports whether the one the specification names is
available at all.

Observe-only. Must be run as root.
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
WORKDIR = pathlib.Path("/tmp/sentinel-p4b")
TRUTH_FILE = pathlib.Path("/tmp/sentinel-p4b-truth.json")

# interp_flags bit indicating the kernel is running an interpreter for a script.
BINPRM_FLAGS_ENFORCE_NONDUMP = 0x1


def load_records(path: pathlib.Path) -> tuple[list[dict], dict, list[dict]]:
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
            counters = rec["values"]
        elif kind == "attach_failed":
            failures.append(rec)
    return events, counters, failures


def main() -> int:
    if os.geteuid() != 0:
        print("error: must be run as root", file=sys.stderr)
        return 2

    obj = OUT / "identity.bpf.o"
    collector = OUT / "collector_b"
    workload = HERE / "workload_b.py"
    if not obj.exists() or not collector.exists():
        print(f"error: build first ({obj}, {collector})", file=sys.stderr)
        return 2

    run_as = os.environ.get("SUDO_USER") or "nobody"
    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)
    WORKDIR.mkdir(parents=True)
    shutil.chown(WORKDIR, run_as)

    observed = OUT / "experiment3-observed.jsonl"
    clog = OUT / "experiment3-collector.log"

    print("=" * 74)
    print(" Phase 4B: event identity and coverage")
    print("=" * 74)
    print()
    print(" observe-only; the probe cannot deny anything")
    print()

    print("[1/3] attaching identity probe...")
    with observed.open("w") as fout, clog.open("w") as ferr:
        proc = subprocess.Popen([str(collector), str(obj)], stdout=fout, stderr=ferr)
        ready = False
        deadline = time.time() + 20
        while time.time() < deadline and proc.poll() is None:
            if observed.exists() and '"rec":"ready"' in observed.read_text(errors="replace"):
                ready = True
                break
            time.sleep(0.1)
        if not ready:
            proc.kill()
            print("      FAILED TO ATTACH")
            print(clog.read_text()[-3000:])
            return 1
        print(f"      attached ({clog.read_text().count('attached')} hooks)")

        print("[2/3] running workload...")
        r = subprocess.run(
            ["runuser", "-u", run_as, "--", sys.executable, str(workload), str(TRUTH_FILE)],
            capture_output=True, text=True)
        for line in r.stdout.splitlines():
            print(f"      {line}")
        if r.returncode != 0:
            print(f"      stderr: {r.stderr[:600]}")

        print("[3/3] detaching...")
        time.sleep(1)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

    events, counters, attach_failures = load_records(observed)
    if not TRUTH_FILE.exists():
        print("      no ground truth produced")
        return 1
    truth = json.loads(TRUTH_FILE.read_text())
    print(f"      {len(events)} records")
    print()

    windows = {op["case"]: (op["case_start_ns"], op["case_end_ns"])
               for op in truth["operations"] if op["op"] == "_case_bounds"}
    ops = {op["case"]: op for op in truth["operations"] if op["op"] != "_case_bounds"}

    def in_case(case: str, hook_prefix: str = "") -> list[dict]:
        if case not in windows:
            return []
        lo, hi = windows[case]
        return [e for e in events
                if lo <= e["ts_ns"] <= hi and e["hook"].startswith(hook_prefix)]

    # ---------------- EXEC identity --------------------------------------------
    print("=" * 74)
    print(" EXEC: is the pathname passed to the syscall recoverable at the hook?")
    print("=" * 74)
    print()

    exec_results = {}
    for case in ["E1_absolute", "E2_symlink", "E3_versioned", "E4_relative",
                 "E5_script", "E6_execveat"]:
        op = ops.get(case)
        if not op:
            continue
        recs = in_case(case, "bprm")
        passed = op["passed"]

        print(f" {case}")
        print(f"   passed to syscall : {passed!r}")
        if not recs:
            print("   hook records      : none")
            print()
            exec_results[case] = {"passed": passed, "records": [], "recoverable": False}
            continue

        for i, r in enumerate(recs):
            print(f"   record {i + 1}:")
            print(f"     bprm->filename  : {r['primary']!r}")
            print(f"     resolved d_path : {r['secondary']!r}")
            if r["interp"]:
                print(f"     bprm->interp    : {r['interp']!r}")
            print(f"     interp_flags    : {r['flags']}")

        recoverable = any(r["primary"] == passed for r in recs)
        resolved_matches = any(r["secondary"] == passed for r in recs)
        print(f"   filename matches what was passed : {'YES' if recoverable else 'NO'}")
        print(f"   resolved path matches what was passed : "
              f"{'YES' if resolved_matches else 'NO'}")
        print()
        exec_results[case] = {
            "passed": passed,
            "records": recs,
            "recoverable": recoverable,
            "resolved_matches": resolved_matches,
        }

    recoverable_all = [c for c, v in exec_results.items() if v.get("recoverable")]
    print(" Summary")
    print(f"   cases where bprm->filename equals the pathname passed: "
          f"{len(recoverable_all)}/{len(exec_results)}")
    for case, v in exec_results.items():
        mark = "yes" if v.get("recoverable") else "NO"
        print(f"     {case:<24} {mark}")
    print()

    # ---------------- DELETE coverage ---------------------------------------------
    print("=" * 74)
    print(" DELETE: which destruction mechanisms produce an event?")
    print("=" * 74)
    print()
    print(f" {'case':<26} {'destroys?':<11} {'hooks that fired'}")

    destroys = {
        "D1_unlink": "yes",
        "D2_unlinkat": "yes",
        "D3_rmdir": "yes (dir)",
        "D4_rename_over": "YES",
        "D5_rename_fresh": "no",
        "D6_renameat2_noreplace": "refused",
        "D7_renameat2_exchange": "no (swap)",
        "D8_hardlink_unlink": "no (name)",
        "D9_truncate": "contents",
    }

    delete_results = {}
    for case, destroy in destroys.items():
        recs = in_case(case)
        hooks = sorted({r["hook"] for r in recs})
        # Rename records carry whether the destination was occupied.
        extra = ""
        for r in recs:
            if r["hook"].endswith("rename"):
                extra = f"  [dest_exists={r['dest_exists']}, flags={r['flags']}]"
        print(f" {case:<26} {destroy:<11} {hooks if hooks else 'NONE'}{extra}")
        delete_results[case] = {"destroys": destroy, "hooks": hooks,
                                "records": recs}
    print()

    silent = [c for c, v in delete_results.items()
              if v["destroys"].lower().startswith("yes") and not v["hooks"]]
    if silent:
        print(f" Destruction with NO event: {silent}")
    else:
        print(" Every destructive mechanism produced at least one event.")
    print()

    # ---------------- OPEN identity ------------------------------------------------
    print("=" * 74)
    print(" OPEN: which name does file_open report?")
    print("=" * 74)
    print()
    op = ops.get("O1_open_symlink")
    if op:
        recs = in_case("O1_open_symlink", "file_open")
        print(f"   passed to syscall : {op['passed']!r}")
        for r in recs:
            print(f"   dentry name     : {r['primary']!r}")
            print(f"   resolved d_path : {r['secondary']!r}")
        print()

    print(" Hook call counters:")
    for hook, n in sorted(counters.items()):
        print(f"   {hook:<22} {n}")
    if attach_failures:
        print()
        print(" Hooks that would not attach:")
        for f in attach_failures:
            print(f"   {f['program']}: {f['error']}")
    print()

    (OUT / "experiment3.json").write_text(json.dumps({
        "truth": truth,
        "exec": {k: {kk: vv for kk, vv in v.items() if kk != "records"}
                 for k, v in exec_results.items()},
        "delete": {k: {kk: vv for kk, vv in v.items() if kk != "records"}
                   for k, v in delete_results.items()},
        "counters": counters,
        "attach_failures": attach_failures,
    }, indent=2) + "\n")

    print("=" * 74)
    print(f" raw      : {observed}")
    print(f" analysis : {OUT / 'experiment3.json'}")
    print("=" * 74)

    shutil.rmtree(WORKDIR, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
