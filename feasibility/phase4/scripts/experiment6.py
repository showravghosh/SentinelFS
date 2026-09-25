#!/usr/bin/env python3
"""Phase 5A-E3: correlation capacity and degradation.

A1b makes the WRITE correlation part of the enforcement path: without it there is
no pathname, and without a pathname there is no WRITE(p) event. Its capacity is
therefore a security property, not only a resource one.

The question is what happens when the correlation cannot be established, and in
particular whether any failure mode produces a WRONG pathname rather than no
pathname. A missing pathname is consistent with A1b. A wrong one would mean a
policy naming one file matching a write to another, which the specification does
not permit and which no amount of capacity would fix.

The probe stores the inode alongside the path at open and compares it against the
file's actual inode at write, so a stale entry is distinguished from a correct hit
and from a miss. Its map holds 64 entries, small enough to exhaust deliberately.

Four scenarios:

  T1  fill        open fewer files than capacity; all should correlate
  T2  overflow    open more files than capacity while holding them all open
  T3  reuse       repeated open/close cycles, to provoke struct file reuse
  T4  recovery    after closing everything, does capacity return?

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
BASE = pathlib.Path("/tmp/sentinel-p6")

CAPACITY = 64          # must match CORRELATION_CAPACITY in the probe
UNDER = 32             # T1: comfortably under
OVER = 160             # T2: well over
REUSE_CYCLES = 400     # T3

STAT_NAMES = [
    "open_seen", "insert_ok", "insert_fail", "write_seen",
    "lookup_hit_correct", "lookup_hit_stale", "lookup_miss",
    "free_seen", "delete_ok", "delete_miss",
]


def read_records(path: pathlib.Path) -> tuple[list[dict], dict]:
    stale, stats = [], {}
    if not path.exists():
        return stale, stats
    for line in path.read_text(errors="replace").splitlines():
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        if rec.get("rec") == "stale":
            stale.append(rec)
        elif rec.get("rec") == "stats":
            stats = rec["values"]
    return stale, stats


def snapshot(collector_out: pathlib.Path) -> dict:
    """Stats are emitted only at exit, so per-scenario deltas are derived from the
    workload's own accounting rather than from the probe."""
    return {}


def make_files(n: int, tag: str) -> list[pathlib.Path]:
    """Create files BEFORE the probe attaches, per methodology rule M4."""
    files = []
    for i in range(n):
        p = BASE / f"{tag}-{i:04d}"
        p.write_bytes(b"x")
        files.append(p)
    return files


WORKLOAD = r'''
import os, sys, json, pathlib
mode = sys.argv[1]
BASE = pathlib.Path("/tmp/sentinel-p6")
result = {"mode": mode}

if mode in ("t1", "t2"):
    tag, n = ("t1", int(sys.argv[2])) if mode == "t1" else ("t2", int(sys.argv[2]))
    fds = []
    for i in range(n):
        p = BASE / f"{tag}-{i:04d}"
        fds.append(os.open(p, os.O_RDWR))       # observed open -> correlation
    writes = 0
    for fd in fds:                               # all held open simultaneously
        os.write(fd, b"y"); writes += 1
    for fd in fds:
        os.close(fd)
    result.update(opens=n, writes=writes)

elif mode == "t3":
    cycles = int(sys.argv[2])
    p = BASE / "t3-target"
    q = BASE / "t3-other"
    writes = 0
    for i in range(cycles):
        # Open, write, close one file, then another: if a struct file address is
        # reused before its entry is deleted, a later write resolves to the
        # previous file's path.
        fd = os.open(p, os.O_RDWR); os.write(fd, b"a"); os.close(fd); writes += 1
        fd = os.open(q, os.O_RDWR); os.write(fd, b"b"); os.close(fd); writes += 1
    result.update(cycles=cycles, writes=writes)

elif mode == "t4":
    n = int(sys.argv[2])
    fds = [os.open(BASE / f"t4-{i:04d}", os.O_RDWR) for i in range(n)]
    for fd in fds:
        os.write(fd, b"z")
    for fd in fds:
        os.close(fd)
    result.update(opens=n, writes=n)

print(json.dumps(result))
'''


def main() -> int:
    if os.geteuid() != 0:
        print("error: must be run as root", file=sys.stderr)
        return 2

    obj = OUT / "correlation.bpf.o"
    collector = OUT / "collector_e"
    if not obj.exists() or not collector.exists():
        print(f"error: build first ({obj}, {collector})", file=sys.stderr)
        return 2

    run_as = os.environ.get("SUDO_USER") or "nobody"
    shutil.rmtree(BASE, ignore_errors=True)
    BASE.mkdir(parents=True)
    shutil.chown(BASE, run_as)

    # M4: every file is created before the probe attaches.
    for tag, n in (("t1", UNDER), ("t2", OVER), ("t4", UNDER)):
        for f in make_files(n, tag):
            shutil.chown(f, run_as)
    for name in ("t3-target", "t3-other"):
        f = BASE / name
        f.write_bytes(b"x")
        shutil.chown(f, run_as)

    script = OUT / "e3_workload.py"
    script.write_text(WORKLOAD)

    observed = OUT / "experiment6-observed.jsonl"
    clog = OUT / "experiment6-collector.log"

    print("=" * 76)
    print(" Phase 5A-E3: correlation capacity and degradation")
    print("=" * 76)
    print()
    print(f" map capacity: {CAPACITY} entries   observe-only")
    print()

    print("[1/3] attaching probe...")
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
            print(clog.read_text()[-2000:])
            shutil.rmtree(BASE, ignore_errors=True)
            return 1
        print("      attached")

        print("[2/3] running scenarios...")
        results = {}
        for mode, arg, desc in (
            ("t1", UNDER, f"{UNDER} files held open (under capacity {CAPACITY})"),
            ("t2", OVER, f"{OVER} files held open (over capacity {CAPACITY})"),
            ("t3", REUSE_CYCLES, f"{REUSE_CYCLES} open/close cycles (pointer reuse)"),
            ("t4", UNDER, f"{UNDER} files after release (recovery)"),
        ):
            print(f"      {mode}: {desc}")
            r = subprocess.run(
                ["runuser", "-u", run_as, "--", sys.executable, str(script), mode, str(arg)],
                capture_output=True, text=True)
            try:
                results[mode] = json.loads(r.stdout.strip().splitlines()[-1])
            except Exception:
                results[mode] = {"error": r.stderr[:300]}
            time.sleep(0.4)

        print("[3/3] detaching...")
        time.sleep(0.6)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

    stale, stats = read_records(observed)

    print()
    print("=" * 76)
    print(" Probe counters (whole run)")
    print("=" * 76)
    print()
    for name in STAT_NAMES:
        v = stats.get(name, 0)
        mark = ""
        if name == "lookup_hit_stale" and int(v) > 0:
            mark = "   <-- SOUNDNESS FAILURE"
        if name == "insert_fail" and int(v) > 0:
            mark = "   <-- capacity exceeded"
        print(f"   {name:<22} {v}{mark}")
    print()

    workload_opens = sum(r.get("opens", 0) for r in results.values())
    workload_opens += results.get("t3", {}).get("cycles", 0) * 2
    workload_writes = sum(r.get("writes", 0) for r in results.values())

    print("=" * 76)
    print(" Assessment")
    print("=" * 76)
    print()
    print(f"   workload opens  : {workload_opens}")
    print(f"   workload writes : {workload_writes}")
    print()

    stale_n = int(stats.get("lookup_hit_stale", 0))
    fail_n = int(stats.get("insert_fail", 0))
    miss_n = int(stats.get("lookup_miss", 0))
    correct_n = int(stats.get("lookup_hit_correct", 0))

    print(f"   correct resolutions : {correct_n}")
    print(f"   unresolved (miss)   : {miss_n}"
          "   <- consistent with A1b: not a WRITE(p) for any p")
    print(f"   insertion failures  : {fail_n}")
    print(f"   STALE resolutions   : {stale_n}")
    print()

    if stale_n == 0:
        print("   No write resolved to a pathname belonging to a different object.")
        print("   Under the tested scenarios, correlation failure degrades to an")
        print("   absent pathname rather than a wrong one, which is what A1b requires.")
    else:
        print("   A write resolved to a pathname belonging to a DIFFERENT object.")
        print("   This is a soundness failure: a policy naming one file would match a")
        print("   write to another. Examples:")
        for s in stale[:5]:
            print(f"     stored ino={s['stored_ino']} path={s['stored_path']!r} "
                  f"actual ino={s['actual_ino']}")
    print()

    if fail_n > 0:
        print(f"   Capacity was exceeded ({fail_n} insertions refused). Writes to those")
        print("   descriptors cannot yield a WRITE(p) event. An adversary able to")
        print("   exhaust the map can therefore suppress WRITE enforcement without")
        print("   triggering any policy - which is consistent with A1b and is exactly")
        print("   why A1b is load-bearing.")
    print()

    (OUT / "experiment6.json").write_text(json.dumps({
        "capacity": CAPACITY, "scenarios": results, "stats": stats,
        "stale_examples": stale[:20],
    }, indent=2) + "\n")
    print(f" raw      : {observed}")
    print(f" analysis : {OUT / 'experiment6.json'}")

    shutil.rmtree(BASE, ignore_errors=True)
    script.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
