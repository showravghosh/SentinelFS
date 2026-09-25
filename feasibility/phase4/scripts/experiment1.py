#!/usr/bin/env python3
"""Phase 4, experiment 1: does a BPF LSM program actually prevent an operation?

Phase 2 established that the v1 alphabet can be observed using tracepoints, which
fire after the operation has already happened. Enforcement needs a hook that runs
before the operation and whose return value decides whether it proceeds.

This experiment asks the smallest version of that question. It does not involve a
policy, an automaton, or any SentinelFS decision logic: it attaches a program that
denies writes to one fixed path, and measures what happens.

The measurement that matters is not the errno. It is whether the file changed. A
hook that returns -EPERM while the write still lands has enforced nothing, so the
file's contents are hashed before and after.

Must be run as root: attaching an LSM program requires it.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
PHASE4 = HERE.parent
OUT = PHASE4 / "out"
TARGET = pathlib.Path("/tmp/sentinel-test")
CONTROL = pathlib.Path("/tmp/sentinel-control")

ORIGINAL = b"original contents, must not change\n"
ATTEMPTED = b"MODIFIED BY TEST - enforcement failed if you can read this\n"


def digest(path: pathlib.Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def attempt_write(path: pathlib.Path, data: bytes) -> dict:
    """Attempt to open for writing and write. Records what the kernel returned."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
    except OSError as e:
        return {
            "open_succeeded": False,
            "errno": e.errno,
            "errno_name": os.strerror(e.errno),
            "bytes_written": 0,
        }
    try:
        written = os.write(fd, data)
        return {
            "open_succeeded": True,
            "errno": 0,
            "errno_name": "OK",
            "bytes_written": written,
        }
    except OSError as e:
        return {
            "open_succeeded": True,
            "errno": e.errno,
            "errno_name": os.strerror(e.errno),
            "bytes_written": 0,
        }
    finally:
        os.close(fd)


def attempt_read(path: pathlib.Path) -> dict:
    """Reads must keep working. A probe that denies reads as well has over-reached."""
    try:
        with open(path, "rb") as f:
            f.read()
        return {"read_succeeded": True, "errno": 0}
    except OSError as e:
        return {"read_succeeded": False, "errno": e.errno, "errno_name": os.strerror(e.errno)}


def run_phase(label: str) -> dict:
    """Exercise the target and a control file, recording effects."""
    before_target = digest(TARGET)
    before_control = digest(CONTROL)

    result = {
        "phase": label,
        "target": {
            "path": str(TARGET),
            "digest_before": before_target,
            "write": attempt_write(TARGET, ATTEMPTED),
            "read": attempt_read(TARGET),
        },
        "control": {
            "path": str(CONTROL),
            "digest_before": before_control,
            "write": attempt_write(CONTROL, ATTEMPTED),
        },
    }

    result["target"]["digest_after"] = digest(TARGET)
    result["control"]["digest_after"] = digest(CONTROL)
    result["target"]["contents_changed"] = (
        result["target"]["digest_before"] != result["target"]["digest_after"]
    )
    result["control"]["contents_changed"] = (
        result["control"]["digest_before"] != result["control"]["digest_after"]
    )
    return result


def reset_files() -> None:
    for p in (TARGET, CONTROL):
        p.write_bytes(ORIGINAL)
        os.chmod(p, 0o644)


def main() -> int:
    if os.geteuid() != 0:
        print("error: must be run as root (attaching an LSM program requires it)",
              file=sys.stderr)
        return 2

    obj = OUT / "minimal_deny.bpf.o"
    loader = OUT / "loader"
    if not obj.exists() or not loader.exists():
        print(f"error: build first ({obj}, {loader} missing)", file=sys.stderr)
        return 2

    OUT.mkdir(parents=True, exist_ok=True)

    print("=" * 66)
    print(" Phase 4, experiment 1: minimal enforcement proof")
    print("=" * 66)
    print()
    print(f" target file : {TARGET}   (probe denies writes to this)")
    print(f" control file: {CONTROL}  (probe must not affect this)")
    print()

    record: dict = {
        "experiment": "minimal enforcement proof",
        "question": "can a BPF LSM program prevent an operation, not merely observe it",
        "kernel": subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip(),
        "phases": [],
    }

    # --- baseline: no probe attached ------------------------------------------
    reset_files()
    print("[1/3] baseline, no probe attached")
    baseline = run_phase("baseline")
    record["phases"].append(baseline)
    print(f"      target write: errno={baseline['target']['write']['errno_name']}, "
          f"contents changed={baseline['target']['contents_changed']}")
    print()

    # --- probe attached --------------------------------------------------------
    reset_files()
    print("[2/3] attaching probe...")
    proc = subprocess.Popen(
        [str(loader), str(obj)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )

    ready = False
    deadline = time.time() + 15
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        line = proc.stdout.readline()
        if line.strip() == "READY":
            ready = True
            break

    if not ready:
        err = proc.stderr.read() if proc.stderr else ""
        print("      PROBE FAILED TO ATTACH")
        print(f"      {err.strip()}")
        record["attach_failed"] = True
        record["attach_error"] = err.strip()
        (OUT / "experiment1.json").write_text(json.dumps(record, indent=2))
        return 1

    print("      attached")
    enforced = run_phase("probe_attached")
    record["phases"].append(enforced)
    print(f"      target write : errno={enforced['target']['write']['errno_name']}, "
          f"contents changed={enforced['target']['contents_changed']}")
    print(f"      target read  : succeeded={enforced['target']['read']['read_succeeded']}")
    print(f"      control write: errno={enforced['control']['write']['errno_name']}, "
          f"contents changed={enforced['control']['contents_changed']}")

    proc.send_signal(signal.SIGINT)
    try:
        stdout, _ = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout = ""
    for line in stdout.splitlines():
        if line.startswith("{"):
            record["probe_stats"] = json.loads(line).get("stats", {})
    print()

    # --- detached: enforcement must stop ---------------------------------------
    reset_files()
    print("[3/3] probe detached, verifying enforcement stopped")
    after = run_phase("probe_detached")
    record["phases"].append(after)
    print(f"      target write: errno={after['target']['write']['errno_name']}, "
          f"contents changed={after['target']['contents_changed']}")
    print()

    # --- assessment -------------------------------------------------------------
    checks = {
        "baseline_write_succeeded": (
            not baseline["target"]["write"]["errno"] and baseline["target"]["contents_changed"]
        ),
        "attached_write_refused": enforced["target"]["write"]["errno"] != 0,
        "attached_file_unchanged": not enforced["target"]["contents_changed"],
        "attached_read_still_allowed": enforced["target"]["read"]["read_succeeded"],
        "control_file_unaffected": enforced["control"]["contents_changed"],
        "detached_write_succeeded": after["target"]["contents_changed"],
    }
    record["checks"] = checks
    record["enforcement_demonstrated"] = (
        checks["attached_write_refused"] and checks["attached_file_unchanged"]
    )

    print("=" * 66)
    for name, ok in checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print("=" * 66)
    if record["enforcement_demonstrated"]:
        print(" ENFORCEMENT DEMONSTRATED: the operation was refused and did not occur.")
    else:
        print(" ENFORCEMENT NOT DEMONSTRATED. See the per-check results above.")
    print("=" * 66)

    if record.get("probe_stats"):
        print()
        print(" probe counters:", record["probe_stats"])

    (OUT / "experiment1.json").write_text(json.dumps(record, indent=2) + "\n")
    print()
    print(f" raw record: {OUT / 'experiment1.json'}")

    for p in (TARGET, CONTROL):
        p.unlink(missing_ok=True)

    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
