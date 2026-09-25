#!/usr/bin/env python3
"""Ground-truth workload for the Phase 2 event-observation feasibility study.

Performs a precisely known sequence of security-relevant operations and writes a
record of exactly what it did, so the events reported by the kernel probe can be
compared against reality rather than against expectation.

Every operation is recorded with the monotonic timestamp taken immediately after
the syscall returns, so observed ordering can be checked against actual ordering.

The record is kept at SYSCALL granularity, not at the level of what the workload
"meant" to do. Writing to a path entails an openat as well as a write, and the
probe observes both; a ground truth recording only the write would disagree with
the kernel and produce spurious ordering violations.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

TRUTH: list[dict] = []


def record(event_type: str, arg: str, pid: int | None = None) -> None:
    TRUTH.append(
        {
            "type": event_type,
            "arg": arg,
            "pid": pid if pid is not None else os.getpid(),
            "ts_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC),
            "seq": len(TRUTH),
        }
    )


def do_exec(path: str, args: list[str]) -> int:
    """Run a binary in a child process. Produces one SPAWN (fork) and one EXEC."""
    proc = subprocess.Popen([path, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    record("SPAWN", path, pid=proc.pid)
    record("EXEC", path, pid=proc.pid)
    proc.wait()
    return proc.pid


def do_open(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    record("OPEN", path)
    os.close(fd)


def do_write(path: str, data: bytes = b"sentinelfs-groundtruth\n") -> None:
    """Write to a path.

    At the syscall level this is openat + write, so BOTH events are recorded. The
    ground truth must describe the syscalls actually issued, not the programmer's
    intent: a kernel probe observes the open regardless of why it happened, and
    omitting it makes the recorded trace disagree with reality.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    record("OPEN", path)
    os.write(fd, data)
    record("WRITE", path)
    os.close(fd)


def scenario_attack_chain(workdir: str) -> None:
    """The canonical protect_shadow pattern, against a decoy file.

    EXEC(python3) -> SPAWN(bash) -> WRITE(shadow-decoy)
    Uses a decoy path so the real /etc/shadow is never touched.
    """
    decoy = os.path.join(workdir, "shadow-decoy")
    do_exec("/usr/bin/python3", ["-c", "pass"])
    do_exec("/bin/bash", ["-c", "true"])
    do_write(decoy)


def scenario_interleaved(workdir: str) -> None:
    """The same chain with unrelated events interleaved between the pattern events."""
    decoy = os.path.join(workdir, "shadow-decoy")
    noise = os.path.join(workdir, "noise.txt")

    do_exec("/usr/bin/python3", ["-c", "pass"])
    do_write(noise)
    do_open(noise)
    do_exec("/bin/bash", ["-c", "true"])
    do_open(noise)
    do_write(decoy)


def scenario_volume(workdir: str, count: int) -> None:
    """Emit a known, countable number of events to measure delivery loss.

    A single fd is reused so the measurement isolates write delivery rather than
    open/close overhead.
    """
    target = os.path.join(workdir, "volume.txt")
    for _ in range(count):
        do_write(target)


def scenario_ordering(workdir: str, rounds: int) -> None:
    """Strictly alternating OPEN/WRITE pairs, to check order preservation.

    Each round uses a distinct path so that every observed event is uniquely
    attributable to one ground-truth operation. Reusing a single path makes
    matching ambiguous against the interpreter's own file activity.
    """
    for i in range(rounds):
        target = os.path.join(workdir, f"ordering-{i:04d}.txt")
        do_write(target)   # creates the file
        do_open(target)
        do_write(target)


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelFS ground-truth event workload")
    parser.add_argument(
        "scenario", choices=["attack_chain", "interleaved", "volume", "ordering"]
    )
    parser.add_argument("--workdir", default="/tmp/sentinelfs-gt")
    parser.add_argument("--count", type=int, default=1000, help="events for volume scenario")
    parser.add_argument("--rounds", type=int, default=50, help="rounds for ordering scenario")
    parser.add_argument("--out", default=None, help="where to write the ground-truth JSON")
    parser.add_argument("--settle", type=float, default=0.5, help="quiet period before starting")
    args = parser.parse_args()

    os.makedirs(args.workdir, exist_ok=True)

    # Quiet period so the probe can distinguish our events from startup noise.
    time.sleep(args.settle)

    start_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)

    if args.scenario == "attack_chain":
        scenario_attack_chain(args.workdir)
    elif args.scenario == "interleaved":
        scenario_interleaved(args.workdir)
    elif args.scenario == "volume":
        scenario_volume(args.workdir, args.count)
    elif args.scenario == "ordering":
        scenario_ordering(args.workdir, args.rounds)

    end_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    time.sleep(args.settle)

    manifest = {
        "scenario": args.scenario,
        "runner_pid": os.getpid(),
        "start_ns": start_ns,
        "end_ns": end_ns,
        "duration_s": (end_ns - start_ns) / 1e9,
        "event_count": len(TRUTH),
        "events": TRUTH,
    }

    out_path = args.out or os.path.join(args.workdir, f"truth-{args.scenario}.json")
    with open(out_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"scenario:    {args.scenario}")
    print(f"runner pid:  {os.getpid()}")
    print(f"events done: {len(TRUTH)}")
    print(f"duration:    {manifest['duration_s']:.3f} s")
    if manifest["duration_s"] > 0:
        print(f"rate:        {len(TRUTH) / manifest['duration_s']:.0f} events/s")
    print(f"truth file:  {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
