#!/usr/bin/env python3
"""Phase 5A-E1: concurrent host-wide ordering.

The v1.1 semantics define one host-wide trace (§1.2). Assumption A2 asserts events
reach the evaluator in the order they occurred. Phase 2 tested A2 with a
single-process workload, which cannot distinguish order preservation from there
having been only one order.

Under concurrency the question is what the order IS. Three candidate orderings are
captured for every event and compared:

    seq        the order the kernel executed the hook, from an atomic counter
    ts_ns      the timestamp taken at the same point
    delivery   the position of the record in the collector's output

A kernel-resident automaton would apply transitions in `seq` order. A userspace
automaton reading the ring buffer would apply them in `delivery` order. If those
disagree, the two architectures do not implement the same semantics, and that is a
fact about Linux rather than a choice either of them gets to make.

Two workloads:

  W1  strict happens-before across CPUs. Two processes pinned to different CPUs
      alternate, synchronised through a pipe, so the true order is known by
      construction and can be checked against each candidate ordering.

  W2  unsynchronised contention. Several processes on all CPUs generate events as
      fast as they can, to measure loss and the extent of disagreement.

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
BASE = pathlib.Path("/tmp/sentinel-p5")

W1_ROUNDS = 300
W2_PER_PROC = 1500


# --- W1: strict happens-before across CPUs --------------------------------------

W1_CHILD = r'''
import os, sys
role, cpu, rounds, rfd, wfd = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
os.sched_setaffinity(0, {cpu})
target = f"/tmp/sentinel-p5/w1-{role}"   # created before the probe attached

for i in range(rounds):
    if role == "A":
        fd = os.open(target, os.O_RDONLY); os.close(fd)   # event A_i
        os.write(wfd, b"x")                                # release B
        os.read(rfd, 1)                                    # wait for B
    else:
        os.read(rfd, 1)                                    # wait for A
        fd = os.open(target, os.O_RDONLY); os.close(fd)   # event B_i
        os.write(wfd, b"x")                                # release A
'''


def run_w1(run_as: str) -> dict:
    """A_i strictly precedes B_i, which strictly precedes A_(i+1)."""
    a2b_r, a2b_w = os.pipe()
    b2a_r, b2a_w = os.pipe()

    script = OUT / "w1_child.py"
    script.write_text(W1_CHILD)

    procs = []
    for role, cpu, rfd, wfd in (("A", 0, b2a_r, a2b_w), ("B", 2, a2b_r, b2a_w)):
        p = subprocess.Popen(
            ["taskset", "-c", str(cpu), "runuser", "-u", run_as, "--",
             sys.executable, str(script), role, str(cpu), str(W1_ROUNDS),
             str(rfd), str(wfd)],
            pass_fds=(rfd, wfd),
        )
        procs.append(p)

    for p in procs:
        p.wait(timeout=120)
    for fd in (a2b_r, a2b_w, b2a_r, b2a_w):
        try:
            os.close(fd)
        except OSError:
            pass

    return {"rounds": W1_ROUNDS, "cpus": [0, 2]}


# --- W2: unsynchronised contention ------------------------------------------------

W2_CHILD = r'''
import os, sys
cpu, n = int(sys.argv[1]), int(sys.argv[2])
os.sched_setaffinity(0, {cpu})
target = f"/tmp/sentinel-p5/w2-cpu{cpu}"  # created before the probe attached
for _ in range(n):
    fd = os.open(target, os.O_RDONLY); os.close(fd)
'''


def run_w2(run_as: str, ncpu: int) -> dict:
    script = OUT / "w2_child.py"
    script.write_text(W2_CHILD)
    procs = [
        subprocess.Popen(["taskset", "-c", str(c), "runuser", "-u", run_as, "--",
                          sys.executable, str(script), str(c), str(W2_PER_PROC)])
        for c in range(ncpu)
    ]
    for p in procs:
        p.wait(timeout=120)
    return {"processes": ncpu, "per_process": W2_PER_PROC,
            "expected": ncpu * W2_PER_PROC}


# --- analysis --------------------------------------------------------------------

def analyse(events: list[dict], label: str, expected: int | None = None) -> dict:
    """Compare the three orderings on one workload's records."""
    if not events:
        print(f"  [{label}] no records")
        return {}

    by_delivery = events                      # already in output order
    by_seq = sorted(events, key=lambda e: e["seq"])
    by_ts = sorted(events, key=lambda e: e["ts_ns"])

    delivery_matches_seq = [e["seq"] for e in by_delivery] == [e["seq"] for e in by_seq]
    ts_matches_seq = [e["seq"] for e in by_ts] == [e["seq"] for e in by_seq]

    # Inversions between delivery order and hook-execution order.
    seqs = [e["seq"] for e in by_delivery]
    delivery_inversions = sum(1 for a, b in zip(seqs, seqs[1:]) if b < a)

    ts_list = [e["ts_ns"] for e in by_seq]
    ts_inversions = sum(1 for a, b in zip(ts_list, ts_list[1:]) if b < a)

    cpus = sorted({e["cpu"] for e in events})
    span = (by_seq[-1]["seq"] - by_seq[0]["seq"] + 1) if by_seq else 0
    gaps = span - len(by_seq)

    print(f"  [{label}]")
    print(f"      records            : {len(events)}"
          + (f" of {expected} expected" if expected else ""))
    print(f"      CPUs observed      : {cpus}")
    print(f"      seq range          : {by_seq[0]['seq']}..{by_seq[-1]['seq']}"
          f"  gaps={gaps}")
    print(f"      delivery order == hook order : "
          f"{'YES' if delivery_matches_seq else f'NO ({delivery_inversions} inversions)'}")
    print(f"      timestamp order == hook order: "
          f"{'YES' if ts_matches_seq else f'NO ({ts_inversions} inversions)'}")

    return {
        "records": len(events),
        "expected": expected,
        "cpus": cpus,
        "seq_gaps": gaps,
        "delivery_matches_hook_order": delivery_matches_seq,
        "delivery_inversions": delivery_inversions,
        "timestamp_matches_hook_order": ts_matches_seq,
        "timestamp_inversions": ts_inversions,
    }


def check_happens_before(events: list[dict]) -> dict:
    """W1 enforced A_i -> B_i -> A_(i+1). Does each ordering agree?"""
    pairs = [(e["seq"], e["ts_ns"], "A" if e["path"].endswith("w1-A") else "B")
             for e in events if e["path"].endswith(("w1-A", "w1-B"))]
    if not pairs:
        return {}

    by_seq = sorted(pairs, key=lambda p: p[0])
    roles = [r for _, _, r in by_seq]
    # The enforced order strictly alternates.
    alternating = all(roles[i] != roles[i + 1] for i in range(len(roles) - 1))
    violations = sum(1 for i in range(len(roles) - 1) if roles[i] == roles[i + 1])

    by_ts = sorted(pairs, key=lambda p: p[1])
    roles_ts = [r for _, _, r in by_ts]
    alternating_ts = all(roles_ts[i] != roles_ts[i + 1] for i in range(len(roles_ts) - 1))

    print()
    print("  Happens-before check (A strictly precedes B, enforced by pipe):")
    print(f"      events in the alternating chain : {len(by_seq)}")
    print(f"      hook order preserves it         : "
          f"{'YES' if alternating else f'NO ({violations} violations)'}")
    print(f"      timestamp order preserves it    : "
          f"{'YES' if alternating_ts else 'NO'}")
    return {"chain_events": len(by_seq), "hook_order_preserves": alternating,
            "hook_order_violations": violations,
            "timestamp_order_preserves": alternating_ts}


def main() -> int:
    if os.geteuid() != 0:
        print("error: must be run as root", file=sys.stderr)
        return 2

    obj = OUT / "ordering.bpf.o"
    collector = OUT / "collector_d"
    if not obj.exists() or not collector.exists():
        print(f"error: build first ({obj}, {collector})", file=sys.stderr)
        return 2

    run_as = os.environ.get("SUDO_USER") or "nobody"
    ncpu = os.cpu_count() or 1

    shutil.rmtree(BASE, ignore_errors=True)
    BASE.mkdir(parents=True)
    shutil.chown(BASE, run_as)

    # M4: every file the workloads touch is created here, before the probe
    # attaches, so no setup open falls inside the measurement window. The first
    # run of this experiment created them in the children and recorded two extra
    # events, which broke the alternation check at its first index.
    for name in ["w1-A", "w1-B"] + [f"w2-cpu{c}" for c in range(ncpu)]:
        f = BASE / name
        f.write_bytes(b"")
        shutil.chown(f, run_as)

    observed = OUT / "experiment5-observed.jsonl"
    clog = OUT / "experiment5-collector.log"

    print("=" * 76)
    print(" Phase 5A-E1: concurrent host-wide ordering")
    print("=" * 76)
    print()
    print(f" CPUs: {ncpu}   observe-only")
    print()

    print("[1/4] attaching probe...")
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
            return 1
        print("      attached")

        time.sleep(0.3)
        print(f"[2/4] W1: strict happens-before, CPUs 0 and 2, {W1_ROUNDS} rounds...")
        w1_meta = run_w1(run_as)
        w1_end = time.time()
        time.sleep(0.4)

        print(f"[3/4] W2: contention, {ncpu} processes x {W2_PER_PROC} events...")
        w2_start_marker = time.time()
        w2_meta = run_w2(run_as, ncpu)
        time.sleep(0.6)

        print("[4/4] detaching...")
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()

    events, counters = [], {}
    for line in observed.read_text(errors="replace").splitlines():
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        if rec.get("rec") == "event":
            events.append(rec)
        elif rec.get("rec") == "counters":
            counters = rec["values"]

    w1 = [e for e in events if "/w1-" in e["path"]]
    w2 = [e for e in events if "/w2-" in e["path"]]
    print(f"      {len(events)} records  (W1 {len(w1)}, W2 {len(w2)})")
    print()

    print("=" * 76)
    print(" Ordering comparison")
    print("=" * 76)
    print()
    r1 = analyse(w1, "W1 synchronised", expected=W1_ROUNDS * 2)
    hb = check_happens_before(w1)
    print()
    r2 = analyse(w2, "W2 contention", expected=w2_meta["expected"])
    print()

    print(" Probe counters:", counters)
    dropped = int(counters.get("dropped", 0))
    print(f"      ring buffer drops reported by the probe: {dropped}")
    print()

    print("=" * 76)
    print(" What this constrains")
    print("=" * 76)
    print()
    if r2.get("delivery_matches_hook_order") is False:
        print(" Delivery order and hook-execution order DISAGREE under concurrency.")
        print(" A userspace automaton reading the ring buffer would apply transitions")
        print(" in an order the kernel did not execute them in. A kernel-resident")
        print(" automaton would not have this problem, because it transitions inline.")
    elif r2.get("delivery_matches_hook_order"):
        print(" Delivery order matched hook-execution order in this run. That is a")
        print(" measurement under this load on this kernel, not a guarantee.")
    print()

    (OUT / "experiment5.json").write_text(json.dumps({
        "cpus": ncpu, "w1": {**w1_meta, **r1, "happens_before": hb},
        "w2": {**w2_meta, **r2}, "counters": counters,
    }, indent=2) + "\n")

    print(f" raw      : {observed}")
    print(f" analysis : {OUT / 'experiment5.json'}")

    shutil.rmtree(BASE, ignore_errors=True)
    for f in ("w1_child.py", "w2_child.py"):
        (OUT / f).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
