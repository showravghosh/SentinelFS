#!/usr/bin/env python3
"""Phase 4C: is resolved-path identity stable enough to carry the security property?

The event-identity analysis recommends defining every event on the resolved
filesystem path. That rests on a resolved path naming the object rather than the
route taken to it. Symlinks resolve; the remaining cases were untested.

Each scenario accesses one object by a different route, or changes the object
underneath a fixed name. For each, the probe reports the resolved path and the
device/inode. The inode settles what the path cannot: whether two accesses reached
the same object.

The decisive case is the hard link. A hard link has no canonical path, so if
d_path reports the route used, resolved-path identity is evadable by `ln` exactly
as name identity is evadable by `ln -s`.

Observe-only. Must be run as root: bind mounts and mount namespaces require it.
"""

from __future__ import annotations

import ctypes
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
BASE = pathlib.Path("/tmp/sentinel-p4c")
BIND = pathlib.Path("/tmp/sentinel-p4c-bind")

libc = ctypes.CDLL("libc.so.6", use_errno=True)
CLONE_NEWNS = 0x00020000
MS_BIND = 0x1000

SCENARIOS: list[dict] = []


def note(scenario: str, action: str, opened: str, expect: str) -> None:
    SCENARIOS.append({
        "scenario": scenario,
        "action": action,
        "opened": opened,
        "expectation": expect,
        "ts_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC),
    })


def touch_open(path: str) -> None:
    """Open for reading and close. This is what the probe observes."""
    try:
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)
    except OSError as e:
        SCENARIOS[-1]["open_error"] = os.strerror(e.errno)


def run_scenarios() -> None:
    canonical = BASE / "target"

    # S1 - the ordinary case, establishing the baseline path and inode.
    canonical.write_bytes(b"protected contents\n")
    note("S1_ordinary", "open the file by its own path", str(canonical),
         "resolved path equals the literal a policy would name")
    touch_open(str(canonical))

    # S2 - symlink. Already known to resolve; included so every route appears in
    # one table with its inode.
    link = BASE / "via-symlink"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(canonical)
    note("S2_symlink", "open through a symlink", str(link),
         "resolves to the canonical path; same inode")
    touch_open(str(link))

    # S3 - hard link. The decisive case: no canonical path exists.
    hard = BASE / "via-hardlink"
    hard.unlink(missing_ok=True)
    os.link(canonical, hard)
    note("S3_hardlink", "open through a second hard link", str(hard),
         "same inode; resolved path may be the link, not the original")
    touch_open(str(hard))

    # S4 - bind mount. The same object reachable under a second mount point.
    BIND.mkdir(exist_ok=True)
    rc = libc.mount(str(BASE).encode(), str(BIND).encode(), None, MS_BIND, None)
    if rc == 0:
        note("S4_bind_mount", "open through a bind mount", str(BIND / "target"),
             "same inode; resolved path reflects the mount used")
        touch_open(str(BIND / "target"))
    else:
        note("S4_bind_mount", "bind mount failed", str(BIND / "target"),
             f"could not mount: {os.strerror(ctypes.get_errno())}")

    # S5 - rename after the policy would have been loaded.
    renamed = BASE / "renamed-after-load"
    renamed.unlink(missing_ok=True)
    os.rename(canonical, renamed)
    note("S5_renamed", "rename the object, then open it under the new name",
         str(renamed), "same inode; resolved path is now the new name")
    touch_open(str(renamed))
    os.rename(renamed, canonical)  # restore for the next scenario

    # S6 - replacement. The name is kept; the object behind it is different.
    old_ino = canonical.stat().st_ino
    canonical.unlink()
    canonical.write_bytes(b"substituted contents\n")
    new_ino = canonical.stat().st_ino
    note("S6_replaced", "delete the object and recreate the same name",
         str(canonical),
         f"path unchanged; inode changes {old_ino} -> {new_ino}")
    touch_open(str(canonical))

    # S7 - mount namespace. d_path is namespace-relative, so a private mount in a
    # separate namespace may yield a different resolved path for the same object.
    note("S7_mount_namespace", "open inside a separate mount namespace",
         str(BASE / "target"), "resolved path is relative to the namespace")
    pid = os.fork()
    if pid == 0:
        try:
            if libc.unshare(CLONE_NEWNS) == 0:
                libc.mount(b"none", b"/", None, 1 << 19, None)  # MS_PRIVATE
                libc.mount(str(BASE).encode(), str(BIND).encode(), None, MS_BIND, None)
                fd = os.open(str(BIND / "target"), os.O_RDONLY)
                os.close(fd)
        except Exception:
            pass
        os._exit(0)
    os.waitpid(pid, 0)


def cleanup() -> None:
    subprocess.run(["umount", "-l", str(BIND)], capture_output=True)
    shutil.rmtree(BIND, ignore_errors=True)
    shutil.rmtree(BASE, ignore_errors=True)


def main() -> int:
    if os.geteuid() != 0:
        print("error: must be run as root (bind mounts and namespaces require it)",
              file=sys.stderr)
        return 2

    obj = OUT / "stability.bpf.o"
    collector = OUT / "collector_c"
    if not obj.exists() or not collector.exists():
        print(f"error: build first ({obj}, {collector})", file=sys.stderr)
        return 2

    cleanup()
    BASE.mkdir(parents=True, exist_ok=True)

    observed = OUT / "experiment4-observed.jsonl"
    clog = OUT / "experiment4-collector.log"

    print("=" * 76)
    print(" Phase 4C: stability of resolved-path identity")
    print("=" * 76)
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
            cleanup()
            return 1
        print("      attached")

        print("[2/3] running scenarios...")
        time.sleep(0.3)
        run_scenarios()
        time.sleep(0.5)

        print("[3/3] detaching...")
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

    events = []
    for line in observed.read_text(errors="replace").splitlines():
        if line.startswith("{"):
            rec = json.loads(line)
            if rec.get("rec") == "event":
                events.append(rec)
    print(f"      {len(events)} records")
    print()

    # Attribute each record to the scenario whose window contains it.
    bounds = []
    for i, s in enumerate(SCENARIOS):
        end = SCENARIOS[i + 1]["ts_ns"] if i + 1 < len(SCENARIOS) else float("inf")
        bounds.append((s["scenario"], s["ts_ns"], end, s))

    print("=" * 76)
    print(" What the probe reported for each route to the object")
    print("=" * 76)
    print()

    baseline_ino = None
    rows = []
    for name, lo, hi, meta in bounds:
        recs = [e for e in events if lo <= e["ts_ns"] < hi]
        if not recs:
            rows.append({"scenario": name, "records": 0, "meta": meta})
            print(f" {name}")
            print(f"   opened      : {meta['opened']}")
            print(f"   expectation : {meta['expectation']}")
            print("   reported    : NO RECORD"
                  + (f"  ({meta['open_error']})" if "open_error" in meta else ""))
            print()
            continue

        # Attribute by the object accessed, not by position in the window: the
        # next scenario's setup can open a file before its marker is recorded,
        # which displaced S5 in the first run of this experiment.
        wanted = pathlib.PurePosixPath(meta["opened"]).name
        matching = [e for e in recs
                    if e["dentry_name"] == wanted
                    or pathlib.PurePosixPath(e["resolved"]).name == wanted]
        r = matching[0] if matching else recs[0]
        if baseline_ino is None:
            baseline_ino = r["ino"]
        same_object = "same" if r["ino"] == baseline_ino else "DIFFERENT"

        print(f" {name}")
        print(f"   opened      : {meta['opened']}")
        print(f"   resolved to : {r['resolved']}")
        print(f"   dentry name : {r['dentry_name']}")
        print(f"   inode       : {r['ino']} (dev {r['dev_major']}:{r['dev_minor']}, "
              f"nlink {r['nlink']})  -> {same_object} object as S1")
        print()
        rows.append({"scenario": name, "records": len(recs), "meta": meta,
                     "resolved": r["resolved"], "ino": r["ino"],
                     "nlink": r["nlink"], "same_object": same_object})

    # --- the questions this experiment exists to answer ---------------------------
    canonical_path = str(BASE / "target")
    print("=" * 76)
    print(" Consequences for resolved-path identity")
    print("=" * 76)
    print()

    def row(name: str) -> dict | None:
        for r in rows:
            if r["scenario"] == name and r.get("records"):
                return r
        return None

    s1, s3 = row("S1_ordinary"), row("S3_hardlink")
    if s1 and s3:
        evadable = s3["resolved"] != s1["resolved"] and s3["ino"] == s1["ino"]
        print(" Hard link")
        print(f"   S1 resolved : {s1['resolved']}")
        print(f"   S3 resolved : {s3['resolved']}")
        print(f"   same object : {s3['ino'] == s1['ino']}")
        if evadable:
            print("   => the same object was reached under a path a policy naming")
            print("      the original would NOT match. Resolved-path identity is")
            print("      evadable by hard link.")
        else:
            print("   => the hard link resolved to the original path.")
        print()

    s4 = row("S4_bind_mount")
    if s4 and s1:
        print(" Bind mount")
        print(f"   resolved    : {s4['resolved']}")
        print(f"   same object : {s4['ino'] == s1['ino']}")
        print("   => a policy naming the original path does "
              + ("NOT match" if s4["resolved"] != s1["resolved"] else "match")
              + " access via the bind mount.")
        print()

    s5 = row("S5_renamed")
    if s5 and s1:
        print(" Rename after policy load")
        print(f"   resolved    : {s5['resolved']}")
        print(f"   same object : {s5['ino'] == s1['ino']}")
        print("   => the object outlives the name a policy named.")
        print()

    s6 = row("S6_replaced")
    if s6 and s1:
        print(" Replacement behind a stable name")
        print(f"   resolved    : {s6['resolved']}")
        print(f"   same object : {s6['same_object']}")
        print("   => the path a policy names can come to denote a different object.")
        print()

    (OUT / "experiment4.json").write_text(json.dumps({
        "scenarios": SCENARIOS,
        "rows": [{k: v for k, v in r.items() if k != "meta"} for r in rows],
        "canonical_path": canonical_path,
    }, indent=2) + "\n")

    print("=" * 76)
    print(f" raw      : {observed}")
    print(f" analysis : {OUT / 'experiment4.json'}")
    print("=" * 76)

    cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
