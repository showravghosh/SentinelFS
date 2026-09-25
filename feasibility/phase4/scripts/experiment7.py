#!/usr/bin/env python3
"""Phase 5B.0 step 4: can the adopted EXEC, WRITE and DELETE hooks deny?

Phase 4 demonstrated pre-effect denial for lsm/file_open only, and recorded the
other three as unmeasured. This experiment measures them.

What it can conclude is bounded, and the report says so: pre-effect denial was
measured for these hooks, on this kernel, in these configurations. It is not
evidence that EXEC, WRITE and DELETE are universally pre-effect on Linux, and
it is not evidence for any trace model. Whether a formal event means a completed
occurrence or an adjudicated attempt is a separate decision that this experiment
informs and does not make.

Structure. Each arm attaches its probe inert, performs setup, arms the probe,
makes exactly one attempt, disarms, and then checks the post-condition. Setup is
outside the armed interval by construction rather than by ordering discipline,
which is methodology rule M4: an earlier phase produced a phantom result because
setup work fell inside a measurement interval.

Each test records the same five things:

    before state -> attempt -> LSM return value -> hook counters -> after state

A denial that leaves the post-condition unchanged is the result. A denial whose
post-condition changed anyway would mean the hook refused after the effect, which
is the outcome that would matter most and is therefore checked explicitly rather
than assumed away.

Must be run as root: attaching an LSM program requires it.
"""

import ctypes
import errno
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
OUT = HERE / "out"
RESULTS = HERE / "results"
ROOT = Path("/tmp/sentinel-p7")

RENAME_EXCHANGE = 2


class Probe:
    """A probe attached inert, armed only for the measurement interval."""

    def __init__(self, obj_name):
        self.obj = OUT / obj_name
        self.proc = None

    def __enter__(self):
        loader = OUT / "loader7"
        if not self.obj.exists() or not loader.exists():
            raise SystemExit(f"build first: {self.obj} or {loader} missing")
        self.proc = subprocess.Popen(
            [str(loader), str(self.obj)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        line = self.proc.stdout.readline().strip()
        if not line.startswith("READY"):
            err = self.proc.stderr.read()
            raise SystemExit(f"attach failed: {line} {err}")
        self.attached_programs = int(line.split()[1])
        return self

    def _cmd(self, text, expect):
        self.proc.stdin.write(text + "\n")
        self.proc.stdin.flush()
        got = self.proc.stdout.readline().strip()
        if got != expect:
            raise SystemExit(f"loader said {got!r}, expected {expect!r}")

    def arm(self):
        self._cmd("arm", "ARMED")

    def disarm(self):
        self._cmd("disarm", "DISARMED")

    def stats(self):
        self.proc.stdin.write("stats\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline().strip()
        counters = {}
        if line.startswith("STATS"):
            for part in line.split()[1:]:
                k, v = part.split("=")
                counters[int(k)] = int(v)
        last = ""
        nxt = self.proc.stdout.readline().strip()
        if nxt.startswith("LAST_DENIED"):
            last = nxt[len("LAST_DENIED "):]
        return counters, last

    def __exit__(self, *exc):
        try:
            self.proc.stdin.write("quit\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def attempt(fn):
    """Run an operation, returning the errno it produced (0 on success)."""
    try:
        fn()
        return 0
    except OSError as e:
        return e.errno
    except subprocess.CalledProcessError:
        return -1


def run_exec_arm():
    d = ROOT / "exec"
    results = {}

    with Probe("deny_exec.bpf.o") as probe:
        # --- setup, probe attached but inert -----------------------------------
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)

        # A real ELF that leaves an observable effect, so "did not start" is
        # measured by absence of the effect rather than only by the return code.
        shutil.copy("/bin/touch", d / "protected-elf")
        shutil.copy("/bin/touch", d / "allowed-elf")
        (d / "protected-script").write_text("#!/bin/sh\nexec /bin/touch \"$1\"\n")
        # The symlink's own name is NOT protected; only its target is. If denial
        # worked on the passed name rather than the resolved one, this case would
        # be allowed, so it distinguishes the two.
        os.symlink(d / "protected-elf", d / "sneaky-link")
        for f in ("protected-elf", "allowed-elf", "protected-script"):
            os.chmod(d / f, 0o755)

        cases = [
            ("elf", [str(d / "protected-elf")], d / "marker-elf", None, True),
            ("script", [str(d / "protected-script")], d / "marker-script", None, True),
            ("symlink", [str(d / "sneaky-link")], d / "marker-link", None, True),
            ("relative", ["./protected-elf"], d / "marker-rel", str(d), True),
            ("control", [str(d / "allowed-elf")], d / "marker-ctrl", None, False),
        ]

        for name, argv, marker, cwd, expect_denied in cases:
            if marker.exists():
                marker.unlink()

        probe.arm()
        # --- measurement interval ---------------------------------------------
        for name, argv, marker, cwd, expect_denied in cases:
            # A refusal at bprm_check_security means no child is created, so
            # posix_spawn raises instead of returning a code. That raise IS the
            # denial, and is recorded rather than propagated.
            try:
                rc = subprocess.run(argv + [str(marker)], cwd=cwd,
                                    capture_output=True, text=True)
                returncode, err, detail = rc.returncode, 0, rc.stderr.strip()[:120]
            except OSError as e:
                returncode, err, detail = -1, e.errno, f"{type(e).__name__}: {e}"
            results[name] = {
                "argv": argv,
                "returncode": returncode,
                "errno": err,
                "stderr": detail,
                "expected_denied": expect_denied,
            }
        probe.disarm()
        # --- end of measurement interval ---------------------------------------

        for name, argv, marker, cwd, expect_denied in cases:
            started = marker.exists()
            results[name]["program_started"] = started
            refused = results[name]["returncode"] != 0 or results[name]["errno"] != 0
            results[name]["denied"] = (not started) and refused
            # The outcome that would matter most: refused, yet the program ran.
            results[name]["started_despite_refusal"] = started and refused
            results[name]["correct"] = results[name]["denied"] == expect_denied

        counters, last = probe.stats()
        return {
            "cases": results,
            "counters": counters,
            "last_denied": last,
            "attached_programs": probe.attached_programs,
        }


def run_write_arm():
    d = ROOT / "write"
    payload = b"ORIGINAL-CONTENT-DO-NOT-MODIFY\n"
    overwrite = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    results = {}

    with Probe("deny_write.bpf.o") as probe:
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        (d / "protected-file").write_bytes(payload)
        (d / "allowed-file").write_bytes(payload)

        # The descriptors are opened BEFORE arming, for two reasons. A1b requires
        # the correlation to come from an observed opening, and opening while
        # armed would risk the refusal landing at open time -- which Phase 4
        # already measured and which would say nothing about write-time
        # enforcement.
        # Raw descriptors, not buffered file objects. A BufferedWriter retains
        # its buffer when a flush fails and flushes again on close; with the
        # probe disarmed by then, the cleanup itself would perform the write
        # the measurement had just refused.
        fds = {
            "protected": os.open(d / "protected-file", os.O_RDWR),
            "allowed": os.open(d / "allowed-file", os.O_RDWR),
        }
        sampled = {}

        probe.arm()
        # --- measurement interval ---------------------------------------------
        for name, fd in fds.items():
            def do_write(fd=fd):
                os.lseek(fd, 0, os.SEEK_SET)
                os.write(fd, overwrite)
            results[name] = {"errno": attempt(do_write)}
            # Sampled while still armed, so the observation cannot include
            # anything done after the interval.
            sampled[name] = os.pread(fd, len(payload) + 8, 0)
        probe.disarm()
        # --- end of measurement interval ---------------------------------------

        for fd in fds.values():
            try:
                os.close(fd)
            except OSError:
                pass

        for name, fname, expect_denied in (
            ("protected", "protected-file", True),
            ("allowed", "allowed-file", False),
        ):
            after = (d / fname).read_bytes()
            # Both readings are kept: in-interval and post-close. A disagreement
            # between them localises a change to the cleanup rather than the
            # measured operation.
            unchanged = after == payload
            results[name]["bytes_unchanged_in_interval"] = sampled[name] == payload
            results[name]["bytes_unchanged_after_close"] = unchanged
            results[name]["bytes_unchanged"] = unchanged
            results[name]["expected_denied"] = expect_denied
            results[name]["denied"] = results[name]["errno"] != 0 and unchanged
            results[name]["correct"] = results[name]["denied"] == expect_denied
            # The case that would matter most: refused, yet the bytes changed.
            results[name]["refused_after_effect"] = (
                results[name]["errno"] != 0 and not unchanged
            )

        counters, last = probe.stats()
        return {"cases": results, "counters": counters, "last_denied": last,
                "attached_programs": probe.attached_programs}


def renameat2(old, new, flags):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    AT_FDCWD = -100
    res = libc.syscall(316, AT_FDCWD, old.encode(), AT_FDCWD, new.encode(), flags)
    if res != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


def run_delete_arm():
    d = ROOT / "delete"
    results = {}

    with Probe("deny_delete.bpf.o") as probe:
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        (d / "protected-unlink").write_text("keep\n")
        (d / "protected-src").write_text("keep\n")
        (d / "protected-dst").write_text("keep-dst\n")
        (d / "allowed-unlink").write_text("removable\n")
        (d / "mover-src").write_text("mover\n")
        (d / "protected-rmdir").mkdir()

        probe.arm()
        # --- measurement interval ---------------------------------------------
        results["unlink"] = {
            "errno": attempt(lambda: os.unlink(d / "protected-unlink")),
            "entry": "protected-unlink", "expected_denied": True}
        results["rmdir"] = {
            "errno": attempt(lambda: os.rmdir(d / "protected-rmdir")),
            "entry": "protected-rmdir", "expected_denied": True}
        results["rename_src"] = {
            "errno": attempt(lambda: os.rename(d / "protected-src", d / "moved-away")),
            "entry": "protected-src", "expected_denied": True}
        results["rename_over"] = {
            "errno": attempt(lambda: os.rename(d / "mover-src", d / "protected-dst")),
            "entry": "protected-dst", "expected_denied": True}
        results["rename_exchange"] = {
            "errno": attempt(lambda: renameat2(str(d / "mover-src"),
                                               str(d / "protected-dst"),
                                               RENAME_EXCHANGE)),
            "entry": "protected-dst", "expected_denied": True}
        results["control_unlink"] = {
            "errno": attempt(lambda: os.unlink(d / "allowed-unlink")),
            "entry": "allowed-unlink", "expected_denied": False}
        probe.disarm()
        # --- end of measurement interval ---------------------------------------

        for name, r in results.items():
            present = (d / r["entry"]).exists()
            r["entry_present_after"] = present
            if r["expected_denied"]:
                r["denied"] = r["errno"] != 0 and present
                r["removed_despite_refusal"] = r["errno"] != 0 and not present
            else:
                r["denied"] = r["errno"] != 0 or present
            r["correct"] = r["denied"] == r["expected_denied"]

        # protected-dst must still hold its own content: an exchange that was
        # refused must not have swapped the contents either.
        results["rename_over"]["dst_content_intact"] = (
            (d / "protected-dst").read_text() == "keep-dst\n"
            if (d / "protected-dst").exists() else False)

        counters, last = probe.stats()
        return {"cases": results, "counters": counters, "last_denied": last,
                "attached_programs": probe.attached_programs}


def main():
    if os.geteuid() != 0:
        print("error: must be run as root (attaching an LSM program requires it)",
              file=sys.stderr)
        return 2

    RESULTS.mkdir(exist_ok=True)
    record = {
        "experiment": "phase5b0-step4-enforcement-capability",
        "kernel": subprocess.run(["uname", "-r"], capture_output=True,
                                 text=True).stdout.strip(),
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "claim_scope": (
            "Pre-effect denial measured for the tested hooks, kernel, "
            "configurations and workloads. Not a universal claim about Linux, "
            "and not evidence for any trace model."
        ),
    }

    for label, fn in (("exec", run_exec_arm), ("write", run_write_arm),
                      ("delete", run_delete_arm)):
        print(f"[{label}] attaching inert, setting up, arming...")
        try:
            record[label] = fn()
        except SystemExit as e:
            record[label] = {"error": str(e)}
            print(f"  ERROR: {e}")
            continue
        cases = record[label]["cases"]
        for name, r in cases.items():
            mark = "ok " if r.get("correct") else "MISMATCH"
            print(f"  {mark} {name:16s} errno={r.get('errno', r.get('returncode'))} "
                  f"denied={r.get('denied')} expected={r.get('expected_denied')}")

    out = RESULTS / "step4-enforcement.json"
    out.write_text(json.dumps(record, indent=2, default=str))
    print(f"\nwritten: {out}")

    # Overall correctness, reported but not interpreted.
    all_cases = [r for label in ("exec", "write", "delete")
                 if isinstance(record.get(label), dict) and "cases" in record[label]
                 for r in record[label]["cases"].values()]
    correct = sum(1 for r in all_cases if r.get("correct"))
    print(f"cases correct: {correct}/{len(all_cases)}")
    return 0 if all_cases and correct == len(all_cases) else 1


if __name__ == "__main__":
    sys.exit(main())
