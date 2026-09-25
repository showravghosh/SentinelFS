#!/usr/bin/env python3
"""Phase 4B workload: EXEC identity and DELETE coverage.

For EXEC, each case records the pathname it actually passed to the exec syscall,
so the hook's report can be compared against the argument rather than against an
assumption about it. The cases differ in how the pathname relates to the object:
absolute, symlink, relative, interpreted script, and execveat.

For DELETE, each case removes or replaces an object by a different mechanism. The
question is not whether Linux can block deletion but whether each mechanism
produces an event, and which.
"""

from __future__ import annotations

import ctypes
import json
import os
import pathlib
import subprocess
import sys
import time

WORKDIR = pathlib.Path("/tmp/sentinel-p4b")
TRUTH: list[dict] = []

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def record(case: str, op: str, passed: str, note: str = "", **extra) -> None:
    """`passed` is the exact string handed to the syscall. That is the value the
    frozen semantics appear to name, and the point of comparison."""
    entry = {
        "case": case,
        "op": op,
        "passed": passed,
        "note": note,
        "pid": os.getpid(),
        "ts_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC),
        "seq": len(TRUTH),
    }
    entry.update(extra)
    TRUTH.append(entry)


def run_exec(pathname: str, argv: list[str], case: str, note: str = "",
             cwd: str | None = None) -> None:
    """Execute via an explicit pathname, in a child, recording the exact string."""
    pid = os.fork()
    if pid == 0:
        try:
            if cwd:
                os.chdir(cwd)
            os.execv(pathname, argv)
        except Exception:
            os._exit(127)
    record(case, "EXEC", pathname, note, child_pid=pid)
    os.waitpid(pid, 0)


# --- EXEC identity cases ---------------------------------------------------------

def case_exec_absolute() -> None:
    """A plain absolute path to a real binary."""
    run_exec("/bin/true", ["/bin/true"], "E1_absolute",
             "/bin is itself a symlink to /usr/bin on a usr-merged system")


def case_exec_symlink_chain() -> None:
    """A path that is a symlink to the real executable.

    The pathname passed and the resolved object are different files. Which one
    EXEC(p) names is exactly the question.
    """
    link = WORKDIR / "E2-link-to-true"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to("/usr/bin/true")
    run_exec(str(link), [str(link)], "E2_symlink",
             "pathname is a symlink in the workdir; object is /usr/bin/true")


def case_exec_versioned() -> None:
    """The case from Phase 4: an unversioned name resolving to a versioned binary."""
    run_exec("/usr/bin/python3", ["/usr/bin/python3", "-c", "pass"], "E3_versioned",
             "resolves to a versioned interpreter")


def case_exec_relative() -> None:
    """A relative pathname. There is no absolute string to report at all."""
    target = WORKDIR / "E4-relative.sh"
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o755)
    run_exec("./E4-relative.sh", ["./E4-relative.sh"], "E4_relative",
             "relative pathname, executed with cwd set to the workdir",
             cwd=str(WORKDIR))


def case_exec_script() -> None:
    """An interpreted script: the kernel runs the interpreter, not the script."""
    script = WORKDIR / "E5-script.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    run_exec(str(script), [str(script)], "E5_script",
             "kernel performs a second binprm pass for the interpreter")


def case_exec_at() -> None:
    """execveat with an open directory fd and a relative name.

    The pathname argument is relative to a descriptor, so there is no absolute
    pathname anywhere in the call.
    """
    target = WORKDIR / "E6-execveat.sh"
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o755)

    dirfd = os.open(str(WORKDIR), os.O_RDONLY | os.O_DIRECTORY)
    pid = os.fork()
    if pid == 0:
        try:
            argv = (ctypes.c_char_p * 2)(b"E6-execveat.sh", None)
            envp = (ctypes.c_char_p * 1)(None)
            libc.syscall(322, dirfd, b"E6-execveat.sh", argv, envp, 0)  # __NR_execveat
        finally:
            os._exit(127)
    record("E6_execveat", "EXECVEAT", "E6-execveat.sh",
           "relative to a directory fd; no absolute pathname in the call",
           child_pid=pid)
    os.waitpid(pid, 0)
    os.close(dirfd)


# --- DELETE coverage cases ---------------------------------------------------------

def make(name: str) -> pathlib.Path:
    p = WORKDIR / name
    p.write_bytes(b"payload\n")
    return p


def case_unlink() -> None:
    p = make("D1-unlink")
    os.unlink(p)
    record("D1_unlink", "UNLINK", str(p), "the object is destroyed")


def case_unlinkat() -> None:
    p = make("D2-unlinkat")
    dirfd = os.open(str(WORKDIR), os.O_RDONLY | os.O_DIRECTORY)
    os.unlink("D2-unlinkat", dir_fd=dirfd)
    record("D2_unlinkat", "UNLINKAT", str(p), "unlinkat with a directory fd")
    os.close(dirfd)


def case_rmdir() -> None:
    d = WORKDIR / "D3-dir"
    d.mkdir(exist_ok=True)
    os.rmdir(d)
    record("D3_rmdir", "RMDIR", str(d), "directory removal")


def case_rename_over_existing() -> None:
    """The destructive case: the destination exists and is replaced."""
    victim = make("D4-victim")
    source = make("D4-source")
    os.rename(source, victim)
    record("D4_rename_over", "RENAME", str(victim),
           "destination existed and was destroyed", source=str(source))


def case_rename_no_destination() -> None:
    """A rename whose destination does not exist destroys nothing."""
    source = make("D5-source")
    dest = WORKDIR / "D5-dest-absent"
    dest.unlink(missing_ok=True)
    os.rename(source, dest)
    record("D5_rename_fresh", "RENAME", str(dest),
           "destination did not exist; nothing destroyed", source=str(source))


def case_renameat2_noreplace() -> None:
    """renameat2 with RENAME_NOREPLACE must refuse to destroy the destination."""
    victim = make("D6-victim")
    source = make("D6-source")
    RENAME_NOREPLACE = 1
    dirfd = os.open(str(WORKDIR), os.O_RDONLY | os.O_DIRECTORY)
    rc = libc.syscall(316, dirfd, b"D6-source", dirfd, b"D6-victim", RENAME_NOREPLACE)
    err = ctypes.get_errno() if rc != 0 else 0
    record("D6_renameat2_noreplace", "RENAMEAT2", str(victim),
           f"RENAME_NOREPLACE, rc={rc} errno={err}", source=str(source))
    os.close(dirfd)
    victim.unlink(missing_ok=True)
    source.unlink(missing_ok=True)


def case_renameat2_exchange() -> None:
    """RENAME_EXCHANGE swaps two files: neither is destroyed, both change identity."""
    a = make("D7-a")
    b = make("D7-b")
    RENAME_EXCHANGE = 2
    dirfd = os.open(str(WORKDIR), os.O_RDONLY | os.O_DIRECTORY)
    rc = libc.syscall(316, dirfd, b"D7-a", dirfd, b"D7-b", RENAME_EXCHANGE)
    err = ctypes.get_errno() if rc != 0 else 0
    record("D7_renameat2_exchange", "RENAMEAT2", str(b),
           f"RENAME_EXCHANGE, rc={rc} errno={err}", source=str(a))
    os.close(dirfd)
    a.unlink(missing_ok=True)
    b.unlink(missing_ok=True)


def case_hardlink_then_unlink() -> None:
    """Removing one of two names leaves the object intact."""
    p = make("D8-original")
    link = WORKDIR / "D8-second"
    link.unlink(missing_ok=True)
    os.link(p, link)
    os.unlink(link)
    record("D8_hardlink_unlink", "UNLINK", str(link),
           "one name removed; the object survives under another name")
    p.unlink(missing_ok=True)


def case_truncate_to_zero() -> None:
    """Truncation destroys contents without removing the name."""
    p = make("D9-truncate")
    os.truncate(p, 0)
    record("D9_truncate", "TRUNCATE", str(p),
           "contents destroyed, name retained")
    p.unlink(missing_ok=True)


# --- OPEN identity ------------------------------------------------------------------

def case_open_via_symlink() -> None:
    """Open a file through a symlink: which name does the hook report?"""
    real = make("O1-real")
    link = WORKDIR / "O1-link"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(real)
    fd = os.open(str(link), os.O_RDONLY)
    record("O1_open_symlink", "OPEN", str(link),
           "opened through a symlink; object is O1-real")
    os.close(fd)


CASES = [
    ("E1_absolute", case_exec_absolute),
    ("E2_symlink", case_exec_symlink_chain),
    ("E3_versioned", case_exec_versioned),
    ("E4_relative", case_exec_relative),
    ("E5_script", case_exec_script),
    ("E6_execveat", case_exec_at),
    ("D1_unlink", case_unlink),
    ("D2_unlinkat", case_unlinkat),
    ("D3_rmdir", case_rmdir),
    ("D4_rename_over", case_rename_over_existing),
    ("D5_rename_fresh", case_rename_no_destination),
    ("D6_renameat2_noreplace", case_renameat2_noreplace),
    ("D7_renameat2_exchange", case_renameat2_exchange),
    ("D8_hardlink_unlink", case_hardlink_then_unlink),
    ("D9_truncate", case_truncate_to_zero),
    ("O1_open_symlink", case_open_via_symlink),
]


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sentinel-p4b-truth.json"
    WORKDIR.mkdir(parents=True, exist_ok=True)

    time.sleep(0.4)
    start = time.clock_gettime_ns(time.CLOCK_MONOTONIC)

    for name, fn in CASES:
        case_start = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        try:
            fn()
            failed = None
        except Exception as e:  # a case that cannot run is itself a result
            failed = f"{type(e).__name__}: {e}"
        case_end = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        TRUTH.append({
            "case": name, "op": "_case_bounds", "passed": "", "note": "",
            "pid": os.getpid(), "ts_ns": case_end, "seq": len(TRUTH),
            "case_start_ns": case_start, "case_end_ns": case_end,
            "failed": failed,
        })
        time.sleep(0.06)

    end = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    time.sleep(0.4)

    pathlib.Path(out).write_text(json.dumps({
        "runner_pid": os.getpid(),
        "workdir": str(WORKDIR),
        "start_ns": start, "end_ns": end,
        "operations": TRUTH,
    }, indent=2))

    ops = [t for t in TRUTH if t["op"] != "_case_bounds"]
    failures = [t for t in TRUTH if t["op"] == "_case_bounds" and t.get("failed")]
    print(f"runner pid: {os.getpid()}")
    print(f"cases:      {len(CASES)}")
    print(f"operations: {len(ops)}")
    if failures:
        print(f"cases that could not run: {[(f['case'], f['failed']) for f in failures]}")
    print(f"truth file: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
