#!/usr/bin/env python3
"""Phase 4 experiment 2 workload: precisely known operations, including the cases
that distinguish one candidate hook from another.

The decisive cases are the negative ones. Whether lsm/file_open can stand in for
WRITE(path) is settled not by watching a write happen, but by watching what the
hooks do when a file is opened for writing and then closed without a write: under
the frozen semantics that must produce no WRITE event.

Each case records what it did, at syscall granularity, following the lesson of
Phase 2 section 4.3: the ground truth describes the syscalls issued, not the
programmer's intent.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import sys
import time

WORKDIR = pathlib.Path("/tmp/sentinel-p4")
TRUTH: list[dict] = []


def record(case: str, op: str, target: str, note: str = "") -> None:
    TRUTH.append({
        "case": case,
        "op": op,
        "target": target,
        "note": note,
        "pid": os.getpid(),
        "ts_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC),
        "seq": len(TRUTH),
    })


def fresh(name: str, contents: bytes = b"seed\n") -> pathlib.Path:
    p = WORKDIR / name
    p.write_bytes(contents)
    return p


# --- WRITE: the semantic cases -------------------------------------------------

def case_open_write_close() -> None:
    """Case A: open for write, write, close. Must yield a WRITE event."""
    p = fresh("A-open-write-close")
    fd = os.open(p, os.O_WRONLY)
    record("A_open_write_close", "OPEN_WRONLY", str(p))
    os.write(fd, b"x")
    record("A_open_write_close", "WRITE", str(p), "one write of one byte")
    os.close(fd)


def case_open_close_no_write() -> None:
    """Case B: open for write, close, NO write.

    This is the case that decides whether file_open can implement WRITE. Under the
    frozen semantics this must produce no WRITE event: nothing was written.
    """
    p = fresh("B-open-close-nowrite")
    fd = os.open(p, os.O_WRONLY)
    record("B_open_close_no_write", "OPEN_WRONLY", str(p),
           "opened for write but never written")
    os.close(fd)


def case_read_only() -> None:
    """A read-only open must yield no WRITE event under any candidate."""
    p = fresh("C-readonly")
    fd = os.open(p, os.O_RDONLY)
    record("C_read_only", "OPEN_RDONLY", str(p))
    os.read(fd, 16)
    record("C_read_only", "READ", str(p))
    os.close(fd)


def case_multiple_writes() -> None:
    """Three writes through one descriptor: does the hook fire per write or per open?"""
    p = fresh("D-multiwrite")
    fd = os.open(p, os.O_WRONLY)
    record("D_multiple_writes", "OPEN_WRONLY", str(p))
    for i in range(3):
        os.write(fd, b"y")
        record("D_multiple_writes", "WRITE", str(p), f"write {i + 1} of 3")
    os.close(fd)


def case_inherited_fd() -> None:
    """Write through a descriptor inherited across fork.

    Assumption A1b says a WRITE event carries a path only where the descriptor's
    creation was observed. Here the open is observed, but the write happens in a
    different process.
    """
    p = fresh("E-inherited")
    fd = os.open(p, os.O_WRONLY)
    record("E_inherited_fd", "OPEN_WRONLY", str(p), "opened in parent")

    pid = os.fork()
    if pid == 0:
        try:
            os.write(fd, b"z")
        finally:
            os._exit(0)
    os.waitpid(pid, 0)
    record("E_inherited_fd", "WRITE", str(p), "written in forked child")
    os.close(fd)


def case_reopened_fd() -> None:
    """Write through a descriptor opened before the probe attached is untestable
    from inside this workload, so the nearest approximation is recorded: an fd
    duplicated after opening, which keeps the same file but a new descriptor."""
    p = fresh("F-dup")
    fd = os.open(p, os.O_WRONLY)
    record("F_dup_fd", "OPEN_WRONLY", str(p))
    dup = os.dup(fd)
    record("F_dup_fd", "DUP", str(p))
    os.write(dup, b"w")
    record("F_dup_fd", "WRITE", str(p), "written through duplicated descriptor")
    os.close(dup)
    os.close(fd)


def case_non_file_write() -> None:
    """Writes to a pipe and a socket: objects with no filesystem path.

    These must not appear as WRITE(p) for any p, because there is no p. A1b says
    such writes fall outside the alphabet rather than being reported with an empty
    argument.
    """
    r, w = os.pipe()
    os.write(w, b"pipe")
    record("G_non_file_write", "WRITE_PIPE", "<pipe>", "no filesystem path exists")
    os.close(r)
    os.close(w)

    a, b = socket.socketpair()
    a.send(b"sock")
    record("G_non_file_write", "WRITE_SOCKET", "<socketpair>", "no filesystem path exists")
    a.close()
    b.close()


def case_truncate() -> None:
    """Truncation empties a file without unlinking or writing it. Which event, if
    any, this corresponds to is a question for the findings."""
    p = fresh("H-truncate", b"contents to be discarded\n")
    fd = os.open(p, os.O_WRONLY | os.O_TRUNC)
    record("H_truncate", "OPEN_TRUNC", str(p), "O_TRUNC empties the file")
    os.close(fd)

    p2 = fresh("H-truncate-call", b"contents to be discarded\n")
    os.truncate(p2, 0)
    record("H_truncate", "TRUNCATE", str(p2), "truncate(2) syscall")


# --- DELETE: the variants -------------------------------------------------------

def case_unlink() -> None:
    p = fresh("I-unlink")
    os.unlink(p)
    record("I_unlink", "UNLINK", str(p))


def case_rename_over() -> None:
    """Renaming over an existing file removes that file without unlink(2).

    If DELETE is implemented with an unlink hook, this path destroys a file without
    producing a DELETE event.
    """
    victim = fresh("J-rename-victim")
    source = fresh("J-rename-source")
    os.rename(source, victim)
    record("J_rename_over", "RENAME_OVER", str(victim),
           "victim destroyed without unlink(2)")
    victim.unlink(missing_ok=True)


def case_rmdir() -> None:
    d = WORKDIR / "K-dir"
    d.mkdir(exist_ok=True)
    os.rmdir(d)
    record("K_rmdir", "RMDIR", str(d), "directory removal, not unlink(2)")


def case_hardlink_unlink() -> None:
    """Unlinking one of two links removes a name, not the file's contents.

    DELETE(path) names a path; whether removing one link of several is the event
    the specification means is a question this case makes concrete.
    """
    p = fresh("L-hardlink-original")
    link = WORKDIR / "L-hardlink-second"
    if link.exists():
        link.unlink()
    os.link(p, link)
    record("L_hardlink", "LINK", str(link))
    os.unlink(link)
    record("L_hardlink", "UNLINK", str(link), "file survives, one name removed")
    p.unlink(missing_ok=True)


# --- EXEC ------------------------------------------------------------------------

def case_exec() -> None:
    """Execute two binaries, as the canonical policy chain does."""
    for binary in ("/usr/bin/python3", "/bin/bash"):
        proc = subprocess.Popen([binary, "-c", "pass" if "python" in binary else "true"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        record("M_exec", "EXEC", binary, f"child pid {proc.pid}")
        proc.wait()


def case_exec_script() -> None:
    """Execute a script with an interpreter line.

    The kernel executes the interpreter, not the script, so the executable named by
    the hook may not be the file the user ran. Whether EXEC(path) means the script
    or the interpreter is a semantic question worth making explicit.
    """
    script = WORKDIR / "N-script.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    proc = subprocess.Popen([str(script)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    record("N_exec_script", "EXEC_SCRIPT", str(script),
           "interpreted script; kernel execs /bin/sh")
    proc.wait()


CASES = [
    ("A_open_write_close", case_open_write_close),
    ("B_open_close_no_write", case_open_close_no_write),
    ("C_read_only", case_read_only),
    ("D_multiple_writes", case_multiple_writes),
    ("E_inherited_fd", case_inherited_fd),
    ("F_dup_fd", case_reopened_fd),
    ("G_non_file_write", case_non_file_write),
    ("H_truncate", case_truncate),
    ("I_unlink", case_unlink),
    ("J_rename_over", case_rename_over),
    ("K_rmdir", case_rmdir),
    ("L_hardlink", case_hardlink_unlink),
    ("M_exec", case_exec),
    ("N_exec_script", case_exec_script),
]


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sentinel-p4-truth.json"
    WORKDIR.mkdir(parents=True, exist_ok=True)

    time.sleep(0.4)  # quiet period so the collector can separate setup from cases
    start = time.clock_gettime_ns(time.CLOCK_MONOTONIC)

    for name, fn in CASES:
        marker_start = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        fn()
        marker_end = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        TRUTH.append({
            "case": name, "op": "_case_bounds", "target": "",
            "note": "", "pid": os.getpid(),
            "ts_ns": marker_end, "seq": len(TRUTH),
            "case_start_ns": marker_start, "case_end_ns": marker_end,
        })
        time.sleep(0.05)  # separate cases in time so records attribute unambiguously

    end = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    time.sleep(0.4)

    pathlib.Path(out).write_text(json.dumps({
        "runner_pid": os.getpid(),
        "workdir": str(WORKDIR),
        "start_ns": start,
        "end_ns": end,
        "operations": TRUTH,
    }, indent=2))

    print(f"runner pid:  {os.getpid()}")
    print(f"cases run:   {len(CASES)}")
    print(f"operations:  {len([t for t in TRUTH if t['op'] != '_case_bounds'])}")
    print(f"truth file:  {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
