#!/usr/bin/env python3
"""Cross-implementation conformance between the Python reference and the Rust port.

The Rust implementation is required to conform to the Python reference, which is in
turn the executable statement of docs/formal-semantics.md. This harness runs the
same policies and the same traces through both command-line interfaces and compares
their output exactly.

Comparing stdout rather than in-process values is deliberate: it checks the compiled
automaton, the executor, the decision, the step-by-step path, and the formatting of
all of them, and it cannot accidentally share code between the two sides.

A divergence is a defect to be investigated, not smoothed over. Per the freeze of
v1.0-spec, the specification is not to be revised because an implementation finds it
inconvenient.
"""

from __future__ import annotations

import argparse
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
RUST_BIN = ROOT / "rust" / "target" / "release" / "sentinelfs"

EVENT_TYPES = ["EXEC", "WRITE", "OPEN", "DELETE"]
ARGS = [
    "/usr/bin/python3",
    "/bin/bash",
    "/etc/shadow",
    "/etc/passwd",
    "/tmp/test.txt",
    "/var/log/syslog",
]


def event_literal(rng: random.Random) -> str:
    return f'{rng.choice(EVENT_TYPES)}("{rng.choice(ARGS)}")'


def run_python(args: list[str]) -> tuple[int, str, str]:
    r = subprocess.run(
        [sys.executable, "-m", "sentinelfs.cli", *args],
        cwd=ROOT, capture_output=True, text=True,
    )
    return r.returncode, r.stdout, r.stderr


def run_rust(args: list[str]) -> tuple[int, str, str]:
    r = subprocess.run([str(RUST_BIN), *args], cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def compare(label: str, args: list[str], failures: list[str]) -> None:
    py_code, py_out, py_err = run_python(args)
    rs_code, rs_out, rs_err = run_rust(args)

    if py_out != rs_out:
        failures.append(
            f"{label}: stdout differs\n"
            f"  args:   {args}\n"
            f"  python: {py_out!r}\n"
            f"  rust:   {rs_out!r}"
        )
        return

    # Exit status must agree on success versus failure. The exact non-zero value is
    # not part of the specification, so only the distinction is compared.
    if (py_code == 0) != (rs_code == 0):
        failures.append(
            f"{label}: exit status differs\n"
            f"  args:   {args}\n"
            f"  python: {py_code} ({py_err.strip()!r})\n"
            f"  rust:   {rs_code} ({rs_err.strip()!r})"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--traces", type=int, default=150,
                        help="random traces per example policy")
    parser.add_argument("--seed", type=int, default=20260925)
    args = parser.parse_args()

    if not RUST_BIN.exists():
        print(f"error: Rust binary not built at {RUST_BIN}", file=sys.stderr)
        print("build it with:  cd rust && cargo build --release", file=sys.stderr)
        return 2

    examples = sorted((ROOT / "examples").glob("*.sfs"))
    if not examples:
        print("error: no example policies found", file=sys.stderr)
        return 2

    failures: list[str] = []
    comparisons = 0

    print("=" * 64)
    print(" Cross-implementation conformance: Python reference vs Rust port")
    print("=" * 64)
    print()

    print("compile:")
    for ex in examples:
        compare(f"compile {ex.name}", ["compile", str(ex.relative_to(ROOT))], failures)
        comparisons += 1
        print(f"  {ex.name}")

    print()
    print("malformed policies (diagnostics must agree):")
    bad_dir = ROOT / "rust" / "target" / "conformance-tmp"
    bad_dir.mkdir(parents=True, exist_ok=True)
    malformed = {
        "missing_policy.sfs": 'VERSION 1\nON EXEC("x")\nDENY\n',
        "missing_version.sfs": 'POLICY p\nON EXEC("x")\nDENY\n',
        "missing_on.sfs": 'POLICY p\nVERSION 1\nEXEC("x")\nDENY\n',
        "missing_action.sfs": 'POLICY p\nVERSION 1\nON EXEC("x")\n',
        "unknown_event.sfs": 'POLICY p\nVERSION 1\nON FOO("x")\nDENY\n',
        "removed_spawn.sfs": 'POLICY p\nVERSION 1\nON SPAWN("/bin/bash")\nDENY\n',
        "trailing_tokens.sfs": 'POLICY p\nVERSION 1\nON EXEC("x")\nDENY\nEXTRA\n',
        "unterminated_string.sfs": 'POLICY p\nVERSION 1\nON EXEC("x\nDENY\n',
        "bad_character.sfs": 'POLICY foo$bar\nVERSION 1\nON EXEC("x")\nDENY\n',
        "zero_version.sfs": 'POLICY p\nVERSION 0\nON EXEC("x")\nDENY\n',
        "empty_argument.sfs": 'POLICY p\nVERSION 1\nON EXEC("")\nDENY\n',
    }
    for name, body in malformed.items():
        path = bad_dir / name
        path.write_text(body)
        compare(f"compile {name}", ["compile", str(path.relative_to(ROOT))], failures)
        comparisons += 1
        print(f"  {name}")

    print()
    print(f"traces ({args.traces} per policy):")
    rng = random.Random(args.seed)
    for ex in examples:
        rel = str(ex.relative_to(ROOT))
        for i in range(args.traces):
            length = rng.randint(0, 8)
            trace = [event_literal(rng) for _ in range(length)]
            if not trace:
                continue  # the CLI requires at least one event
            compare(f"run {ex.name} #{i}", ["run", rel, "--trace", *trace], failures)
            comparisons += 1
        print(f"  {ex.name}: done")

    print()
    print("=" * 64)
    if failures:
        print(f" {len(failures)} DIVERGENCE(S) in {comparisons} comparisons")
        print("=" * 64)
        for f in failures[:10]:
            print()
            print(f)
        if len(failures) > 10:
            print(f"\n... and {len(failures) - 10} more")
        print()
        print(" A divergence means one implementation does not conform to the")
        print(" specification. Investigate; do not adjust the specification to match.")
        return 1

    print(f" NO DIVERGENCE across {comparisons} comparisons")
    print("=" * 64)
    print()
    print(" The Rust port produces byte-identical output to the Python reference")
    print(" for every policy and trace tested, including diagnostics for malformed")
    print(" policies. This is conformance evidence, not a proof of equivalence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
