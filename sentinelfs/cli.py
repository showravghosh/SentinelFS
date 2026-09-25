"""SentinelFS Milestone 1 CLI: compile a policy and run it against a trace.

Usage:
    python -m sentinelfs.cli compile examples/protect_shadow.sfs
    python -m sentinelfs.cli run examples/protect_shadow.sfs \
        --trace 'EXEC("/usr/bin/python3")' 'SPAWN("/bin/bash")' 'WRITE("/etc/shadow")'
"""

from __future__ import annotations

import argparse
import re
import sys

from sentinelfs.compiler.automaton import Automaton, compile_policy
from sentinelfs.dsl.ast_nodes import Event
from sentinelfs.dsl.errors import CompileError
from sentinelfs.dsl.parser import parse_source
from sentinelfs.runtime.executor import run_trace

_EVENT_RE = re.compile(r'^([A-Z]+)\("([^"]*)"\)$')


def parse_event_literal(text: str) -> Event:
    m = _EVENT_RE.match(text.strip())
    if not m:
        raise ValueError(f"Malformed event literal: {text!r}")
    return Event(type=m.group(1), arg=m.group(2))


def describe_automaton(automaton: Automaton) -> str:
    lines = [f"Policy: {automaton.policy_name}  Version: {automaton.policy_version}"]
    for t in automaton.transitions:
        lines.append(f"  {t.from_state} --{t.event.label()}--> {t.to_state}")
    lines.append(f"  {automaton.final_state} = VIOLATION -> {automaton.action}")
    return "\n".join(lines)


def cmd_compile(args: argparse.Namespace) -> int:
    source = open(args.policy_file, encoding="utf-8").read()
    try:
        policy = parse_source(source)
        automaton = compile_policy(policy)
    except CompileError as e:
        print(f"Compile error: {e}", file=sys.stderr)
        return 1
    print(describe_automaton(automaton))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    source = open(args.policy_file, encoding="utf-8").read()
    try:
        policy = parse_source(source)
        automaton = compile_policy(policy)
        trace = [parse_event_literal(t) for t in args.trace]
    except (CompileError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    result = run_trace(automaton, trace)
    for step in result.path:
        mark = "matched" if step.matched else "ignored"
        print(f"  {step.event.label():45s} {step.from_state} -> {step.to_state}  ({mark})")
    print(f"Final State: {result.final_state}")
    print(f"Decision: {result.decision}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="sentinelfs")
    sub = parser.add_subparsers(dest="command", required=True)

    p_compile = sub.add_parser("compile", help="compile a .sfs policy to its automaton")
    p_compile.add_argument("policy_file")
    p_compile.set_defaults(func=cmd_compile)

    p_run = sub.add_parser("run", help="run an event trace against a compiled policy")
    p_run.add_argument("policy_file")
    p_run.add_argument("--trace", nargs="+", required=True, help='e.g. EXEC("/bin/bash")')
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
