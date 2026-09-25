"""Stage 6 - formal test suite.

Checks the compilation-correctness claim experimentally: for many randomly
generated event traces, the compiled DFA's decision must agree with an
independent reference semantics defined directly on the policy AST (does the
required event sequence occur, in order, as a subsequence of the trace -
arbitrary other events interleaved are allowed).

This does not replace a formal proof; it is evidence supporting it, and a
counterexample here would immediately falsify the compilation-correctness
theorem for the tested policies.
"""

import random

from sentinelfs.compiler.automaton import compile_policy
from sentinelfs.dsl.ast_nodes import Event, Policy
from sentinelfs.dsl.parser import parse_source
from sentinelfs.runtime.executor import run_trace

POLICIES = [
    '''POLICY protect_shadow
VERSION 1
ON EXEC("/usr/bin/python3")
THEN EXEC("/bin/bash")
THEN WRITE("/etc/shadow")
DENY
''',
    '''POLICY protect_passwd
VERSION 1
ON EXEC("/bin/bash")
THEN WRITE("/etc/passwd")
DENY
''',
    '''POLICY monitor_sensitive_file
VERSION 1
ON OPEN("/etc/shadow")
ALERT
''',
]

NOISE_EVENTS = [
    Event("OPEN", "/var/log/syslog"),
    Event("EXEC", "/usr/bin/curl"),
    Event("DELETE", "/tmp/scratch"),
    Event("WRITE", "/tmp/scratch"),
    Event("EXEC", "/usr/bin/env"),
]


def reference_decision(policy: Policy, trace: list[Event]) -> str:
    """Independent semantics: policy.sequence must occur as an in-order
    subsequence of trace. This is defined directly on the AST, without
    going through the compiler, so it is a fair oracle for the DFA."""
    needle = list(policy.sequence)
    k = 0
    for event in trace:
        if k < len(needle) and event == needle[k]:
            k += 1
            if k == len(needle):
                return policy.action
    return "ALLOW"


def random_trace(rng: random.Random, policy: Policy, max_len: int) -> list[Event]:
    pool = list(policy.sequence) + NOISE_EVENTS
    length = rng.randint(0, max_len)
    return [rng.choice(pool) for _ in range(length)]


def test_dfa_matches_reference_semantics_on_random_traces():
    rng = random.Random(1337)
    trials_per_policy = 500

    for source in POLICIES:
        policy = parse_source(source)
        automaton = compile_policy(policy)

        for _ in range(trials_per_policy):
            trace = random_trace(rng, policy, max_len=10)
            expected = reference_decision(policy, trace)
            actual = run_trace(automaton, trace).decision
            assert actual == expected, (
                f"Mismatch for policy {policy.name} on trace "
                f"{[e.label() for e in trace]}: expected {expected}, got {actual}"
            )


def test_dfa_matches_reference_semantics_including_exact_matches():
    # Force some traces to be exact matches (the highest-value case) rather
    # than relying only on random chance to produce them.
    rng = random.Random(42)
    for source in POLICIES:
        policy = parse_source(source)
        automaton = compile_policy(policy)
        exact_trace = list(policy.sequence)
        assert run_trace(automaton, exact_trace).decision == policy.action

        for _ in range(200):
            noisy = []
            for event in policy.sequence:
                if rng.random() < 0.5:
                    noisy.append(rng.choice(NOISE_EVENTS))
                noisy.append(event)
            expected = reference_decision(policy, noisy)
            actual = run_trace(automaton, noisy).decision
            assert actual == expected
