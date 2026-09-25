"""Conformance tests for docs/formal-semantics.md.

Each test corresponds to a numbered result in the specification. These check that the
implementation conforms to the formal model; they do not prove the results themselves,
which are established in the document. A failure here means the code has diverged from
the specification, not that the mathematics is wrong.
"""

import random

import pytest

from sentinelfs.compiler.automaton import compile_policy
from sentinelfs.dsl.ast_nodes import Event, Policy
from sentinelfs.dsl.errors import CompileError
from sentinelfs.dsl.parser import parse_source
from sentinelfs.dsl.validator import validate
from sentinelfs.runtime.executor import run_trace

POLICY_SOURCES = [
    '''POLICY protect_shadow
VERSION 1
ON EXEC("/usr/bin/python3")
THEN SPAWN("/bin/bash")
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
    '''POLICY repeated_event
VERSION 1
ON WRITE("/etc/hosts")
THEN WRITE("/etc/hosts")
THEN WRITE("/etc/hosts")
DENY
''',
]

NOISE = [
    Event("OPEN", "/var/log/syslog"),
    Event("EXEC", "/usr/bin/curl"),
    Event("DELETE", "/tmp/scratch"),
    Event("WRITE", "/tmp/scratch"),
    Event("SPAWN", "/usr/bin/env"),
]


@pytest.fixture(params=POLICY_SOURCES, ids=lambda s: s.split()[1])
def policy(request):
    return parse_source(request.param)


def embeds(pattern: list[Event], trace: list[Event]) -> bool:
    """Definition 1: pattern occurs in trace in order, not necessarily contiguously."""
    k = 0
    for event in trace:
        if k < len(pattern) and event == pattern[k]:
            k += 1
    return k == len(pattern)


def match_index(pattern: list[Event], trace: list[Event]) -> int:
    """match(tau) of Lemma 1: length of the longest pattern prefix embedding in trace."""
    k = 0
    for event in trace:
        if k < len(pattern) and event == pattern[k]:
            k += 1
    return k


def spec_delta_star(policy: Policy, trace: list[Event]) -> str:
    """Definition 6 applied directly, draining the whole trace with no early exit."""
    pattern = list(policy.sequence)
    n = len(pattern)
    i = 0
    for event in trace:
        if i < n and event == pattern[i]:
            i += 1
        # otherwise self-loop (i < n) or absorbing (i == n): state unchanged
    return f"q{i}"


def random_trace(rng: random.Random, policy: Policy, max_len: int = 12) -> list[Event]:
    pool = list(policy.sequence) + NOISE
    return [rng.choice(pool) for _ in range(rng.randint(0, max_len))]


# --- Theorem 1: determinism -------------------------------------------------------

def test_theorem1_transition_function_is_total_and_single_valued(policy):
    """delta is defined for every (state, event) pair and yields exactly one successor."""
    automaton = compile_policy(policy)
    alphabet = list(policy.sequence) + NOISE

    for state in automaton.states:
        for event in alphabet:
            edge = automaton.transition_from(state)
            successors = {edge.to_state} if (edge and edge.event == event) else {state}
            assert len(successors) == 1

        outgoing = [t for t in automaton.transitions if t.from_state == state]
        assert len(outgoing) <= 1, f"{state} has multiple advancing edges"


def test_theorem1_repeated_evaluation_is_identical(policy):
    """Corollary 1.1: same policy and trace always yield the same state and decision."""
    rng = random.Random(7)
    automaton = compile_policy(policy)

    for _ in range(50):
        trace = random_trace(rng, policy)
        results = [run_trace(automaton, trace) for _ in range(5)]
        states = {r.final_state for r in results}
        decisions = {r.decision for r in results}
        assert len(states) == 1, f"nondeterministic state: {states}"
        assert len(decisions) == 1, f"nondeterministic decision: {decisions}"


def test_theorem1_recompilation_is_stable(policy):
    """Compiling the same policy twice yields the same automaton."""
    a, b = compile_policy(policy), compile_policy(policy)
    assert a == b


# --- Lemma 1: state characterisation ---------------------------------------------

def test_lemma1_state_equals_match_index(policy):
    """delta*(q0, tau) = q_match(tau), computed against an independent oracle."""
    rng = random.Random(11)
    automaton = compile_policy(policy)
    pattern = list(policy.sequence)

    for _ in range(300):
        trace = random_trace(rng, policy)
        expected = f"q{match_index(pattern, trace)}"
        actual = run_trace(automaton, trace).final_state
        assert actual == expected, (
            f"Lemma 1 violated on {[e.label() for e in trace]}: "
            f"expected {expected}, got {actual}"
        )


# --- Theorem 2: compilation correctness -------------------------------------------

def test_theorem2_acceptance_iff_violation(policy):
    """tau |= P  <=>  C(P) accepts tau."""
    rng = random.Random(13)
    automaton = compile_policy(policy)
    pattern = list(policy.sequence)

    for _ in range(300):
        trace = random_trace(rng, policy)
        violates = embeds(pattern, trace)
        accepts = run_trace(automaton, trace).triggered
        assert violates == accepts, (
            f"Theorem 2 violated on {[e.label() for e in trace]}: "
            f"models={violates}, accepts={accepts}"
        )


def test_corollary_2_1_decision_matches_definition_3(policy):
    """Executed decision equals D(P, tau) of Definition 3."""
    rng = random.Random(17)
    automaton = compile_policy(policy)
    pattern = list(policy.sequence)

    for _ in range(300):
        trace = random_trace(rng, policy)
        expected = policy.action if embeds(pattern, trace) else "ALLOW"
        assert run_trace(automaton, trace).decision == expected


# --- Theorem 3: absorption and sound halting --------------------------------------

def test_theorem3_violation_state_is_absorbing(policy):
    """Once q_n is reached, no extension of the trace leaves it."""
    rng = random.Random(19)
    automaton = compile_policy(policy)
    base = list(policy.sequence)  # reaches q_n by construction

    assert run_trace(automaton, base).final_state == automaton.final_state

    for _ in range(100):
        suffix = [rng.choice(list(policy.sequence) + NOISE) for _ in range(rng.randint(1, 6))]
        result = run_trace(automaton, base + suffix)
        assert result.final_state == automaton.final_state
        assert result.decision == policy.action


def test_corollary_3_1_early_exit_agrees_with_full_drain(policy):
    """Halting at q_n computes the same state as draining the entire trace."""
    rng = random.Random(23)
    automaton = compile_policy(policy)

    for _ in range(300):
        trace = random_trace(rng, policy)
        assert run_trace(automaton, trace).final_state == spec_delta_star(policy, trace)


# --- Corollary 4: enforcement soundness -------------------------------------------

def test_corollary4_violation_never_yields_allow(policy):
    """For DENY/ALERT policies, a violating trace never produces ALLOW."""
    if policy.action == "ALLOW":
        pytest.skip("Corollary 4 is stated for DENY/ALERT policies only")

    rng = random.Random(29)
    automaton = compile_policy(policy)
    pattern = list(policy.sequence)
    checked = 0

    for _ in range(400):
        trace = random_trace(rng, policy)
        if not embeds(pattern, trace):
            continue
        checked += 1
        assert run_trace(automaton, trace).decision != "ALLOW"

    assert checked > 0, "no violating traces generated; test would be vacuous"


# --- Section 2.1: well-formedness WF1-WF4 -----------------------------------------

def test_wf1_empty_pattern_rejected():
    with pytest.raises(CompileError):
        validate(Policy(name="p", version=1, sequence=(), action="DENY"))


def test_wf2_version_must_be_positive():
    with pytest.raises(CompileError):
        validate(Policy(name="p", version=0, sequence=(Event("EXEC", "/bin/sh"),), action="DENY"))


def test_wf3_name_must_be_non_empty():
    with pytest.raises(CompileError):
        validate(Policy(name="", version=1, sequence=(Event("EXEC", "/bin/sh"),), action="DENY"))


def test_wf4_event_argument_must_be_non_empty():
    with pytest.raises(CompileError):
        validate(Policy(name="p", version=1, sequence=(Event("EXEC", ""),), action="DENY"))


# --- Section 5: compiler is linear in pattern length ------------------------------

def test_compiler_produces_n_plus_one_states(policy):
    automaton = compile_policy(policy)
    n = len(policy.sequence)
    assert len(automaton.states) == n + 1
    assert len(automaton.transitions) == n
    assert automaton.final_state == f"q{n}"
