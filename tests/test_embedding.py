"""Independent check that greedy matching coincides with the existential semantics.

Definition 1 of docs/formal-semantics.md defines violation existentially:

    tau |= P  iff  there EXIST indices j_1 < j_2 < ... < j_n with tau[j_k] = e_k.

Both the compiled automaton and the reference oracle in test_semantics.py decide this
by scanning left to right and advancing on the first match. That the two coincide is
the content of Lemma 1, and it is proved there - but a differential test between two
greedy implementations cannot establish it, since both share the assumption.

These tests close that gap empirically by deciding the existential question directly,
enumerating index combinations rather than scanning. That is exponential, so traces are
kept short; the point is independence from the greedy strategy, not scale.
"""

from __future__ import annotations

import itertools
import random

import pytest

from sentinelfs.compiler.automaton import compile_policy
from sentinelfs.dsl.ast_nodes import Event, Policy
from sentinelfs.runtime.executor import run_trace

ALPHABET = [
    Event("EXEC", "/bin/a"),
    Event("EXEC", "/bin/b"),
    Event("WRITE", "/f"),
    Event("OPEN", "/f"),
]


def embeds_existentially(pattern: list[Event], trace: list[Event]) -> bool:
    """Decide Definition 1 directly: enumerate strictly increasing index tuples and
    ask whether any of them witnesses the embedding. No greedy scanning."""
    n = len(pattern)
    if n == 0:
        return True
    if n > len(trace):
        return False
    for indices in itertools.combinations(range(len(trace)), n):
        if all(trace[j] == pattern[k] for k, j in enumerate(indices)):
            return True
    return False


def embeds_greedily(pattern: list[Event], trace: list[Event]) -> bool:
    """The greedy strategy, stated separately so the two can be compared."""
    k = 0
    for event in trace:
        if k < len(pattern) and event == pattern[k]:
            k += 1
    return k == len(pattern)


@pytest.mark.parametrize("pattern_len", [1, 2, 3])
def test_greedy_coincides_with_existential_semantics(pattern_len):
    """Lemma 1's substance, checked without assuming it: over every short trace,
    the greedy decision agrees with the existential one."""
    rng = random.Random(4242)
    for _ in range(400):
        pattern = [rng.choice(ALPHABET) for _ in range(pattern_len)]
        trace = [rng.choice(ALPHABET) for _ in range(rng.randint(0, 7))]
        assert embeds_greedily(pattern, trace) == embeds_existentially(pattern, trace), (
            f"greedy and existential disagree on pattern "
            f"{[e.label() for e in pattern]} trace {[e.label() for e in trace]}"
        )


@pytest.mark.parametrize("pattern_len", [1, 2, 3])
def test_automaton_decides_the_existential_semantics(pattern_len):
    """Theorem 2 against an oracle that does not share the automaton's strategy:
    the compiled automaton accepts exactly the traces that existentially embed."""
    rng = random.Random(99)
    for _ in range(400):
        pattern = [rng.choice(ALPHABET) for _ in range(pattern_len)]
        policy = Policy(name="p", version=1, sequence=tuple(pattern), action="DENY")
        automaton = compile_policy(policy)

        trace = [rng.choice(ALPHABET) for _ in range(rng.randint(0, 7))]
        expected = embeds_existentially(pattern, trace)
        actual = run_trace(automaton, trace).triggered
        assert actual == expected, (
            f"Theorem 2 fails against the existential oracle: pattern "
            f"{[e.label() for e in pattern]} trace {[e.label() for e in trace]}: "
            f"existential={expected}, automaton={actual}"
        )


def test_exhaustive_over_small_alphabet():
    """Exhaustive rather than random, over every trace up to length 5 drawn from a
    two-symbol alphabet, for a repeated pattern - the case where greedy strategies
    are most likely to differ from existential ones."""
    a, b = ALPHABET[0], ALPHABET[1]
    small = [a, b]
    pattern = [a, b, a]
    policy = Policy(name="p", version=1, sequence=tuple(pattern), action="DENY")
    automaton = compile_policy(policy)

    checked = 0
    for length in range(6):
        for combo in itertools.product(small, repeat=length):
            trace = list(combo)
            expected = embeds_existentially(pattern, trace)
            assert run_trace(automaton, trace).triggered == expected, (
                f"disagreement on {[e.label() for e in trace]}"
            )
            checked += 1
    assert checked == sum(2**i for i in range(6))
