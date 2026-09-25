import pytest

from sentinelfs.dsl.ast_nodes import Event
from sentinelfs.dsl.errors import CompileError
from sentinelfs.dsl.parser import parse_source

SHADOW = '''POLICY protect_shadow
VERSION 1

ON EXEC("/usr/bin/python3")
THEN EXEC("/bin/bash")
THEN WRITE("/etc/shadow")
DENY
'''


def test_parses_full_policy():
    policy = parse_source(SHADOW)
    assert policy.name == "protect_shadow"
    assert policy.version == 1
    assert policy.sequence == (
        Event("EXEC", "/usr/bin/python3"),
        Event("EXEC", "/bin/bash"),
        Event("WRITE", "/etc/shadow"),
    )
    assert policy.action == "DENY"


def test_alert_only_policy():
    policy = parse_source('POLICY monitor\nVERSION 1\nON OPEN("/etc/shadow")\nALERT\n')
    assert policy.sequence == (Event("OPEN", "/etc/shadow"),)
    assert policy.action == "ALERT"


@pytest.mark.parametrize(
    "bad_source",
    [
        'VERSION 1\nON EXEC("x")\nDENY\n',  # missing POLICY
        'POLICY p\nON EXEC("x")\nDENY\n',  # missing VERSION
        'POLICY p\nVERSION 1\nEXEC("x")\nDENY\n',  # missing ON
        'POLICY p\nVERSION 1\nON EXEC("x")\n',  # missing action
        'POLICY p\nVERSION 1\nON FOO("x")\nDENY\n',  # unknown event type
        'POLICY p\nVERSION 1\nON EXEC("x")\nDENY\nEXTRA\n',  # trailing tokens
    ],
)
def test_invalid_policies_raise(bad_source):
    with pytest.raises(CompileError):
        parse_source(bad_source)


def test_spawn_is_not_in_the_v1_alphabet():
    """SPAWN was removed after the Phase 2 study showed it is unobservable:
    at fork time the kernel cannot name the binary the child will execute.
    See docs/phase2-findings.md section 4.1."""
    with pytest.raises(CompileError):
        parse_source('POLICY p\nVERSION 1\nON SPAWN("/bin/bash")\nDENY\n')


def test_admitted_event_types_are_exactly_the_observable_four():
    from sentinelfs.dsl.lexer import EVENT_TYPES
    assert set(EVENT_TYPES) == {"EXEC", "WRITE", "OPEN", "DELETE"}

def test_allow_is_not_in_the_action_domain():
    """ALLOW was removed from the action grammar.

    It was decision-inert: Definition 3 returned the policy's action when the
    trace violated it and ALLOW otherwise, so for an ALLOW-action policy both
    branches gave ALLOW and the decision could not distinguish a policy that
    fired from one that did not.

    Reading it instead as an affirmative override was not available: under the
    monotone trace semantics of Definition 1 and the absorbing violation state
    of Theorem 3, a single match would have suppressed denial host-wide for the
    remaining lifetime of the policy set. See docs/phase5b0f-decision-domain.md.
    """
    with pytest.raises(CompileError):
        parse_source('POLICY p\nVERSION 1\nON EXEC("/bin/sh")\nALLOW\n')


def test_admitted_actions_are_exactly_deny_and_alert():
    from sentinelfs.dsl.lexer import ACTIONS
    assert set(ACTIONS) == {"DENY", "ALERT"}


def test_allow_remains_a_decision_although_not_an_action():
    """Removing the action does not remove the decision.

    ALLOW is still what Definition 3 returns when no violation was established,
    which is the outcome for every non-violating trace.
    """
    from sentinelfs.compiler.automaton import compile_policy
    from sentinelfs.runtime.executor import run_trace

    policy = parse_source('POLICY p\nVERSION 1\nON EXEC("/bin/sh")\nDENY\n')
    automaton = compile_policy(policy)
    result = run_trace(automaton, [Event("EXEC", "/bin/other")])

    assert result.triggered is False
    assert result.decision == "ALLOW"
