from sentinelfs.compiler.automaton import compile_policy
from sentinelfs.dsl.ast_nodes import Event
from sentinelfs.dsl.parser import parse_source

SHADOW = '''POLICY protect_shadow
VERSION 1

ON EXEC("/usr/bin/python3")
THEN SPAWN("/bin/bash")
THEN WRITE("/etc/shadow")
DENY
'''


def test_compiles_to_expected_states_and_transitions():
    automaton = compile_policy(parse_source(SHADOW))
    assert automaton.states == ("q0", "q1", "q2", "q3")
    assert automaton.final_state == "q3"
    assert automaton.action == "DENY"
    assert [t.event for t in automaton.transitions] == [
        Event("EXEC", "/usr/bin/python3"),
        Event("SPAWN", "/bin/bash"),
        Event("WRITE", "/etc/shadow"),
    ]


def test_each_state_has_at_most_one_outgoing_edge():
    automaton = compile_policy(parse_source(SHADOW))
    for state in automaton.states:
        outgoing = [t for t in automaton.transitions if t.from_state == state]
        assert len(outgoing) <= 1
