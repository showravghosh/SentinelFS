import pytest

from sentinelfs.compiler.automaton import compile_policy
from sentinelfs.dsl.ast_nodes import Event
from sentinelfs.dsl.parser import parse_source
from sentinelfs.runtime.executor import run_trace

SHADOW = '''POLICY protect_shadow
VERSION 1

ON EXEC("/usr/bin/python3")
THEN EXEC("/bin/bash")
THEN WRITE("/etc/shadow")
DENY
'''


@pytest.fixture
def shadow_automaton():
    return compile_policy(parse_source(SHADOW))


def test_full_matching_trace_denies(shadow_automaton):
    trace = [
        Event("EXEC", "/usr/bin/python3"),
        Event("EXEC", "/bin/bash"),
        Event("WRITE", "/etc/shadow"),
    ]
    result = run_trace(shadow_automaton, trace)
    assert result.final_state == "q3"
    assert result.triggered is True
    assert result.decision == "DENY"


def test_prefix_only_allows(shadow_automaton):
    trace = [Event("EXEC", "/usr/bin/python3")]
    result = run_trace(shadow_automaton, trace)
    assert result.final_state == "q1"
    assert result.triggered is False
    assert result.decision == "ALLOW"


def test_wrong_final_target_allows(shadow_automaton):
    trace = [
        Event("EXEC", "/usr/bin/python3"),
        Event("EXEC", "/bin/bash"),
        Event("WRITE", "/tmp/test.txt"),
    ]
    result = run_trace(shadow_automaton, trace)
    assert result.final_state == "q2"
    assert result.triggered is False
    assert result.decision == "ALLOW"


def test_noise_events_do_not_block_detection(shadow_automaton):
    trace = [
        Event("OPEN", "/var/log/syslog"),
        Event("EXEC", "/usr/bin/python3"),
        Event("OPEN", "/var/log/syslog"),
        Event("EXEC", "/bin/bash"),
        Event("OPEN", "/var/log/syslog"),
        Event("WRITE", "/etc/shadow"),
    ]
    result = run_trace(shadow_automaton, trace)
    assert result.triggered is True
    assert result.decision == "DENY"


def test_empty_trace_allows(shadow_automaton):
    result = run_trace(shadow_automaton, [])
    assert result.triggered is False
    assert result.decision == "ALLOW"


def test_events_after_violation_do_not_change_decision(shadow_automaton):
    trace = [
        Event("EXEC", "/usr/bin/python3"),
        Event("EXEC", "/bin/bash"),
        Event("WRITE", "/etc/shadow"),
        Event("DELETE", "/var/log/audit.log"),
    ]
    result = run_trace(shadow_automaton, trace)
    assert result.decision == "DENY"
    assert len(result.path) == 3  # halts at the violation state
