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
