import pytest

from sentinelfs.dsl.ast_nodes import Event
from sentinelfs.dsl.errors import CompileError
from sentinelfs.dsl.parser import parse_source

SHADOW = '''POLICY protect_shadow
VERSION 1

ON EXEC("/usr/bin/python3")
THEN SPAWN("/bin/bash")
THEN WRITE("/etc/shadow")
DENY
'''


def test_parses_full_policy():
    policy = parse_source(SHADOW)
    assert policy.name == "protect_shadow"
    assert policy.version == 1
    assert policy.sequence == (
        Event("EXEC", "/usr/bin/python3"),
        Event("SPAWN", "/bin/bash"),
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
