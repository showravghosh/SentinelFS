import pytest

from sentinelfs.dsl.errors import CompileError
from sentinelfs.dsl.lexer import tokenize

SHADOW = '''POLICY protect_shadow
VERSION 1

ON EXEC("/usr/bin/python3")
THEN EXEC("/bin/bash")
THEN WRITE("/etc/shadow")
DENY
'''


def test_tokenizes_keywords_and_literals():
    tokens = tokenize(SHADOW)
    types = [t.type for t in tokens]
    assert types[:6] == ["POLICY", "IDENT", "VERSION", "NUMBER", "ON", "EXEC"]
    assert types[-1] == "EOF"


def test_string_literal_value():
    tokens = tokenize('EXEC("/usr/bin/python3")')
    strings = [t.value for t in tokens if t.type == "STRING"]
    assert strings == ["/usr/bin/python3"]


def test_unterminated_string_raises():
    with pytest.raises(CompileError):
        tokenize('EXEC("/usr/bin/python3')


def test_unexpected_character_raises():
    with pytest.raises(CompileError):
        tokenize("POLICY foo$bar")
