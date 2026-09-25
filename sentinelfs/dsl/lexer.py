from dataclasses import dataclass

from .errors import CompileError

EVENT_TYPES = ("EXEC", "WRITE", "OPEN", "DELETE")
ACTIONS = ("DENY", "ALERT", "ALLOW")
KEYWORDS = frozenset(("POLICY", "VERSION", "ON", "THEN", *ACTIONS, *EVENT_TYPES))


@dataclass(frozen=True)
class Token:
    type: str
    value: str
    line: int


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    line = 1
    n = len(source)

    while i < n:
        c = source[i]

        if c == "\n":
            line += 1
            i += 1
            continue

        if c.isspace():
            i += 1
            continue

        if c == '"':
            j = i + 1
            buf = []
            while j < n and source[j] != '"':
                if source[j] == "\n":
                    raise CompileError("Unterminated string literal", line)
                buf.append(source[j])
                j += 1
            if j >= n:
                raise CompileError("Unterminated string literal", line)
            tokens.append(Token("STRING", "".join(buf), line))
            i = j + 1
            continue

        if c == "(":
            tokens.append(Token("LPAREN", "(", line))
            i += 1
            continue

        if c == ")":
            tokens.append(Token("RPAREN", ")", line))
            i += 1
            continue

        if c.isdigit():
            j = i
            while j < n and source[j].isdigit():
                j += 1
            tokens.append(Token("NUMBER", source[i:j], line))
            i = j
            continue

        if c.isalpha() or c == "_":
            j = i
            while j < n and (source[j].isalnum() or source[j] == "_"):
                j += 1
            word = source[i:j]
            tok_type = word if word in KEYWORDS else "IDENT"
            tokens.append(Token(tok_type, word, line))
            i = j
            continue

        raise CompileError(f"Unexpected character {c!r}", line)

    tokens.append(Token("EOF", "", line))
    return tokens
