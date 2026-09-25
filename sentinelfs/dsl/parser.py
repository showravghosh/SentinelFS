from .ast_nodes import Event, Policy
from .errors import CompileError
from .lexer import ACTIONS, EVENT_TYPES, Token, tokenize


class _Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token:
        return self.tokens[self.pos]

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, tok_type: str) -> Token:
        tok = self.peek()
        if tok.type != tok_type:
            raise CompileError(
                f"Expected {tok_type} but found {tok.type} {tok.value!r}", tok.line
            )
        return self.advance()

    def parse_policy(self) -> Policy:
        self.expect("POLICY")
        name = self.expect("IDENT").value
        self.expect("VERSION")
        version = int(self.expect("NUMBER").value)
        self.expect("ON")
        sequence = [self.parse_event()]
        while self.peek().type == "THEN":
            self.advance()
            sequence.append(self.parse_event())

        if self.peek().type not in ACTIONS:
            tok = self.peek()
            raise CompileError(
                f"Expected DENY or ALERT but found {tok.type} {tok.value!r}",
                tok.line,
            )
        action = self.advance().type
        self.expect("EOF")
        return Policy(name=name, version=version, sequence=tuple(sequence), action=action)

    def parse_event(self) -> Event:
        tok = self.peek()
        if tok.type not in EVENT_TYPES:
            raise CompileError(
                f"Expected an event ({'/'.join(EVENT_TYPES)}) but found {tok.type} {tok.value!r}",
                tok.line,
            )
        event_type = self.advance().type
        self.expect("LPAREN")
        arg = self.expect("STRING").value
        self.expect("RPAREN")
        return Event(type=event_type, arg=arg)


def parse(tokens: list[Token]) -> Policy:
    return _Parser(tokens).parse_policy()


def parse_source(source: str) -> Policy:
    return parse(tokenize(source))
