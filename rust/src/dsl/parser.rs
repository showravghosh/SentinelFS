use super::ast::{Action, Event, EventType, Policy};
use super::errors::{CompileError, Result};
use super::lexer::{tokenize, Token, TokenKind};

/// Recursive-descent parser for the grammar of `formal-semantics.md` section 2.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens[self.pos].clone();
        self.pos += 1;
        tok
    }

    /// Whether a token is of the expected kind. Kinds that carry a payload match
    /// on the kind alone, since `expect` is asking for a category of token, not a
    /// particular identifier or literal.
    fn kind_matches(actual: &TokenKind, expected: &TokenKind) -> bool {
        matches!(
            (actual, expected),
            (TokenKind::Policy, TokenKind::Policy)
                | (TokenKind::Version, TokenKind::Version)
                | (TokenKind::On, TokenKind::On)
                | (TokenKind::Then, TokenKind::Then)
                | (TokenKind::LParen, TokenKind::LParen)
                | (TokenKind::RParen, TokenKind::RParen)
                | (TokenKind::Eof, TokenKind::Eof)
                | (TokenKind::Ident(_), TokenKind::Ident(_))
                | (TokenKind::Number(_), TokenKind::Number(_))
                | (TokenKind::Str(_), TokenKind::Str(_))
        )
    }

    fn expect(&mut self, expected: &TokenKind) -> Result<Token> {
        let tok = self.peek();
        if !Self::kind_matches(&tok.kind, expected) {
            return Err(CompileError::at_line(
                format!(
                    "Expected {} but found {} {:?}",
                    expected.type_name(),
                    tok.kind.type_name(),
                    tok.kind.value()
                ),
                tok.line,
            ));
        }
        Ok(self.advance())
    }

    fn parse_policy(&mut self) -> Result<Policy> {
        self.expect(&TokenKind::Policy)?;
        let name = match self.expect(&TokenKind::Ident(String::new()))?.kind {
            TokenKind::Ident(s) => s,
            _ => unreachable!("expect(Ident) returned a non-identifier"),
        };

        self.expect(&TokenKind::Version)?;
        let version_tok = self.expect(&TokenKind::Number(String::new()))?;
        let version: u32 = match &version_tok.kind {
            TokenKind::Number(s) => s.parse().map_err(|_| {
                CompileError::at_line(format!("Version {s} is out of range"), version_tok.line)
            })?,
            _ => unreachable!("expect(Number) returned a non-number"),
        };

        self.expect(&TokenKind::On)?;
        let mut sequence = vec![self.parse_event()?];
        while matches!(self.peek().kind, TokenKind::Then) {
            self.advance();
            sequence.push(self.parse_event()?);
        }

        let action = match self.peek().kind {
            TokenKind::Action(a) => {
                self.advance();
                a
            }
            _ => {
                let tok = self.peek();
                return Err(CompileError::at_line(
                    format!(
                        "Expected DENY, ALERT or ALLOW but found {} {:?}",
                        tok.kind.type_name(),
                        tok.kind.value()
                    ),
                    tok.line,
                ));
            }
        };

        self.expect(&TokenKind::Eof)?;
        Ok(Policy { name, version, sequence, action })
    }

    fn parse_event(&mut self) -> Result<Event> {
        let event_type = match self.peek().kind {
            TokenKind::Event(t) => {
                self.advance();
                t
            }
            _ => {
                let tok = self.peek();
                let names: Vec<&str> = EventType::ALL.iter().map(|t| t.as_str()).collect();
                return Err(CompileError::at_line(
                    format!(
                        "Expected an event ({}) but found {} {:?}",
                        names.join("/"),
                        tok.kind.type_name(),
                        tok.kind.value()
                    ),
                    tok.line,
                ));
            }
        };

        self.expect(&TokenKind::LParen)?;
        let arg = match self.expect(&TokenKind::Str(String::new()))?.kind {
            TokenKind::Str(s) => s,
            _ => unreachable!("expect(Str) returned a non-string"),
        };
        self.expect(&TokenKind::RParen)?;

        Ok(Event { event_type, arg })
    }
}

pub fn parse(tokens: Vec<Token>) -> Result<Policy> {
    Parser::new(tokens).parse_policy()
}

pub fn parse_source(source: &str) -> Result<Policy> {
    parse(tokenize(source)?)
}

/// Parse an event in surface syntax, e.g. `EXEC("/bin/sh")`.
///
/// Used by the command-line interface to read trace elements. It accepts exactly
/// one event and nothing else.
pub fn parse_event_literal(text: &str) -> Result<Event> {
    let tokens = tokenize(text)?;
    let mut parser = Parser::new(tokens);
    let event = parser.parse_event()?;
    parser.expect(&TokenKind::Eof)?;
    Ok(event)
}

// Keep the Action import used by the grammar documentation above honest.
const _: Option<Action> = None;
