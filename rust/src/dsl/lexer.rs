use super::ast::{Action, EventType};
use super::errors::{CompileError, Result};

/// Token kinds. `Keyword` carries the keyword text so the parser can report it
/// verbatim in diagnostics, matching the reference implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Policy,
    Version,
    On,
    Then,
    Event(EventType),
    Action(Action),
    Ident(String),
    Number(String),
    Str(String),
    LParen,
    RParen,
    Eof,
}

impl TokenKind {
    /// The name used when reporting this token in a diagnostic. Matches the
    /// token type names of the Python reference.
    pub fn type_name(&self) -> String {
        match self {
            TokenKind::Policy => "POLICY".into(),
            TokenKind::Version => "VERSION".into(),
            TokenKind::On => "ON".into(),
            TokenKind::Then => "THEN".into(),
            TokenKind::Event(t) => t.as_str().into(),
            TokenKind::Action(a) => a.as_str().into(),
            TokenKind::Ident(_) => "IDENT".into(),
            TokenKind::Number(_) => "NUMBER".into(),
            TokenKind::Str(_) => "STRING".into(),
            TokenKind::LParen => "LPAREN".into(),
            TokenKind::RParen => "RPAREN".into(),
            TokenKind::Eof => "EOF".into(),
        }
    }

    /// The token's value as the reference implementation would print it.
    pub fn value(&self) -> String {
        match self {
            TokenKind::Policy => "POLICY".into(),
            TokenKind::Version => "VERSION".into(),
            TokenKind::On => "ON".into(),
            TokenKind::Then => "THEN".into(),
            TokenKind::Event(t) => t.as_str().into(),
            TokenKind::Action(a) => a.as_str().into(),
            TokenKind::Ident(s) => s.clone(),
            TokenKind::Number(s) => s.clone(),
            TokenKind::Str(s) => s.clone(),
            TokenKind::LParen => "(".into(),
            TokenKind::RParen => ")".into(),
            TokenKind::Eof => String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub line: usize,
}

/// Lex a policy source into tokens.
///
/// Keyword recognition is exact and case-sensitive. A word that is not a keyword
/// becomes an identifier, which is how a removed construct such as `SPAWN` comes
/// to be rejected by the parser rather than the lexer.
pub fn tokenize(source: &str) -> Result<Vec<Token>> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;

    while i < chars.len() {
        let c = chars[i];

        if c == '\n' {
            line += 1;
            i += 1;
            continue;
        }

        if c.is_whitespace() {
            i += 1;
            continue;
        }

        if c == '"' {
            let mut j = i + 1;
            let mut buf = String::new();
            while j < chars.len() && chars[j] != '"' {
                if chars[j] == '\n' {
                    return Err(CompileError::at_line("Unterminated string literal", line));
                }
                buf.push(chars[j]);
                j += 1;
            }
            if j >= chars.len() {
                return Err(CompileError::at_line("Unterminated string literal", line));
            }
            tokens.push(Token { kind: TokenKind::Str(buf), line });
            i = j + 1;
            continue;
        }

        if c == '(' {
            tokens.push(Token { kind: TokenKind::LParen, line });
            i += 1;
            continue;
        }

        if c == ')' {
            tokens.push(Token { kind: TokenKind::RParen, line });
            i += 1;
            continue;
        }

        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            tokens.push(Token { kind: TokenKind::Number(text), line });
            continue;
        }

        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let kind = match word.as_str() {
                "POLICY" => TokenKind::Policy,
                "VERSION" => TokenKind::Version,
                "ON" => TokenKind::On,
                "THEN" => TokenKind::Then,
                other => {
                    if let Some(t) = EventType::from_keyword(other) {
                        TokenKind::Event(t)
                    } else if let Some(a) = Action::from_keyword(other) {
                        TokenKind::Action(a)
                    } else {
                        TokenKind::Ident(word.clone())
                    }
                }
            };
            tokens.push(Token { kind, line });
            continue;
        }

        return Err(CompileError::at_line(format!("Unexpected character {c:?}"), line));
    }

    tokens.push(Token { kind: TokenKind::Eof, line });
    Ok(tokens)
}
