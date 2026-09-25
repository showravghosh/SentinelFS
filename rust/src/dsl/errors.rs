use std::fmt;

/// An error detected while lexing, parsing, or validating a policy.
///
/// Mirrors `CompileError` in the Python reference, including the message text,
/// so that conformance tests can compare diagnostics and not only accept/reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub message: String,
    pub line: Option<usize>,
}

impl CompileError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), line: None }
    }

    pub fn at_line(message: impl Into<String>, line: usize) -> Self {
        Self { message: message.into(), line: Some(line) }
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "Line {}: {}", line, self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for CompileError {}

pub type Result<T> = std::result::Result<T, CompileError>;
