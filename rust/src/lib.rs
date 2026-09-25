//! SentinelFS: a deterministic policy compiler and runtime evaluator.
//!
//! This crate implements the language frozen as `v1.0-spec` and specified in
//! `docs/formal-semantics.md`. It is a port of the Python reference
//! implementation, not a redesign: the module structure mirrors the reference so
//! that conformance can be checked module by module, and the semantics are those
//! of the specification rather than anything more convenient to express in Rust.
//!
//! The event alphabet is fixed:
//!
//! ```text
//! Sigma = { EXEC(path), WRITE(path), OPEN(path), DELETE(path) }
//! ```
//!
//! A construct whose argument cannot be determined at the moment the event occurs
//! is not admitted to the alphabet. `SPAWN` was removed under that criterion; see
//! `docs/phase2-findings.md` section 4.1.

pub mod compiler;
pub mod dsl;
pub mod runtime;

pub use compiler::automaton::{compile_policy, Automaton, Transition};
pub use dsl::ast::{Action, Event, EventType, Policy};
pub use dsl::errors::CompileError;
pub use dsl::lexer::{tokenize, Token, TokenKind};
pub use dsl::parser::parse_source;
pub use dsl::validator::validate;
pub use runtime::executor::{run_trace, Decision, ExecutionResult, StepResult};
