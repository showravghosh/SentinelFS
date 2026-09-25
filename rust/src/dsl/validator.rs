use super::ast::Policy;
use super::errors::{CompileError, Result};

/// Check the well-formedness conditions WF1-WF4 of `formal-semantics.md`
/// section 2.1.
///
/// WF2 (version >= 1) is expressed here rather than in the type, because a
/// policy with version 0 must be rejected with a diagnostic rather than being
/// unrepresentable: the reference implementation reports it, and conformance
/// requires the same.
pub fn validate(policy: &Policy) -> Result<()> {
    if policy.name.is_empty() {
        return Err(CompileError::new("Policy name must not be empty"));
    }
    if policy.version < 1 {
        return Err(CompileError::new(format!(
            "Policy version must be >= 1, got {}",
            policy.version
        )));
    }
    if policy.sequence.is_empty() {
        return Err(CompileError::new("Policy must contain at least one event (ON ...)"));
    }
    for event in &policy.sequence {
        if event.arg.is_empty() {
            return Err(CompileError::new(format!(
                "{} event has an empty argument",
                event.event_type
            )));
        }
    }
    Ok(())
}
