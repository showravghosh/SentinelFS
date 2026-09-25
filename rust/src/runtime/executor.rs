use std::fmt;

use crate::compiler::automaton::Automaton;
use crate::dsl::ast::{Action, Event};

/// The decision issued for a trace.
///
/// `Allow` means no violation was established, not that the trace was
/// affirmatively permitted; see `formal-semantics.md` section 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Deny,
    Alert,
    Allow,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Deny => "DENY",
            Decision::Alert => "ALERT",
            Decision::Allow => "ALLOW",
        }
    }

    fn from_action(action: Action) -> Self {
        match action {
            Action::Deny => Decision::Deny,
            Action::Alert => Decision::Alert,
            Action::Allow => Decision::Allow,
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResult {
    pub event: Event,
    pub from_state: String,
    pub to_state: String,
    pub matched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub policy_name: String,
    pub policy_version: u32,
    pub final_state: String,
    /// True exactly when the automaton reached its violation state.
    pub triggered: bool,
    pub decision: Decision,
    pub path: Vec<StepResult>,
}

/// Evaluate a trace against a compiled automaton.
///
/// Execution halts on reaching the violation state rather than draining the
/// remaining trace. Corollary 3.1 establishes that this computes the same state
/// as consuming the whole trace, because the violation state is absorbing
/// (Theorem 3).
pub fn run_trace(automaton: &Automaton, trace: &[Event]) -> ExecutionResult {
    let mut state = automaton.states[0].clone();
    let mut path = Vec::new();

    for event in trace {
        if state == automaton.final_state {
            break;
        }

        let edge = automaton.transition_from(&state);
        let matched = matches!(edge, Some(e) if &e.event == event);
        let to_state = match edge {
            Some(e) if matched => e.to_state.clone(),
            _ => state.clone(),
        };

        path.push(StepResult {
            event: event.clone(),
            from_state: state.clone(),
            to_state: to_state.clone(),
            matched,
        });
        state = to_state;
    }

    let triggered = state == automaton.final_state;
    let decision =
        if triggered { Decision::from_action(automaton.action) } else { Decision::Allow };

    ExecutionResult {
        policy_name: automaton.policy_name.clone(),
        policy_version: automaton.policy_version,
        final_state: state,
        triggered,
        decision,
        path,
    }
}
