use crate::dsl::ast::{Action, Event, Policy};
use crate::dsl::errors::Result;
use crate::dsl::validator::validate;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub from_state: String,
    pub to_state: String,
    pub event: Event,
}

/// A compiled security automaton, as defined in `formal-semantics.md`
/// section 4 (Definition 4).
///
/// The transition function of Definition 6 is total, but it is not stored as a
/// table: for a policy of pattern length n only the n advancing edges differ from
/// the identity, so the representation holds those and [`Automaton::delta`]
/// supplies the self-loops and the absorbing final state. This is the same
/// representation choice as the reference implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Automaton {
    pub policy_name: String,
    pub policy_version: u32,
    pub states: Vec<String>,
    pub transitions: Vec<Transition>,
    pub final_state: String,
    pub action: Action,
}

impl Automaton {
    /// The advancing edge out of `state`, if any. The final state has none.
    pub fn transition_from(&self, state: &str) -> Option<&Transition> {
        self.transitions.iter().find(|t| t.from_state == state)
    }

    /// The transition function delta of Definition 6, total by construction.
    ///
    /// For a non-final state, the event either matches the state's advancing edge,
    /// in which case the automaton advances, or it does not, in which case the
    /// state is unchanged. The final state is absorbing (Theorem 3).
    pub fn delta<'a>(&'a self, state: &'a str, event: &Event) -> &'a str {
        match self.transition_from(state) {
            Some(edge) if &edge.event == event => &edge.to_state,
            _ => state,
        }
    }

    /// The extended transition function delta* of Definition 4.
    ///
    /// Defined over the whole trace, with no early exit. The executor halts at the
    /// final state instead, which Corollary 3.1 shows computes the same state.
    pub fn delta_star(&self, trace: &[Event]) -> String {
        let mut state = self.states[0].clone();
        for event in trace {
            state = self.delta(&state, event).to_string();
        }
        state
    }

    /// Whether the automaton accepts the trace, i.e. reaches a violation state
    /// (Definition 5).
    pub fn accepts(&self, trace: &[Event]) -> bool {
        self.delta_star(trace) == self.final_state
    }
}

/// Compile a policy into its automaton, per Definition 6.
///
/// State `q_i` records that the first `i` events of the pattern have been
/// matched. Each non-final state has exactly one advancing edge, on the next
/// pattern event; every other event is a self-loop, which is what realises the
/// subsequence-embedding semantics of Definition 1. The construction is linear in
/// the pattern length.
pub fn compile_policy(policy: &Policy) -> Result<Automaton> {
    validate(policy)?;

    let n = policy.sequence.len();
    let states: Vec<String> = (0..=n).map(|i| format!("q{i}")).collect();
    let transitions: Vec<Transition> = policy
        .sequence
        .iter()
        .enumerate()
        .map(|(i, event)| Transition {
            from_state: format!("q{i}"),
            to_state: format!("q{}", i + 1),
            event: event.clone(),
        })
        .collect();

    Ok(Automaton {
        policy_name: policy.name.clone(),
        policy_version: policy.version,
        final_state: states[n].clone(),
        states,
        transitions,
        action: policy.action,
    })
}
