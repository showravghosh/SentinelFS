//! Conformance tests for the numbered results of docs/formal-semantics.md.
//!
//! These check that this implementation conforms to the formal model. They do not
//! prove the results, which are established in the document. A failure here means
//! the code has diverged from the specification, not that the mathematics is wrong.

mod common;

use common::{all_policies, embeds, noise, Rng, SHADOW};
use sentinelfs::dsl::ast::{Event, EventType};
use sentinelfs::{compile_policy, parse_source, run_trace, Decision};

fn random_trace(rng: &mut Rng, pattern: &[Event], max_len: usize) -> Vec<Event> {
    let mut pool: Vec<Event> = pattern.to_vec();
    pool.extend(noise());
    let len = rng.below(max_len + 1);
    (0..len).map(|_| rng.pick(&pool).clone()).collect()
}

// --- Theorem 1: determinism ---------------------------------------------------

#[test]
fn theorem1_transition_function_is_total_and_single_valued() {
    for source in all_policies() {
        let policy = parse_source(source).unwrap();
        let automaton = compile_policy(&policy).unwrap();

        let mut alphabet = policy.sequence.clone();
        alphabet.extend(noise());

        for state in &automaton.states {
            // delta is total: defined for every state and every event.
            for event in &alphabet {
                let next = automaton.delta(state, event);
                assert!(automaton.states.iter().any(|s| s == next));
            }
            // and single-valued: at most one advancing edge leaves each state.
            let outgoing = automaton.transitions.iter().filter(|t| &t.from_state == state).count();
            assert!(outgoing <= 1, "{state} has {outgoing} advancing edges");
        }
    }
}

#[test]
fn corollary1_1_repeated_evaluation_is_identical() {
    let mut rng = Rng::new(7);
    for source in all_policies() {
        let policy = parse_source(source).unwrap();
        let automaton = compile_policy(&policy).unwrap();

        for _ in 0..50 {
            let trace = random_trace(&mut rng, &policy.sequence, 12);
            let first = run_trace(&automaton, &trace);
            for _ in 0..4 {
                let again = run_trace(&automaton, &trace);
                assert_eq!(first.final_state, again.final_state);
                assert_eq!(first.decision, again.decision);
            }
        }
    }
}

#[test]
fn recompilation_is_stable() {
    for source in all_policies() {
        let policy = parse_source(source).unwrap();
        assert_eq!(compile_policy(&policy).unwrap(), compile_policy(&policy).unwrap());
    }
}

// --- Lemma 1: state characterisation ------------------------------------------

/// match(tau): the length of the longest pattern prefix embedding in the trace.
fn match_index(pattern: &[Event], trace: &[Event]) -> usize {
    let mut k = 0;
    for event in trace {
        if k < pattern.len() && *event == pattern[k] {
            k += 1;
        }
    }
    k
}

#[test]
fn lemma1_state_equals_match_index() {
    let mut rng = Rng::new(11);
    for source in all_policies() {
        let policy = parse_source(source).unwrap();
        let automaton = compile_policy(&policy).unwrap();

        for _ in 0..300 {
            let trace = random_trace(&mut rng, &policy.sequence, 12);
            let expected = format!("q{}", match_index(&policy.sequence, &trace));
            assert_eq!(run_trace(&automaton, &trace).final_state, expected);
        }
    }
}

// --- Theorem 2: compilation correctness ---------------------------------------

#[test]
fn theorem2_acceptance_iff_violation() {
    let mut rng = Rng::new(13);
    for source in all_policies() {
        let policy = parse_source(source).unwrap();
        let automaton = compile_policy(&policy).unwrap();

        for _ in 0..300 {
            let trace = random_trace(&mut rng, &policy.sequence, 12);
            assert_eq!(
                embeds(&policy.sequence, &trace),
                run_trace(&automaton, &trace).triggered
            );
        }
    }
}

#[test]
fn corollary2_1_decision_matches_definition_3() {
    let mut rng = Rng::new(17);
    for source in all_policies() {
        let policy = parse_source(source).unwrap();
        let automaton = compile_policy(&policy).unwrap();

        for _ in 0..300 {
            let trace = random_trace(&mut rng, &policy.sequence, 12);
            let expected = if embeds(&policy.sequence, &trace) {
                match policy.action.as_str() {
                    "DENY" => Decision::Deny,
                    "ALERT" => Decision::Alert,
                    _ => Decision::Allow,
                }
            } else {
                Decision::Allow
            };
            assert_eq!(run_trace(&automaton, &trace).decision, expected);
        }
    }
}

// --- Theorem 3: absorption, and sound halting ----------------------------------

#[test]
fn theorem3_violation_state_is_absorbing() {
    let mut rng = Rng::new(19);
    for source in all_policies() {
        let policy = parse_source(source).unwrap();
        let automaton = compile_policy(&policy).unwrap();

        let base = policy.sequence.clone(); // reaches the final state by construction
        assert_eq!(run_trace(&automaton, &base).final_state, automaton.final_state);

        for _ in 0..100 {
            let mut extended = base.clone();
            let suffix_len = 1 + rng.below(6);
            let mut pool = policy.sequence.clone();
            pool.extend(noise());
            for _ in 0..suffix_len {
                extended.push(rng.pick(&pool).clone());
            }
            let result = run_trace(&automaton, &extended);
            assert_eq!(result.final_state, automaton.final_state);
            assert!(result.triggered);
        }
    }
}

#[test]
fn corollary3_1_early_exit_agrees_with_full_drain() {
    let mut rng = Rng::new(23);
    for source in all_policies() {
        let policy = parse_source(source).unwrap();
        let automaton = compile_policy(&policy).unwrap();

        for _ in 0..300 {
            let trace = random_trace(&mut rng, &policy.sequence, 12);
            // run_trace halts at the violation state; delta_star drains the trace.
            assert_eq!(run_trace(&automaton, &trace).final_state, automaton.delta_star(&trace));
        }
    }
}

// --- Corollary 4: enforcement soundness ----------------------------------------

#[test]
fn corollary4_violation_never_yields_allow() {
    let mut rng = Rng::new(29);
    for source in all_policies() {
        let policy = parse_source(source).unwrap();
        if policy.action.as_str() == "ALLOW" {
            continue; // Corollary 4 is stated for DENY/ALERT policies
        }
        let automaton = compile_policy(&policy).unwrap();

        let mut checked = 0;
        for _ in 0..400 {
            let trace = random_trace(&mut rng, &policy.sequence, 12);
            if !embeds(&policy.sequence, &trace) {
                continue;
            }
            checked += 1;
            assert_ne!(run_trace(&automaton, &trace).decision, Decision::Allow);
        }
        assert!(checked > 0, "no violating traces generated; the test would be vacuous");
    }
}

// --- section 5: the construction is linear in the pattern length ---------------

#[test]
fn compiler_produces_n_plus_one_states() {
    for source in all_policies() {
        let policy = parse_source(source).unwrap();
        let automaton = compile_policy(&policy).unwrap();
        let n = policy.sequence.len();
        assert_eq!(automaton.states.len(), n + 1);
        assert_eq!(automaton.transitions.len(), n);
        assert_eq!(automaton.final_state, format!("q{n}"));
    }
}

// --- the documented example traces ---------------------------------------------

#[test]
fn documented_example_traces() {
    let policy = parse_source(SHADOW).unwrap();
    let automaton = compile_policy(&policy).unwrap();

    let full = vec![
        Event::new(EventType::Exec, "/usr/bin/python3"),
        Event::new(EventType::Exec, "/bin/bash"),
        Event::new(EventType::Write, "/etc/shadow"),
    ];
    assert_eq!(run_trace(&automaton, &full).decision, Decision::Deny);
    assert_eq!(run_trace(&automaton, &full).final_state, "q3");

    let prefix = vec![Event::new(EventType::Exec, "/usr/bin/python3")];
    assert_eq!(run_trace(&automaton, &prefix).decision, Decision::Allow);
    assert_eq!(run_trace(&automaton, &prefix).final_state, "q1");

    let wrong_target = vec![
        Event::new(EventType::Exec, "/usr/bin/python3"),
        Event::new(EventType::Exec, "/bin/bash"),
        Event::new(EventType::Write, "/tmp/test.txt"),
    ];
    assert_eq!(run_trace(&automaton, &wrong_target).decision, Decision::Allow);
    assert_eq!(run_trace(&automaton, &wrong_target).final_state, "q2");

    let noisy = vec![
        Event::new(EventType::Open, "/var/log/syslog"),
        Event::new(EventType::Exec, "/usr/bin/python3"),
        Event::new(EventType::Open, "/var/log/syslog"),
        Event::new(EventType::Exec, "/bin/bash"),
        Event::new(EventType::Write, "/etc/shadow"),
    ];
    assert_eq!(run_trace(&automaton, &noisy).decision, Decision::Deny);

    let out_of_order = vec![
        Event::new(EventType::Exec, "/bin/bash"),
        Event::new(EventType::Exec, "/usr/bin/python3"),
        Event::new(EventType::Write, "/etc/shadow"),
    ];
    assert_eq!(run_trace(&automaton, &out_of_order).decision, Decision::Allow);

    assert_eq!(run_trace(&automaton, &[]).decision, Decision::Allow);
}
