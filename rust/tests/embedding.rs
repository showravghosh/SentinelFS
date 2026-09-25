//! Independent check that greedy matching coincides with the existential semantics.
//!
//! Definition 1 of docs/formal-semantics.md defines violation existentially: there
//! EXIST indices j_1 < ... < j_n with tau[j_k] = e_k. Both the automaton and the
//! oracle in theorems.rs decide this by scanning left to right and advancing on the
//! first match. That the two coincide is the content of Lemma 1 - so a differential
//! test between two greedy implementations cannot establish it, since both share the
//! assumption.
//!
//! These tests decide the existential question directly, enumerating index
//! combinations rather than scanning. That is exponential, so traces are kept short;
//! the point is independence from the greedy strategy, not scale.

mod common;

use common::Rng;
use sentinelfs::dsl::ast::{Action, Event, EventType, Policy};
use sentinelfs::{compile_policy, run_trace};

fn alphabet() -> Vec<Event> {
    vec![
        Event::new(EventType::Exec, "/bin/a"),
        Event::new(EventType::Exec, "/bin/b"),
        Event::new(EventType::Write, "/f"),
        Event::new(EventType::Open, "/f"),
    ]
}

/// Decide Definition 1 directly: enumerate strictly increasing index tuples and ask
/// whether any witnesses the embedding. No greedy scanning.
fn embeds_existentially(pattern: &[Event], trace: &[Event]) -> bool {
    let n = pattern.len();
    if n == 0 {
        return true;
    }
    if n > trace.len() {
        return false;
    }

    // Enumerate combinations of n indices from 0..trace.len() in lexicographic order.
    let mut indices: Vec<usize> = (0..n).collect();
    loop {
        if (0..n).all(|k| trace[indices[k]] == pattern[k]) {
            return true;
        }

        // Advance to the next combination.
        let mut i = n;
        loop {
            if i == 0 {
                return false;
            }
            i -= 1;
            if indices[i] != i + trace.len() - n {
                break;
            }
            if i == 0 {
                return false;
            }
        }
        indices[i] += 1;
        for j in i + 1..n {
            indices[j] = indices[j - 1] + 1;
        }
    }
}

/// The greedy strategy, stated separately so the two can be compared.
fn embeds_greedily(pattern: &[Event], trace: &[Event]) -> bool {
    let mut k = 0;
    for event in trace {
        if k < pattern.len() && *event == pattern[k] {
            k += 1;
        }
    }
    k == pattern.len()
}

#[test]
fn greedy_coincides_with_existential_semantics() {
    let alpha = alphabet();
    for pattern_len in 1..=3 {
        let mut rng = Rng::new(4242 + pattern_len as u64);
        for _ in 0..400 {
            let pattern: Vec<Event> =
                (0..pattern_len).map(|_| rng.pick(&alpha).clone()).collect();
            let trace_len = rng.below(8);
            let trace: Vec<Event> = (0..trace_len).map(|_| rng.pick(&alpha).clone()).collect();

            assert_eq!(
                embeds_greedily(&pattern, &trace),
                embeds_existentially(&pattern, &trace),
                "greedy and existential disagree on pattern {:?} trace {:?}",
                pattern.iter().map(Event::label).collect::<Vec<_>>(),
                trace.iter().map(Event::label).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn automaton_decides_the_existential_semantics() {
    let alpha = alphabet();
    for pattern_len in 1..=3 {
        let mut rng = Rng::new(99 + pattern_len as u64);
        for _ in 0..400 {
            let pattern: Vec<Event> =
                (0..pattern_len).map(|_| rng.pick(&alpha).clone()).collect();
            let policy = Policy {
                name: "p".into(),
                version: 1,
                sequence: pattern.clone(),
                action: Action::Deny,
            };
            let automaton = compile_policy(&policy).unwrap();

            let trace_len = rng.below(8);
            let trace: Vec<Event> = (0..trace_len).map(|_| rng.pick(&alpha).clone()).collect();

            assert_eq!(
                run_trace(&automaton, &trace).triggered,
                embeds_existentially(&pattern, &trace),
                "Theorem 2 fails against the existential oracle: pattern {:?} trace {:?}",
                pattern.iter().map(Event::label).collect::<Vec<_>>(),
                trace.iter().map(Event::label).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn exhaustive_over_small_alphabet() {
    // Exhaustive rather than random, over every trace up to length 5 from a
    // two-symbol alphabet, for a repeated pattern - the case where greedy
    // strategies are most likely to differ from existential ones.
    let a = Event::new(EventType::Exec, "/bin/a");
    let b = Event::new(EventType::Exec, "/bin/b");
    let small = [a.clone(), b.clone()];
    let pattern = vec![a.clone(), b.clone(), a.clone()];

    let policy = Policy {
        name: "p".into(),
        version: 1,
        sequence: pattern.clone(),
        action: Action::Deny,
    };
    let automaton = compile_policy(&policy).unwrap();

    let mut checked = 0usize;
    for length in 0..6usize {
        for bits in 0..(1usize << length) {
            let trace: Vec<Event> =
                (0..length).map(|i| small[(bits >> i) & 1].clone()).collect();
            assert_eq!(
                run_trace(&automaton, &trace).triggered,
                embeds_existentially(&pattern, &trace),
                "disagreement on {:?}",
                trace.iter().map(Event::label).collect::<Vec<_>>()
            );
            checked += 1;
        }
    }
    assert_eq!(checked, (0..6).map(|i| 1usize << i).sum::<usize>());
}
