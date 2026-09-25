//! Shared fixtures for the conformance tests.
//!
//! A deterministic pseudo-random generator is used rather than a crate, so the
//! trace sequences are reproducible, seeded identically across runs, and the
//! crate keeps its zero-dependency build.

// Each integration test compiles this module separately and uses a subset of it,
// so every binary sees the remainder as dead code. The alternative would be to
// split the fixtures per consumer and duplicate them.
#![allow(dead_code)]

use sentinelfs::{Event, EventType};

pub const SHADOW: &str = r#"POLICY protect_shadow
VERSION 1

ON EXEC("/usr/bin/python3")
THEN EXEC("/bin/bash")
THEN WRITE("/etc/shadow")
DENY
"#;

pub const PASSWD: &str = r#"POLICY protect_passwd
VERSION 1
ON EXEC("/bin/bash")
THEN WRITE("/etc/passwd")
DENY
"#;

pub const MONITOR: &str = r#"POLICY monitor_sensitive_file
VERSION 1
ON OPEN("/etc/shadow")
ALERT
"#;

pub const REPEATED: &str = r#"POLICY repeated_event
VERSION 1
ON WRITE("/etc/hosts")
THEN WRITE("/etc/hosts")
THEN WRITE("/etc/hosts")
DENY
"#;

pub fn all_policies() -> Vec<&'static str> {
    vec![SHADOW, PASSWD, MONITOR, REPEATED]
}

pub fn noise() -> Vec<Event> {
    vec![
        Event::new(EventType::Open, "/var/log/syslog"),
        Event::new(EventType::Exec, "/usr/bin/curl"),
        Event::new(EventType::Delete, "/tmp/scratch"),
        Event::new(EventType::Write, "/tmp/scratch"),
        Event::new(EventType::Exec, "/usr/bin/env"),
    ]
}

/// A small xorshift generator. Deterministic and seeded, so a failure reported by
/// these tests can be reproduced exactly.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Definition 1 decided directly: does the pattern occur as an in-order
/// subsequence of the trace? Written independently of the automaton so it can
/// serve as an oracle.
pub fn embeds(pattern: &[Event], trace: &[Event]) -> bool {
    let mut k = 0;
    for event in trace {
        if k < pattern.len() && *event == pattern[k] {
            k += 1;
        }
    }
    k == pattern.len()
}
