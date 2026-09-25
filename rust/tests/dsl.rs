//! Lexer, parser and validator conformance, mirroring tests/test_lexer.py and
//! tests/test_parser.py of the reference implementation.

mod common;

use common::SHADOW;
use sentinelfs::dsl::ast::{Action, Event, EventType, Policy};
use sentinelfs::dsl::lexer::{tokenize, TokenKind};
use sentinelfs::dsl::validator::validate;
use sentinelfs::parse_source;

#[test]
fn tokenizes_keywords_and_literals() {
    let tokens = tokenize(SHADOW).expect("should lex");
    let names: Vec<String> = tokens.iter().map(|t| t.kind.type_name()).collect();
    assert_eq!(&names[..6], &["POLICY", "IDENT", "VERSION", "NUMBER", "ON", "EXEC"]);
    assert_eq!(names.last().unwrap(), "EOF");
}

#[test]
fn string_literal_value() {
    let tokens = tokenize(r#"EXEC("/usr/bin/python3")"#).expect("should lex");
    let strings: Vec<String> = tokens
        .iter()
        .filter_map(|t| match &t.kind {
            TokenKind::Str(s) => Some(s.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(strings, vec!["/usr/bin/python3".to_string()]);
}

#[test]
fn unterminated_string_is_rejected() {
    assert!(tokenize(r#"EXEC("/usr/bin/python3"#).is_err());
}

#[test]
fn unexpected_character_is_rejected() {
    assert!(tokenize("POLICY foo$bar").is_err());
}

#[test]
fn parses_full_policy() {
    let policy = parse_source(SHADOW).expect("should parse");
    assert_eq!(policy.name, "protect_shadow");
    assert_eq!(policy.version, 1);
    assert_eq!(
        policy.sequence,
        vec![
            Event::new(EventType::Exec, "/usr/bin/python3"),
            Event::new(EventType::Exec, "/bin/bash"),
            Event::new(EventType::Write, "/etc/shadow"),
        ]
    );
    assert_eq!(policy.action, Action::Deny);
}

#[test]
fn parses_alert_only_policy() {
    let policy =
        parse_source("POLICY monitor\nVERSION 1\nON OPEN(\"/etc/shadow\")\nALERT\n").unwrap();
    assert_eq!(policy.sequence, vec![Event::new(EventType::Open, "/etc/shadow")]);
    assert_eq!(policy.action, Action::Alert);
}

#[test]
fn malformed_policies_are_rejected() {
    let cases = [
        "VERSION 1\nON EXEC(\"x\")\nDENY\n",           // missing POLICY
        "POLICY p\nON EXEC(\"x\")\nDENY\n",            // missing VERSION
        "POLICY p\nVERSION 1\nEXEC(\"x\")\nDENY\n",    // missing ON
        "POLICY p\nVERSION 1\nON EXEC(\"x\")\n",       // missing action
        "POLICY p\nVERSION 1\nON FOO(\"x\")\nDENY\n",  // unknown event type
        "POLICY p\nVERSION 1\nON EXEC(\"x\")\nDENY\nEXTRA\n", // trailing tokens
    ];
    for case in cases {
        assert!(parse_source(case).is_err(), "should have been rejected:\n{case}");
    }
}

#[test]
fn spawn_is_not_in_the_v1_alphabet() {
    // SPAWN was removed after the Phase 2 study showed it is unobservable: at fork
    // time the kernel cannot name the binary the child will execute.
    // See docs/phase2-findings.md section 4.1.
    let err = parse_source("POLICY p\nVERSION 1\nON SPAWN(\"/bin/bash\")\nDENY\n")
        .expect_err("SPAWN must be rejected");
    assert!(err.to_string().contains("Expected an event"), "unexpected: {err}");
}

#[test]
fn admitted_event_types_are_exactly_the_observable_four() {
    let names: Vec<&str> = EventType::ALL.iter().map(|t| t.as_str()).collect();
    assert_eq!(names, vec!["EXEC", "WRITE", "OPEN", "DELETE"]);
}

// --- well-formedness WF1-WF4 -------------------------------------------------

fn policy_with(name: &str, version: u32, sequence: Vec<Event>) -> Policy {
    Policy { name: name.into(), version, sequence, action: Action::Deny }
}

#[test]
fn wf1_empty_pattern_rejected() {
    assert!(validate(&policy_with("p", 1, vec![])).is_err());
}

#[test]
fn wf2_version_must_be_positive() {
    let seq = vec![Event::new(EventType::Exec, "/bin/sh")];
    assert!(validate(&policy_with("p", 0, seq)).is_err());
}

#[test]
fn wf3_name_must_be_non_empty() {
    let seq = vec![Event::new(EventType::Exec, "/bin/sh")];
    assert!(validate(&policy_with("", 1, seq)).is_err());
}

#[test]
fn wf4_event_argument_must_be_non_empty() {
    let seq = vec![Event::new(EventType::Exec, "")];
    assert!(validate(&policy_with("p", 1, seq)).is_err());
}
