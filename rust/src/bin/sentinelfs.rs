//! SentinelFS command-line interface.
//!
//! The output format matches the Python reference implementation exactly, so that
//! conformance between the two can be checked by comparing output rather than only
//! by comparing in-process results.

use std::process::ExitCode;

use sentinelfs::compiler::automaton::{compile_policy, Automaton};
use sentinelfs::dsl::parser::{parse_event_literal, parse_source};
use sentinelfs::runtime::executor::run_trace;

fn usage() -> &'static str {
    "Usage:\n  \
     sentinelfs compile <policy.sfs>\n  \
     sentinelfs run <policy.sfs> --trace 'EXEC(\"/bin/sh\")' ...\n"
}

fn describe_automaton(a: &Automaton) -> String {
    let mut lines = vec![format!("Policy: {}  Version: {}", a.policy_name, a.policy_version)];
    for t in &a.transitions {
        lines.push(format!("  {} --{}--> {}", t.from_state, t.event.label(), t.to_state));
    }
    lines.push(format!("  {} = VIOLATION -> {}", a.final_state, a.action));
    lines.join("\n")
}

fn read_policy(path: &str) -> Result<Automaton, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}: {e}"))?;
    let policy = parse_source(&source).map_err(|e| format!("Compile error: {e}"))?;
    compile_policy(&policy).map_err(|e| format!("Compile error: {e}"))
}

fn cmd_compile(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or_else(|| usage().to_string())?;
    let automaton = read_policy(path)?;
    println!("{}", describe_automaton(&automaton));
    Ok(())
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or_else(|| usage().to_string())?;

    let trace_pos = args
        .iter()
        .position(|a| a == "--trace")
        .ok_or_else(|| "error: --trace is required".to_string())?;
    let literals = &args[trace_pos + 1..];
    if literals.is_empty() {
        return Err("error: --trace requires at least one event".to_string());
    }

    let automaton = read_policy(path)?;
    let mut trace = Vec::new();
    for lit in literals {
        trace.push(parse_event_literal(lit).map_err(|e| format!("Error: {e}"))?);
    }

    let result = run_trace(&automaton, &trace);
    for step in &result.path {
        let mark = if step.matched { "matched" } else { "ignored" };
        println!(
            "  {:<45} {} -> {}  ({})",
            step.event.label(),
            step.from_state,
            step.to_state,
            mark
        );
    }
    println!("Final State: {}", result.final_state);
    println!("Decision: {}", result.decision);
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        eprint!("{}", usage());
        return ExitCode::FAILURE;
    };

    let result = match command.as_str() {
        "compile" => cmd_compile(&args[1..]),
        "run" => cmd_run(&args[1..]),
        other => Err(format!("unknown command {other:?}\n{}", usage())),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
