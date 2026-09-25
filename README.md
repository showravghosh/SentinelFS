# SentinelFS

A deterministic, formally specified policy compiler and runtime enforcement framework for Linux.

SentinelFS takes security policies written in a deliberately restricted domain-specific
language, compiles them into deterministic finite automata, and evaluates Linux
security-relevant events against those automata to produce reproducible
`ALLOW` / `ALERT` / `DENY` decisions bound to cryptographically linked evidence.

No machine learning, no probabilistic scoring, no learned thresholds.

```
Policy DSL -> Parser -> AST -> Validator -> Compiler -> Deterministic Automaton
                                                              |
                                              Linux kernel events (eBPF/LSM)
                                                              |
                                                       Automaton Executor
                                                              |
                                                  ALLOW / ALERT / DENY
                                                              |
                                                 Hash-chained evidence
```

## Status

| Phase | Content | Status |
|-------|---------|--------|
| 0 | DSL grammar, lexer, parser, validator, compiler, executor, test suite | done |
| 1 | Formal trace semantics; determinism and compilation-correctness theorems | in progress |
| 2 | Verification on native Linux | planned |
| 3 | Rust port of the formal core | planned |
| 4 | eBPF/LSM event collection and enforcement | planned |
| 5 | Policy-aware hash-chained evidence layer | planned |
| 6 | Deterministic replay | planned |
| 7 | Evaluation: security coverage, performance, scalability | planned |

## Policy language (v1)

The core language is intentionally restricted to a regular, sequential event-pattern
fragment. This restriction is a design decision: it keeps deterministic compilation and
formal reasoning about compilation correctness tractable.

```
POLICY protect_shadow
VERSION 1

ON EXEC("/usr/bin/python3")
THEN SPAWN("/bin/bash")
THEN WRITE("/etc/shadow")
DENY
```

Supported event types: `EXEC`, `SPAWN`, `WRITE`, `OPEN`, `DELETE`.
Supported actions: `DENY`, `ALERT`, `ALLOW`.

Constructs deliberately excluded from v1: `WHERE`, `TIMEOUT`, boolean connectives,
unrestricted negation, quantification, and cross-process relational constraints.

## Semantics

A policy defines a set of violating event traces. The required events must occur in
order; arbitrary unrelated events may be interleaved between them. A trace violates the
policy exactly when the policy's event sequence occurs as an in-order subsequence of the
trace.

The compiler emits an automaton in which state `q_i` has exactly one outgoing edge, on
the policy's `i`-th event; every other event is a self-loop. Once the final state is
reached, the automaton halts and the decision is fixed.

## Usage

```bash
pip install -e ".[dev]"

# Compile a policy to its automaton
python -m sentinelfs.cli compile examples/protect_shadow.sfs

# Run an event trace against a policy
python -m sentinelfs.cli run examples/protect_shadow.sfs \
    --trace 'EXEC("/usr/bin/python3")' 'SPAWN("/bin/bash")' 'WRITE("/etc/shadow")'
```

## Tests

```bash
python -m pytest tests -v
```

`tests/test_semantics.py` performs differential testing between an independent reference
interpreter, defined directly on the policy AST, and the compiled automaton, over
randomly generated traces. This is experimental evidence supporting the
compilation-correctness theorem, not a substitute for it.

## Scope and limitations

SentinelFS enforces only what its policy language can express and what its event sources
can observe. Guarantees are stated conditionally, under an explicit observation model and
threat model. It does not claim to detect all attacks, and it makes no probabilistic
judgements of any kind.
