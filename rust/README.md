# SentinelFS: Rust implementation

A port of the Python reference implementation to Rust, conforming to the language frozen as
[`v1.0-spec`](../docs/formal-semantics.md).

This is a port, not a redesign. The module structure mirrors the reference so that
conformance can be checked module by module, and the semantics are those of the
specification rather than anything more convenient to express in Rust.

| Reference | This crate |
|---|---|
| `sentinelfs/dsl/lexer.py` | `src/dsl/lexer.rs` |
| `sentinelfs/dsl/ast_nodes.py` | `src/dsl/ast.rs` |
| `sentinelfs/dsl/parser.py` | `src/dsl/parser.rs` |
| `sentinelfs/dsl/validator.py` | `src/dsl/validator.rs` |
| `sentinelfs/dsl/errors.py` | `src/dsl/errors.rs` |
| `sentinelfs/compiler/automaton.py` | `src/compiler/automaton.rs` |
| `sentinelfs/runtime/executor.py` | `src/runtime/executor.rs` |
| `sentinelfs/cli.py` | `src/bin/sentinelfs.rs` |

## Why Rust, and why now

The eventual enforcement path runs in or alongside the kernel, where a garbage collector and
an interpreter are not available. Porting the verified core before that work begins keeps two
hard problems separate: this crate is judged only on whether it agrees with the reference,
and the kernel integration will be judged only on whether it delivers events correctly.

## No dependencies

The `[dependencies]` section is empty and is intended to stay that way. This crate is the
trusted core of a security system: every crate admitted here widens what has to be trusted,
and nothing in the v1 language requires more than the standard library. The tests use a
small seeded generator rather than a property-testing crate for the same reason.

## Building and testing

```bash
cargo build --release
cargo test
cargo clippy --all-targets
```

## Conformance

Three layers, in increasing strength.

**1. The crate's own tests** (`cargo test`) mirror the reference suite, including a
conformance test for each numbered result of the specification:

| Test file | Covers |
|---|---|
| `tests/dsl.rs` | grammar, diagnostics, well-formedness WF1–WF4, rejection of removed constructs |
| `tests/theorems.rs` | Theorem 1, Lemma 1, Theorem 2, Theorem 3, Corollaries 1.1, 2.1, 3.1, 4 |
| `tests/embedding.rs` | that greedy matching decides the existential semantics of Definition 1 |

`tests/embedding.rs` deserves a note. Both the automaton and the ordinary oracle decide
embedding by scanning left to right, so agreement between them cannot establish that greedy
matching coincides with the existential definition — which is the content of Lemma 1. Those
tests decide the existential question directly by enumerating index combinations, including
exhaustively over every trace up to length five for a repeated pattern.

**2. Cross-implementation conformance** (`../conformance.py`) runs the same policies and
traces through both command-line interfaces and compares output byte for byte, including
diagnostics for malformed policies:

```bash
cargo build --release
cd .. && python3 conformance.py --traces 250
```

Comparing output rather than in-process values is deliberate: it exercises the compiled
automaton, the executor, the decision, the step-by-step path, and the formatting of each,
and the two sides cannot accidentally share code.

**3. The specification itself.** Layers 1 and 2 are evidence of conformance, not proofs of
equivalence. The theorems are statements about the compilation function of Definition 6; that
this crate implements that function is a separate claim, supported here by testing.

## If an implementation and the specification disagree

The specification is frozen at `v1.0-spec`. A mismatch discovered here is to be investigated
as a defect in this implementation or an error in the specification, and resolved by a
deliberate revision of whichever is wrong. It is not to be worked around by quietly adjusting
the semantics to whatever Rust made convenient.

## Not yet implemented

This crate covers the formal core only: DSL, compiler, executor. It does not implement event
collection, enforcement, or the evidence layer. In particular it has no kernel interface: the
eBPF/LSM work is a later phase, and the Phase 2 feasibility study that informs it lives in
[`../feasibility/`](../feasibility/).
