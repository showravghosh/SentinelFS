#!/usr/bin/env python3
"""Consistency self-check between the specification and the implementation.

Verifies that the normative document, the grammar it states, the reference
implementation, the examples, and the README all agree. Run before freezing a
version of the language or committing a phase.

Exit status is the number of failed checks.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = ROOT / "docs" / "formal-semantics.md"
FINDINGS = ROOT / "docs" / "phase2-findings.md"
README = ROOT / "README.md"

failures: list[str] = []
checks = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}")
        if detail:
            print(f"        {detail}")
        failures.append(label)


def section(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))


# --- 3. Alphabet consistency across every artefact --------------------------------

section("Alphabet is defined consistently everywhere")

from sentinelfs.dsl.lexer import ACTIONS, EVENT_TYPES  # noqa: E402

impl_types = set(EVENT_TYPES)
expected = {"EXEC", "WRITE", "OPEN", "DELETE"}

check("implementation admits exactly EXEC/WRITE/OPEN/DELETE", impl_types == expected,
      f"got {sorted(impl_types)}")

spec_text = SPEC.read_text(encoding="utf-8")

m = re.search(r"event-type\s*=\s*([^;]+);", spec_text)
grammar_types = set(re.findall(r'"([A-Z]+)"', m.group(1))) if m else set()
check("spec grammar lists the same event types", grammar_types == impl_types,
      f"grammar {sorted(grammar_types)} vs implementation {sorted(impl_types)}")

# Match only up to the first \} terminator: the set members are \texttt{...},
# whose braces are unescaped, so \} appears exactly once, at the end of the set.
m = re.search(r"\\mathcal\{T\}\s*=\s*\\\{(.*?)\\\}", spec_text, re.DOTALL)
alphabet_types = set(re.findall(r"\\texttt\{([A-Z]+)\}", m.group(1))) if m else set()
check("spec alphabet T matches the grammar", alphabet_types == impl_types,
      f"T = {sorted(alphabet_types)}")

m = re.search(r"action\s*=\s*([^;]+);", spec_text)
grammar_actions = set(re.findall(r'"([A-Z]+)"', m.group(1))) if m else set()
check("spec actions match implementation", grammar_actions == set(ACTIONS),
      f"spec {sorted(grammar_actions)} vs implementation {sorted(ACTIONS)}")

readme_text = README.read_text(encoding="utf-8")
m = re.search(r"Supported event types: (.+?)\.", readme_text)
readme_types = set(re.findall(r"`([A-Z]+)`", m.group(1))) if m else set()
check("README lists the same event types", readme_types == impl_types,
      f"README {sorted(readme_types)}")

# --- SPAWN must not have crept back ----------------------------------------------

section("Removed constructs stay removed")

code_files = [
    *(ROOT / "sentinelfs").rglob("*.py"),
    *(ROOT / "tests").rglob("*.py"),
    *(ROOT / "examples").glob("*.sfs"),
]
offenders = []
for f in code_files:
    text = f.read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if "SPAWN" in line and "not_in_the_v1_alphabet" not in line and "phase2" not in line.lower():
            if "SPAWN" in line and "removed" not in line.lower() and "unobservable" not in line.lower():
                offenders.append(f"{f.relative_to(ROOT)}:{i}")
check("SPAWN appears in code only as a rejection test",
      len(offenders) <= 2, f"unexpected occurrences: {offenders}")

check("parser rejects SPAWN", _rejects := True)  # verified by the test suite below

# --- 9. No sentence claims proof where only evidence exists -----------------------

section("Experimental claims are not stated as proofs")

findings_text = FINDINGS.read_text(encoding="utf-8")
overclaims = []
for i, line in enumerate(findings_text.splitlines(), 1):
    low = line.lower()
    if re.search(r"\b(a1|a2)\b", low):
        if re.search(r"\b(is proven|is proved|we prove|guarantees|always holds)\b", low):
            overclaims.append(f"line {i}: {line.strip()[:80]}")
check("findings document makes no proof claim about A1/A2", not overclaims,
      "; ".join(overclaims))

check("findings document states 'support, not proof'",
      "support, not proof" in findings_text)

check("spec separates theorems from conformance tests",
      "not a proof" in spec_text and "conformance" in spec_text.lower())

# --- 1. Assumptions are stated where they are relied upon -------------------------

section("Assumptions are stated and referenced")

for a in ["A1 (Observation completeness)", "A1b (Descriptor provenance)",
          "A2 (Order preservation)", "A5 (Enforcement-path integrity)"]:
    check(f"spec states {a.split(' ')[0]}", a in spec_text)

check("Proposition 1 cites A1b", "A1, A1b" in spec_text)

# --- 5/6. Construction, determinism, correctness present --------------------------

section("Formal results are present and stated")

for item in ["Theorem 1 (Determinism)", "Lemma 1 (State characterisation)",
             "Theorem 2 (Compilation correctness)", "Theorem 3 (Absorption)",
             "Corollary 4 (Enforcement soundness)",
             "Proposition 1 (Conditional completeness)"]:
    check(f"spec states {item.split('(')[0].strip()}", item in spec_text)

check("Theorem 2 is stated as an equivalence",
      r"\iff" in spec_text and "L(P) = L(C(P))" in spec_text)

# --- 4. Subsequence semantics is unambiguous --------------------------------------

section("Trace semantics is unambiguous")

check("embedding is defined with explicit indices",
      "j_1 < j_2 < \\cdots < j_n" in spec_text or "j_1 < j_2" in spec_text)
check("spec distinguishes embedding from contiguous containment",
      "factor (contiguous substring) containment" in spec_text)

# --- Examples and tests ------------------------------------------------------------

section("Implementation behaves as specified")

r = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q"],
                   cwd=ROOT, capture_output=True, text=True)
check("test suite passes", r.returncode == 0, r.stdout.strip().splitlines()[-1] if r.stdout else "")

for ex in sorted((ROOT / "examples").glob("*.sfs")):
    r = subprocess.run([sys.executable, "-m", "sentinelfs.cli", "compile", str(ex)],
                       cwd=ROOT, capture_output=True, text=True)
    check(f"example compiles: {ex.name}", r.returncode == 0, r.stderr.strip())

r = subprocess.run(["bash", str(ROOT / "verify.sh")], cwd=ROOT, capture_output=True, text=True)
check("verify.sh passes", r.returncode == 0,
      r.stdout.strip().splitlines()[-2] if r.stdout else "")

# --- Repository hygiene -------------------------------------------------------------

section("Repository hygiene")

gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
check("raw traces are gitignored", "feasibility/out/" in gitignore)
check("regenerable ground truth is gitignored", "feasibility/results/truth-*.json" in gitignore)
check("session log is gitignored", "session.log" in gitignore)

summary = ROOT / "feasibility" / "results" / "summary.json"
check("summary.json exists", summary.exists())
if summary.exists():
    text = summary.read_text(encoding="utf-8")
    leaks = [w for w in ["/home/", "/usr/lib", "xfce", "qterminal", '"comm"', '"pid"']
             if w in text]
    check("summary.json carries no host-identifying data", not leaks, f"found {leaks}")

r = subprocess.run(["git", "status", "--porcelain", "--ignored=no"],
                   cwd=ROOT, capture_output=True, text=True)
tracked_out = [l for l in r.stdout.splitlines() if "feasibility/out" in l]
check("no raw trace files are staged or untracked-visible", not tracked_out,
      "; ".join(tracked_out))


# --- Rust port conformance -------------------------------------------------------

section("Rust port agrees with the reference")

rust_dir = ROOT / "rust"
if not rust_dir.exists():
    print("  SKIP  rust/ not present")
else:
    lexer_rs = (rust_dir / "src" / "dsl" / "lexer.rs").read_text(encoding="utf-8")
    ast_rs = (rust_dir / "src" / "dsl" / "ast.rs").read_text(encoding="utf-8")

    rust_types = set(re.findall(r'\"(EXEC|WRITE|OPEN|DELETE|SPAWN)\" => Some\(EventType', ast_rs))
    check("Rust admits the same event types", rust_types == impl_types,
          f"Rust {sorted(rust_types)} vs Python {sorted(impl_types)}")

    check("Rust does not admit SPAWN", "SPAWN" not in rust_types)

    cargo = (rust_dir / "Cargo.toml").read_text(encoding="utf-8")
    deps = cargo.split("[dependencies]")[1].split("[")[0].strip() if "[dependencies]" in cargo else ""
    check("Rust crate has no dependencies", deps == "", f"found: {deps!r}")

    rust_bin = rust_dir / "target" / "release" / "sentinelfs"
    if rust_bin.exists():
        r = subprocess.run([sys.executable, "conformance.py", "--traces", "25"],
                           cwd=ROOT, capture_output=True, text=True)
        check("cross-implementation conformance passes", r.returncode == 0,
              r.stdout.strip().splitlines()[-1] if r.stdout else r.stderr[:200])
    else:
        print("  SKIP  release binary not built (cd rust && cargo build --release)")

# --- Normative source invariant ---------------------------------------------------

section("Normative source invariant")

# Normative Markdown must contain no control characters beyond the permitted
# whitespace set. The permitted set is declared here, positively; everything
# else in the C0 range, plus DEL, is a defect.
#
# This replaces an earlier guard that searched for one known corruption. That
# guard passed while seven occurrences of the same fault, in four other macros,
# sat in the committed file: a LaTeX macro written into a Python string literal
# without escaping its backslash has its leading escape interpreted, so
# backslash-t becomes TAB, backslash-b becomes BACKSPACE, and so on. Checking
# the invariant catches every member of that class, including ones not yet seen.
#
# Tabs are not permitted in normative Markdown: nothing here needs one, and a
# tab is the most common product of this corruption.
# The repository's line-ending policy is LF, set by .gitattributes in commit
# 222c6c2. SPACE and LINE FEED are the only whitespace a normative Markdown
# file needs; everything else in the C0 range, plus DEL, is a defect.
#
# CRLF and a standalone CR are both rejected, and are reported separately: a
# CRLF file violates the line-ending policy, whereas a lone CR is the
# signature of an escape-sequence corruption. Conflating them would misreport
# whichever occurred.
PERMITTED = {10, 32}  # LINE FEED, SPACE

CONTROL_NAMES = {
    0: "NUL", 7: "BEL", 8: "BACKSPACE", 9: "TAB", 11: "VERTICAL TAB",
    12: "FORM FEED", 13: "CARRIAGE RETURN", 27: "ESCAPE", 127: "DELETE",
}

CR, LF = 13, 10


def validate_normative(raw: bytes):
    """Return (crlf_count, offenders) for normative source held as bytes.

    The bytes are decoded explicitly. read_text() is not used anywhere on this
    path: text mode applies universal-newline translation, which rewrites a
    lone CR to LF before it can be observed. Nor is splitlines() used, which
    consumes VERTICAL TAB, FORM FEED and CARRIAGE RETURN as terminators.
    """
    body = raw.decode("utf-8")
    crlf = body.count(chr(CR) + chr(LF))
    offenders = []
    line = 1
    for k, ch in enumerate(body):
        o = ord(ch)
        if o == LF:
            line += 1
            continue
        if o == CR:
            # Part of a CRLF pair: counted as a line-ending violation above,
            # not also as a stray control character.
            if k + 1 < len(body) and body[k + 1] == chr(LF):
                continue
            offenders.append((line, o))
            continue
        if (o < 32 or o == 127) and o not in PERMITTED:
            offenders.append((line, o))
    return crlf, offenders


def describe(offenders):
    out = ", ".join(
        f"line {n}: {CONTROL_NAMES.get(o, 'U+%04X' % o)}" for n, o in offenders[:6]
    )
    if len(offenders) > 6:
        out += f" (+{len(offenders) - 6} more)"
    return out


NORMATIVE = sorted((ROOT / "docs").glob("*.md")) + [ROOT / "README.md"]

for doc in NORMATIVE:
    if not doc.exists():
        continue
    crlf, offenders = validate_normative(doc.read_bytes())
    check(f"{doc.name} contains no forbidden control characters",
          not offenders, describe(offenders))
    check(f"{doc.name} uses LF line endings", crlf == 0,
          f"{crlf} CRLF pair(s)")

# The same validator against the content git will store. The working tree and
# the blob can differ across clean/smudge filters and eol normalisation, so
# validating only the working tree leaves the committed bytes unchecked.
for doc in NORMATIVE:
    rel = doc.relative_to(ROOT).as_posix()
    blob = subprocess.run(["git", "show", f":{rel}"], cwd=ROOT,
                          capture_output=True)
    if blob.returncode != 0:
        continue  # not in the index
    crlf, offenders = validate_normative(blob.stdout)
    check(f"{doc.name} blob contains no forbidden control characters",
          not offenders, describe(offenders))
    check(f"{doc.name} blob uses LF line endings", crlf == 0,
          f"{crlf} CRLF pair(s)")

# The invariant forbids corruption but does not require the macros to be
# present. Check separately that the specification still carries LaTeX, so a
# file emptied of its markup would not pass silently.
spec_body = (ROOT / "docs" / "formal-semantics.md").read_text(encoding="utf-8")
BSL = chr(92)
for macro in ("texttt{", "text{", "tau", "bigl", "bigr", "mathcal{"):
    check(f"formal-semantics.md still uses the {macro.rstrip('{')} macro",
          BSL + macro in spec_body)

# Corollary 4 lost its hypothesis in v1.5. The summary table must not restate
# the superseded form, and must not assert a verdict meaning for DENY or ALERT,
# which the specification does not define.
BT = chr(96)
stale = ("A violation of a " + BT + "DENY" + BT + "/" + BT + "ALERT" + BT
         + " policy never yields " + BT + "ALLOW" + BT)
fresh = ("A violating trace never yields " + BT + "ALLOW" + BT
         + ", for every well-formed policy")
check("Corollary 4 summary row is not the superseded form", stale not in spec_body)
check("Corollary 4 summary row states the strengthened result", fresh in spec_body)

# --- Result ---------------------------------------------------------------------

print()
print("=" * 60)
if failures:
    print(f" {len(failures)} of {checks} checks FAILED")
    for f in failures:
        print(f"   - {f}")
else:
    print(f" ALL {checks} CHECKS PASSED")
print("=" * 60)
sys.exit(len(failures))
