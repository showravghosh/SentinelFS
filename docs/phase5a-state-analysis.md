# Phase 5A: Automaton State and Lifecycle Analysis

**Purpose.** Determine what state the enforcement model requires, and what operations must be
performed on it, **before** asking which BPF mechanisms can host it. Choosing a mechanism
first and then shaping the model to fit is the failure this phase exists to prevent; Phase 4
caught two instances of it, and §1 below is a third.

**Method.** The questions are answered from the specification where the specification answers
them, and from measurement where it does not. Nothing here is decided by what an eBPF map
happens to make convenient.

**Status.** Analysis. No architecture is selected and no code is written.

---

## 1. The scoping question, and what the specification already says

> **Can the first event of a policy come from one process and the second from another?**

This is the question on which every other state decision depends: map keys, cardinality,
inheritance across `fork`, expiry, memory bounds, cleanup, and reload semantics all follow
from it. It must be settled from the formal model, not from what Linux makes convenient.

**The specification already answers it.** §1.2:

> A trace models the sequence of security-relevant events observed at **a monitored host**, in
> observation order.

One trace, host-wide. Definition 1 defines violation as embedding in *that* trace. Nothing in
the document scopes a trace to a process, a session, or a lineage; §8 states only that the
language cannot express constraints relating a process to its ancestors.

Therefore, under v1.1: **there is exactly one automaton instance per policy, and any
process's events advance it.**

### 1.1 What that means in practice

Measured, not argued. A policy shaped exactly like the repository's canonical example was
evaluated against the unmodified host-wide trace recorded in Phase 2:

```
POLICY cross_process_demo
VERSION 1
ON   EXEC("/usr/bin/grep")
THEN EXEC("/usr/bin/python3")
THEN EXEC("/usr/sbin/ip")
DENY
```

| | |
|---|---|
| Trace | 491 events, host-wide, unmodified |
| Final state | `q3` |
| Decision | **DENY** |

The three matching events:

| Event | Transition | Process |
|---|---|---|
| `EXEC("/usr/bin/grep")` | q0 → q1 | pid 40208, `comm=grep` |
| `EXEC("/usr/bin/python3")` | q1 → q2 | pid 40212, `comm=python3` |
| `EXEC("/usr/sbin/ip")` | q2 → q3 | pid 40217, `comm=ip` |

Three unrelated processes, no causal relationship between them, and the policy fires.

**This is a correct match, not a false positive.** Relative to Definition 1 the executor
behaved exactly as specified: the pattern embeds in the host-wide trace, so the trace violates
the policy. It resembles a false positive only relative to the *causal* interpretation a
reader attributes to the policy — that one process did these things in sequence — and that
interpretation is not what the specification states. The distinction matters: the defect, if
there is one, is in what the language can express, not in the compiler, the executor, or the
theorems.

### 1.2 Why this matters more than it first appears

Three properties compound:

1. **The trace is host-wide**, so any process contributes.
2. **The violation state is absorbing** (Theorem 3), so a policy that fires once stays fired.
3. **Events are embedded, not contiguous** (§1.3), so arbitrary unrelated activity between the
   matching events does not prevent the match.

Together: a policy naming three events that each occur routinely on a host will reach its
violation state during ordinary operation, permanently, regardless of whether anything
malicious occurred. The canonical `protect_shadow` policy has this shape. It names
`/usr/bin/python3`, `/bin/bash` and a write to `/etc/shadow` — the first two are ordinary, and
a `passwd` change supplies the third.

The intent a reader attributes to that policy — *a Python process spawned a shell which wrote
to the password file* — is a causal claim about one lineage. **The language cannot express it,
and the semantics do not mean it.**

### 1.3 This is a specification question, not an implementation one

An adapter must choose what its automaton state is keyed by. The options are not
interchangeable:

| Keying | Semantics |
|---|---|
| one instance per policy | matches §1.2 as written; cross-process matching as demonstrated |
| one instance per process | narrower than the specification; a chain spanning `fork`+`exec` would not match |
| one instance per lineage | narrower still, and not expressible in the current language |

Had implementation begun before this was settled, the adapter would have picked one — most
likely per-process, because it is the obvious BPF map key — and would then have been
**narrower than the specification it claims to implement**, silently. Theorem 2 would still
hold of the compiler, and the deployed system would still not do what the specification says.

**No option is selected here.** The decision belongs to a deliberate revision, informed by
whether host-wide correlation is intended — it does allow patterns spanning processes to be
detected — or whether the gap between the specified semantics and the causal reading in §1.1
is itself the problem.

---

## 2. What state is required

Independent of the scoping decision, evaluating a policy requires:

| State | Cardinality | Determined by |
|---|---|---|
| automaton state index | one per instance | scoping decision (§1) |
| compiled policy | one per policy | policy set; static between reloads |
| policy version and hash | one per policy | static between reloads |
| descriptor-to-pathname association | one per open descriptor of interest | A1b; established at `file_open`, released at `file_free_security` |

The last is the only per-object state Phase 4 established as necessary, and it is required
regardless of §1's outcome: `WRITE(p)` has no argument without it
([`phase4-findings.md`](phase4-findings.md) §3.3).

**Upper bound on instances** is a direct function of §1. One per policy is O(policies). One
per process is O(policies × live processes). One per lineage is unbounded without an expiry
rule, because lineages are created faster than they are reaped.

---

## 3. What must be available at a transition

From Definition 6, a transition needs only the current state and the event. In practice the
enforcement path additionally requires:

| Required | Why | Available at the hook? |
|---|---|---|
| event type | selects the transition | yes, by which hook fired |
| pathname argument | structural equality against the pattern | yes, per the §1.4 mappings — for `WRITE` only via the correlation map |
| current automaton state | the transition's domain | depends on §1: a lookup keyed by whatever scoping decides |
| policy identity and version | binds the decision to what produced it | static; resolvable from the compiled policy |
| process identity | **not required for the transition** under §1.2 | yes, and needed for evidence regardless |

Process identity is worth noting explicitly: under the current semantics it is *not* an input
to the decision. It is required for the evidence record — which name reached which object, by
which process — but the automaton does not consult it.

---

## 4. Lifetime

Unanswerable in general until §1 is decided. What can be stated now:

- **Correlation state** (descriptor → pathname) has a well-defined lifetime bounded by the
  descriptor: created at `file_open`, released at `file_free_security`. Phase 4 implemented
  this and it is the one lifetime that is settled.
- **Automaton state under per-policy scoping** has system lifetime and never needs expiry,
  but also never resets — which is §1.2's problem.
- **Automaton state under per-process scoping** would end at process exit, requiring a hook on
  exit and raising the question of inheritance across `fork`.
- **Reset semantics do not exist in the specification.** There is no construct for a policy
  instance to return to `q0`. Theorem 3 makes the violation state absorbing by design. Any
  expiry or reset rule is therefore a semantic addition, not an implementation detail.

---

## 5. Synchrony

| Operation | Must be synchronous | Reason |
|---|---|---|
| transition evaluation | **yes** | the verdict is the hook's return value |
| state lookup | **yes** | input to the transition |
| state update | **yes** | a later event in the same chain must observe it |
| pathname resolution for `WRITE` | **yes** | the argument is required to evaluate the transition |
| `ALLOW` / `DENY` return | **yes** | it *is* the enforcement |
| evidence record construction | no | the decision is already made |
| evidence hashing and chaining | no | Phase 6 concern |
| reporting, statistics, diagnostics | no | |

The synchronous set is what constrains the architecture. Everything in it must complete inside
a security hook, which rules out any design requiring a userspace round trip on the decision
path — though that remains to be measured rather than assumed.

---

## 6. Concurrency

Not yet analysed, and it interacts with §1. If one instance per policy is retained, concurrent
processes contend on a single state cell, and the order in which their events are applied
determines the outcome. Assumption A2 asserts order preservation for *observation*; whether it
extends to *concurrent* observation on multiple CPUs is a separate claim that Phase 2 did not
test — its workloads were single-process.

This should be measured before any architecture is chosen.

---

## 7. What Phase 5A has established

1. **The specification already answers the scoping question**, and the answer is host-wide,
   one instance per policy (§1).
2. **That answer produces cross-process matching**, demonstrated on a real host trace: three
   unrelated processes drove a policy to `DENY` (§1.1).
3. **The canonical example policy has this shape**, so the repository's own illustration does
   not mean what a reader would take it to mean (§1.2).
4. **Correlation state for `WRITE` is required regardless** of how scoping is decided, and its
   lifetime is settled (§2, §4).
5. **The synchronous set is identified** and excludes everything the evidence layer does (§5).
6. **Concurrency is untested** and assumption A2 has only been checked single-process (§6).

## 8. What must be decided before an architecture is chosen

- **The scoping decision** (§1.3). This is a specification question. Options: retain host-wide
  semantics and record the consequence of §1.1 explicitly, so that policy authors are not
  misled by the causal reading; or introduce a scoping construct, which is a language change
  and a v1.2 revision. The implementation must not resolve this by choosing a narrower map
  key.
- **Whether a reset or expiry rule is needed** (§4), which is likewise semantic.
- **Whether A2 holds under concurrent multi-CPU observation** (§6), which is measurable and
  should be measured.

Only after those does the comparison of candidate architectures become meaningful, because
only then is it known what the architecture must support.
