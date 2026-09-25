# Phase 5B.0: Policy Combination — a Gap that Blocks the Kernel Experiments

**Status.** Analysis of a specification gap. No decision is made here, and no semantics are
invented. This document exists because the gap was found while sequencing the 5B experiments,
and it blocks the first of them.

---

## 1. The gap

The specification defines the decision for **one** policy (Definition 3):

$$D(P, \tau) = \begin{cases} \alpha & \text{if } \tau \models P \\ \texttt{ALLOW} & \text{otherwise} \end{cases}$$

and says of a policy set (§8, *Single-policy scope*):

> A policy set $\{P_1,\dots,P_r\}$ is evaluated by running the $r$ compiled automata
> independently on the same trace; because each $\delta_i$ is total and deterministic, the
> combined evaluation is deterministic as well. **Defining a combination operator on decisions
> … is deferred to a later version of this specification.**

`decision combination` is listed among the deferred constructs.

**A BPF LSM hook returns exactly one integer.** With $r$ policies active, $r$ decisions exist
and one value must be returned. The specification does not say which, or how it is derived.

This is not a detail an implementation may settle. It determines, for every event, whether the
operation proceeds — which is the entire enforcement behaviour of the deployed system.

## 2. Why this blocks 5B.1

5B.1 was to measure the cost of a naïve multi-policy evaluator: for each active policy, load
state, evaluate the transition, update state, collect the decision. The first three steps are
well defined. **"Collect the decision" is not**, and the cost of the evaluator depends on what
collecting means — in particular on whether it may stop early.

Measuring instruction counts for an evaluator whose output is undefined would produce a number
that describes nothing.

## 3. Two properties that hold regardless of the answer

Both follow from §8's independence and are worth stating before any combination rule is
chosen, because they constrain the rule.

### 3.1 Policy evaluation is order-free

Each automaton reads and writes only its own state, and no transition depends on another
policy. Evaluating the policies in any order therefore yields the same set of resulting
states.

This is a useful property: it permits parallel evaluation and removes any need to define a
policy ordering. A combination operator should preserve it, which means being **associative,
commutative and idempotent** — that is, a join on a lattice, which is what §8 anticipated.

### 3.2 State updates may not be short-circuited

This is the sharper constraint, and it is easy to get wrong.

Suppose the combination rule were "the first `DENY` wins". An implementation might then stop
evaluating once a `DENY` is found, since the returned value cannot change. **That is unsound.**

Under §8 every policy receives every event and advances independently. A policy skipped for
this event does not advance, so its state is wrong for every *subsequent* event. The verdict
for the current operation would be correct; the system's behaviour afterwards would not be.

So:

> The **decision** may be foldable and may admit early exit. The **state updates** may not.
> Every active policy must receive every event whose type its alphabet includes, whatever the
> combination rule decides.

An implementation may therefore short-circuit only the accumulation of the return value, never
the transition itself. This should be stated wherever the combination rule is, because it is
exactly the optimisation an implementer would reach for.

## 4. Why a single linear order may be the wrong shape

The obvious proposal is a total order — $\texttt{DENY} > \texttt{ALERT} > \texttt{ALLOW}$,
combination by maximum. It is associative, commutative, idempotent, and order-free, so it
satisfies §3.1.

But it loses information, because the three actions are not three points on one axis:

| Action | What it asks for |
|---|---|
| `DENY` | the operation must not proceed |
| `ALERT` | the operation is recorded; nothing is said about whether it proceeds |
| `ALLOW` | no violation was established |

If policy $P_1$ reaches violation with `DENY` and $P_2$ with `ALERT`, taking the maximum
yields `DENY` and **discards the alert**. Yet both policies fired, and a deployment would
reasonably expect the alert to be recorded as well as the operation blocked. The two are not
alternatives.

This suggests the decision is not one value but two: a **verdict** that the hook returns, and
a **set of policies that fired**, which the evidence layer records. Under that reading:

$$\text{verdict} = \begin{cases}\texttt{DENY} & \text{if any policy with action } \texttt{DENY} \text{ is in violation}\\ \texttt{ALLOW} & \text{otherwise}\end{cases}$$

with the set of violating policies — whatever their action — passed to evidence regardless.
`ALERT` then means "record, do not block", which is what the name suggests and what §3's
asymmetry note about `ALLOW` is consistent with.

That is a proposal, not a conclusion. It has at least one consequence worth weighing: it makes
`ALERT` and `ALLOW` indistinguishable *to the hook*, so an `ALERT` policy cannot influence
enforcement at all. Whether that is intended is a question for whoever settles this.

## 5. What must be decided

1. **The combination rule itself.** Whether decisions form a lattice under a total order, or
   decompose into a verdict plus a fired-policy set, or something else.
2. **Whether the rule preserves order-freedom** (§3.1). If it does not, a policy ordering must
   be defined and becomes part of the semantics.
3. **Whether `ALERT` participates in the verdict.** §4 suggests not; the specification does
   not say.
4. **That state updates are not short-circuitable** (§3.2), stated explicitly, because it is
   the natural optimisation and it is wrong.

Items 1–3 are language-level decisions of the same character as the scoping and reset
questions recorded in v1.2 §8: an implementation must not resolve them by picking whatever
the kernel makes convenient. Item 4 is a constraint on implementations that follows from the
existing semantics and could be stated immediately.

## 6. Effect on the 5B sequence

The sequence should be reordered:

| | Step | Depends on |
|---|---|---|
| **5B.0** | **policy combination semantics** | **nothing — blocks everything below** |
| 5B.1 | naïve multi-policy evaluator, measured | 5B.0 defines what it computes |
| 5B.2 | semantics-preserving dispatch | 5B.1 establishes whether it is needed |
| 5B.3 | verifier boundary: policy count × pattern length | 5B.1 |
| 5B.4 | state representation | 5B.1, and v1.3 for the correlation constraints |

5B.2 acquires a clean correctness criterion once 5B.0 exists: a dispatcher that indexes
policies by event type must produce, for every trace, the same per-policy states **and** the
same combined verdict as the naïve evaluator. That is testable by the same differential method
already used against the reference implementation, and it is the reason 5B.1 must be measured
before any optimisation is attempted — there is otherwise nothing to be equivalent *to*.
