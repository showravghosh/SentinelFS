# Phase 5B.0-F: The Decision Domain and the Combination Function

**Purpose.** Develop the formal groundwork for $F$, the function taking the decisions of
several policies to the single verdict an enforcement mechanism returns. This document
defines the domain, establishes a prerequisite question that must be answered first, presents
three candidate structures with their properties, and identifies which choice matches which
security intent.

**Status.** Formal development, not a decision. The choice among the candidates is about what
the system is for, not about what Linux permits, and §6 states it as a question.

**No theorem is affected.** Theorems 1–3, Lemma 1 and Corollaries 1.1, 2.1, 3.1 and 4 are
statements about the automaton compiled from a *single* policy and its behaviour over
$\Sigma^{*}$. Nothing here touches that construction. The questions below concern what a *set*
of policies yields and what a deployed system returns, which sits above the automaton rather
than inside it. This is a boundary in the language, not a correction to the correctness
result.

One consequence is worth stating precisely, because it is easy to read the wrong way.
Corollary 4 — that a violating trace of a `DENY` or `ALERT` policy never yields `ALLOW` — is
a per-policy statement and stands unchanged. Its multi-policy analogue, that a system refuses
an operation when any active `DENY` policy is in violation, **cannot yet be stated**, because
it quantifies over a verdict that is undefined. That analogue is among the things blocked
here, and it is the property a deployment would actually rely on.

---

## 1. A prerequisite: the `ALLOW` action is currently inert

Before $F$ can be defined, one thing about its inputs must be settled.

The grammar admits three actions (§2):

```ebnf
action = "DENY" | "ALERT" | "ALLOW" ;
```

and Definition 3 gives

$$D(P, \tau) = \begin{cases} \alpha & \text{if } \tau \models P \\ \texttt{ALLOW} & \text{otherwise.}\end{cases}$$

For a policy whose action is `ALLOW`, both branches yield `ALLOW`. **The decision is the same
whether the policy fired or not.** Confirmed against the reference implementation:

| `ALLOW`-action policy | decision | `triggered` | state |
|---|---|---|---|
| pattern matched | `ALLOW` | true | `q1` |
| pattern not matched | `ALLOW` | false | `q0` |

The automaton state distinguishes the two cases; the decision does not. So an `ALLOW`-action
policy is admitted by the grammar, compiles, loads, evaluates, advances its automaton — and
can never influence any decision.

This matters for $F$ because it determines whether $F$ has anything to resolve:

| Reading of the `ALLOW` action | Consequence for $F$ |
|---|---|
| **(a) Inert** — the policy names a pattern but requests nothing | $F$ never faces a conflict; a violated `ALLOW` policy contributes nothing |
| **(b) Override** — the policy affirmatively permits, even where another policy denies | $F$ must resolve genuine conflicts, and conflict analysis becomes necessary rather than deferred |

§3's existing note leans toward (a): *"An `ALLOW` decision therefore means 'no policy
violation was established', not 'the trace was affirmatively permitted by a rule'."* But that
note is about the `ALLOW` **decision**, which Definition 3 conflates with the `ALLOW`
**action**. The two are not obviously the same thing, and the language would not carry the
action at all if it were meant to do nothing.

**Under reading (a), the grammar admits a construct with no effect**, which is a defect of a
different kind: the language should not accept what it cannot mean. Either the action is
removed, or it is given meaning.

---

## 2. The domain

Let $\mathcal{I}$ be the identifiers of the active policies and $\alpha : \mathcal{I} \to
\mathcal{A}$ their actions. For a trace $\tau$ define the **violated set**

$$W(\tau) \;=\; \{\, i \in \mathcal{I} \;\mid\; \tau \models P_i \,\}.$$

By MP1, membership of $W(\tau)$ is determined independently per policy. By MP2 it does not
depend on evaluation order. $W(\tau)$ is therefore well defined without reference to any
ordering, and it is the natural object from which a verdict is derived.

The enforcement mechanism requires a verdict in a two-valued domain:

$$\mathcal{V} = \{\texttt{PERMIT}, \texttt{REFUSE}\}$$

Note that $\mathcal{V} \neq \mathcal{A}$. The actions are not three points on one axis: `DENY`
asks that the operation not proceed, `ALERT` asks that it be recorded and says nothing about
whether it proceeds, and `ALLOW` — under reading (a) — asks for nothing. Only `DENY` bears on
$\mathcal{V}$.

---

## 3. Three candidate structures

### F1 — join on a totally ordered $\mathcal{A}$

Order $\texttt{ALLOW} < \texttt{ALERT} < \texttt{DENY}$ and take $F = \max$.

| Property | Holds | Why |
|---|---|---|
| commutative | yes | max is |
| associative | yes | max is |
| idempotent | yes | $\max(x,x)=x$ |

Simple, and a single small integer in the kernel. But it discards $W(\tau)$: if one policy
fires `DENY` and another `ALERT`, the result is `DENY` and the alert is gone, although both
policies fired and a deployment would expect both recorded. It also cannot say *which*
policies fired, which the evidence layer requires regardless.

### F2 — join on the powerset, verdict by projection

Take the multi-policy decision to be $W(\tau)$ itself, combined by union:

$$(\mathcal{P}(\mathcal{I}), \cup)$$

is a join-semilattice. Union is commutative, associative and idempotent, so all three
properties of §8 hold, and by construction the result is independent of evaluation order.

The verdict and the alerts are then **projections** of $W(\tau)$:

$$\mathrm{verdict}(W) = \begin{cases}\texttt{REFUSE} & \text{if } \exists\, i \in W:\ \alpha(i) = \texttt{DENY}\\[2pt] \texttt{PERMIT} & \text{otherwise}\end{cases}
\qquad
\mathrm{alerts}(W) = \{\, i \in W \mid \alpha(i) = \texttt{ALERT} \,\}$$

**F1 can be represented as a lossy projection of F2.** That is a statement about the two
constructions, not an argument that F2 is the right formal decision domain: whether the extra
information belongs in the *semantics* — as opposed to being produced alongside them for the
evidence layer — is itself a specification choice, taken up in §3.4.

The separation does match the contract of 5A.9: the verdict is on the synchronous path, the
set is what evidence records, and evidence is off it.

Under reading (a), a violated `ALLOW`-action policy appears in $W(\tau)$ and contributes to
neither projection — visible in evidence, inert for enforcement.

### 3.4 Two designs that agree on the verdict and differ in the semantics

Even with the violated set available, there are two distinct ways to formalise what a
multi-policy evaluation *yields*, and they are not interchangeable.

**D1 — the decision is the set; enforcement is derived.**

$$D^{*}(\{P_i\}, \tau) \;=\; W(\tau) \qquad\text{with}\qquad \mathrm{enforcement}: \mathcal{P}(\mathcal{I}) \to \mathcal{V}$$

Definition 3 keeps its shape — a decision function — but its codomain becomes
$\mathcal{P}(\mathcal{I})$. Enforcement sits *outside* the decision domain, as an
interpretation applied to it. The semantics then say what happened; a deployment decides what
to do about it.

**D2 — the result is a pair.**

$$D^{*}(\{P_i\}, \tau) \;=\; \bigl(W(\tau),\; v\bigr) \in \mathcal{P}(\mathcal{I}) \times \mathcal{V}$$

Both the record and the verdict are inside the formal domain, so the specification states not
only what was violated but what the system does about it.

| | D1 | D2 |
|---|---|---|
| shape of Definition 3 | unchanged; codomain widened | changed to a product |
| enforcement is | an interpretation outside the semantics | part of the semantics |
| a conforming implementation must agree on | the violated set | the violated set **and** the verdict |
| Corollary 4's multi-policy analogue | must be restated over the interpretation | follows directly |

The distinction matters for conformance testing. Under D1, two implementations agreeing on
$W(\tau)$ conform even if they enforce differently, and the enforcement rule has to be pinned
down somewhere else. Under D2 the verdict is part of what conformance means, which is stricter
and is probably what a security specification wants — but it commits the document to stating
the enforcement rule rather than leaving it to a deployment.

### F3 — with override, under reading (b)

If `ALLOW` affirmatively permits:

$$\mathrm{verdict}(W) = \begin{cases}\texttt{REFUSE} & \text{if } (\exists\, i \in W: \alpha(i)=\texttt{DENY}) \;\wedge\; (\nexists\, j \in W: \alpha(j)=\texttt{ALLOW})\\[2pt] \texttt{PERMIT} & \text{otherwise}\end{cases}$$

This is still a function of the set, so it remains order-independent. But it is not a join on
a totally ordered $\mathcal{A}$ in the way F1 is: `ALLOW` would have to sit *above* `DENY`,
inverting the natural reading of the names, and two policies can now genuinely conflict. The
conflict analysis that §8 defers becomes required rather than optional, because an
administrator needs to know when one policy silently disables another.

---

## 4. Comparison

| | F1 total order | F2 powerset join | F3 override |
|---|---|---|---|
| order-independent | yes | yes | yes |
| associative | yes | yes | yes |
| idempotent | yes | yes | yes |
| preserves which policies fired | **no** | yes | yes |
| `ALERT` survives alongside `DENY` | **no** | yes | yes |
| `ALLOW` action has meaning | no | no | **yes** |
| conflicts possible | no | no | **yes** |
| requires conflict analysis | no | no | **yes** |
| verdict computable as a scalar in-kernel | yes | yes, by projection | yes, by projection |

F2 carries strictly more information than F1 and satisfies the same properties, and F1 is
recoverable from it. Whether that information belongs in the formal decision domain is the
question of §3.4, and is separate from which combination rule is chosen.

The substantive choice is between **F2 under reading (a)** and **F3 under reading (b)**, and
it is the answer to §1.

---

## 5. What each choice commits to

**Choosing F2 (reading (a))** commits to: policies may forbid and may record, but may not
permit. The system has no notion of an exception. `ALLOW` as an action then has no meaning and
should be removed from the grammar, which is consistent with the observability criterion of
§1.1 — that already excludes constructs which cannot mean anything.

**Removing `ALLOW` is a language revision, not an implementation cleanup.** It changes which
policy texts the language accepts: a policy that compiles today would be rejected afterwards.
It therefore requires its own specification revision and tag, and every earlier revision must
remain reproducible, exactly as `v1.0-spec` remains reproducible after `SPAWN` was removed.
This is the second construct to be removed from the language by this process, and for the same
reason in both cases: the language should not admit what it cannot mean.

**Choosing F3 (reading (b))** commits to: policies may grant exceptions, and therefore may
conflict. This is more expressive and is what mandatory access control systems generally
provide, but it requires defining what happens when an exception and a prohibition overlap,
detecting such overlaps before deployment, and explaining to an administrator why a policy
that looks like it forbids something does not. §8's deferred conflict analysis becomes a
prerequisite rather than a future nicety.

A third position is available and should be named: **retain `ALLOW` in the grammar, define it
as inert, and say so.** That is the least work and the least honest, because the language
would continue to accept a construct documented as having no effect.

---

## 6. The decision

Three questions, in dependency order. The first determines the others.

1. **Does the `ALLOW` action affirmatively permit, or does it request nothing?** Under (a) it
   is inert and should be removed; under (b) it is an override and conflicts become real.
2. **Is $F$ the powerset join with verdict by projection (F2/F3), or the scalar join on
   $\mathcal{A}$ (F1)?** F2 is recommended even if a scalar is wanted in the kernel, because
   F1 is its projection and the evidence layer needs the set regardless.
3. **Does `ALERT` participate in the verdict at all?** Under every candidate above it does not
   — an `ALERT` policy records and does not block. That is what the name suggests, but the
   specification has never said it.

These are language-level decisions of the same character as scoping and reset. Once taken,
they become a revision, and only then does 5B.1 have a defined evaluator to measure.

**Recommendation.** F2 under reading (a), with `ALLOW` removed from the action grammar. It
preserves the information the evidence layer needs, satisfies every algebraic property without
argument, keeps the enforcement verdict as a cheap projection on the synchronous path, and
avoids introducing override semantics the language never suggested and the threat model has
not asked for. The cost is that exceptions become inexpressible, which is a real limitation
and should be recorded as one rather than discovered later.
