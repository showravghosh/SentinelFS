# SentinelFS: Formal Semantics of the Core Policy Language (v1)

**Status:** working specification for the core language, at revision **v1.5**.

**Revision history.** No revision has changed the alphabet, the grammar, the compilation
function, or any of Theorems 1–3, Lemma 1 or the corollaries. Those are statements about an
automaton over $\Sigma$ and are indifferent to what its arguments denote or how a trace is
scoped. What the revisions change is what the specification *says*, where v1.0 left something
implicit that an implementation would otherwise have to decide for itself.

| Revision | Tag | Change |
|---|---|---|
| v1.0 | `v1.0-spec` | alphabet frozen after the Phase 2 study removed `SPAWN` |
| v1.1 | `v1.1-spec` | §1.4 event identity; assumption A1c; Proposition 2; the naming-evasion threat model in §7. Forced by measurement: different hooks report different strings for the same operation, and none names the object. See [`phase4c-findings.md`](phase4c-findings.md) |
| v1.2 | `v1.2-spec` | two statements in §8: the host-wide trace of §1.2 permits a pattern to be satisfied across unrelated processes, and no reset or expiry construct exists. Both were already consequences of v1.1; each is a point at which an implementation could narrow or widen the semantics while appearing to implement them. See [`phase5a-state-analysis.md`](phase5a-state-analysis.md) |
| v1.3 | `v1.3-spec` | §7 names correlation-capacity exhaustion as a threat, declares $C$ as a security parameter, forbids silent eviction, and requires insertion failure to be observable. A1b already implied the condition; v1.3 states the mechanism and what an implementation must do about it. See [`phase5a-e3-findings.md`](phase5a-e3-findings.md) |
| v1.4 | `v1.4-spec` | §8 states MP1–MP3 for multi-policy evaluation, and records that the host verdict function $F$ over several policies' decisions is undefined. MP1–MP3 follow from existing semantics; $F$ is a genuine gap that blocks multi-policy enforcement. See [`phase5b-combination.md`](phase5b-combination.md) |
| v1.4 corrected | in `v1.4-spec` lineage | the v1.4 text stated that MP2 requires $F$ to be associative, commutative and idempotent. That was imprecise: only commutativity is required by order-independence, associativity is required for parallel reduction, and idempotence does not follow from MP2. The claim is corrected in place and the original is recorded here, per methodology rule M6 |
| **v1.5** | **this revision** | **a language revision.** `ALLOW` is removed from the action domain, which changes the accepted language: a policy that compiled under v1.4 is rejected under v1.5. $\mathcal{A}$ and the decision domain $\mathcal{D}$ are now distinguished, since writing both as $\mathcal{A}$ is what made an `ALLOW` action meaningless. Corollary 4 is strengthened by losing a now-vacuous hypothesis; no other formal result is affected. The loss of affirmative permission is recorded in §8 as a limitation and a deferred construct. See [`phase5b0f-decision-domain.md`](phase5b0f-decision-domain.md) |

This document defines the syntax, the trace semantics, the compilation function, and states
and proves the determinism and compilation-correctness theorems. It is the normative
reference: the Python reference implementation and any future implementation (Rust,
in-kernel) are correct exactly insofar as they agree with it.

---

## 1. Preliminaries

### 1.1 Events

Let $\mathcal{T} = \{\texttt{EXEC}, \texttt{WRITE}, \texttt{OPEN}, \texttt{DELETE}\}$
be the finite set of **event types**, and let $\mathcal{S}$ be the set of finite strings over a
fixed character set (in practice, filesystem paths and executable names).

An **event** is a pair $e = (t, a)$ with $t \in \mathcal{T}$ and $a \in \mathcal{S}$. The
**event alphabet** is

$$\Sigma = \mathcal{T} \times \mathcal{S}.$$

Events are compared by structural equality: $(t,a) = (t',a')$ iff $t = t'$ and $a = a'$.

**Observability criterion.** Every type in $\mathcal{T}$ corresponds to a single kernel event
that names its own argument. This is a deliberate admission criterion, not a coincidence: a
construct whose argument cannot be determined at the moment the event occurs is not admitted
to the alphabet.

An earlier version of this specification included a type $\texttt{SPAWN}$, intended to denote
the creation of a child process running a named binary. It was removed after the Phase 2
feasibility study established that no such kernel event exists: at `fork` time the child is a
copy of its parent and the binary it will later execute has not been named, so the kernel
cannot report it. The chain that motivated $\texttt{SPAWN}$ is expressible with
$\texttt{EXEC}$ alone. See [`phase2-findings.md`](phase2-findings.md) §4.1.

### 1.2 Traces

A **trace** is a finite sequence of events $\tau = \langle f_1, \dots, f_m \rangle \in \Sigma^*$,
with $|\tau| = m$. We write $\varepsilon$ for the empty trace and $\tau \cdot e$ for the trace
$\tau$ extended by the event $e$.

A trace models the sequence of security-relevant events observed at a monitored host, in
observation order. The ordering assumption is made explicit in §7 (assumption A2).

### 1.3 Subsequence embedding

For sequences $\sigma = \langle e_1, \dots, e_n \rangle$ and $\tau = \langle f_1, \dots, f_m \rangle$,
write $\sigma \sqsubseteq \tau$ ("$\sigma$ embeds in $\tau$") iff there exist indices

$$1 \le j_1 < j_2 < \cdots < j_n \le m \quad\text{such that}\quad f_{j_k} = e_k \ \text{ for all } k \in \{1,\dots,n\}.$$

That is, the events of $\sigma$ occur in $\tau$ in the given order, though not necessarily
contiguously. By convention $\langle\rangle \sqsubseteq \tau$ for every $\tau$.

Embedding, rather than factor (contiguous substring) containment, is the intended reading
of the `THEN` operator: unrelated events occurring between the events named by a policy
must not prevent the policy from applying.

### 1.4 Event identity: arguments are pathnames, not objects

*Added in revision v1.1. The v1.0 text left the notion of identity implicit, which the Phase 4
experiments showed to be a gap rather than an omission: different hooks report different
strings for the same operation, and no available notion names the object. See
[`phase4-findings.md`](phase4-findings.md), [`phase4b-findings.md`](phase4b-findings.md),
[`phase4c-findings.md`](phase4c-findings.md).*

The argument $a$ of an event $(t, a)$ is a **pathname observed for the operation**. It is not
an identifier for a filesystem object, and the language provides no way to name an object
independently of a path to it.

For each type, the pathname is defined as follows:

| Event | $a$ denotes |
|---|---|
| $\texttt{EXEC}(p)$ | the pathname supplied as the argument to the execution interface, before resolution of symbolic links |
| $\texttt{OPEN}(p)$ | the pathname to which the kernel resolved the opened file at the time of opening |
| $\texttt{WRITE}(p)$ | see below: the pathname associated with the written descriptor, established from an observed opening, subject to A1b |
| $\texttt{DELETE}(p)$ | the pathname of the directory entry removed |

$\texttt{WRITE}$ requires the fuller statement, because it is the one type whose argument is
not discovered at the moment the event occurs:

> $\texttt{WRITE}(p)$ denotes a write operation on a filesystem descriptor whose associated
> pathname $p$ was established from an observed file-opening event, subject to A1b.

The descriptor carries no pathname of its own, and the hook at which a write is observed
cannot resolve one (see [`phase4-findings.md`](phase4-findings.md) §3.2). A write through a
descriptor whose opening was not observed — one inherited across `fork` from before the
monitor attached, or referring to a non-filesystem object such as a pipe or socket —
therefore produces no $\texttt{WRITE}(p)$ event for any $p$, rather than producing one with a
guessed or empty argument.

These notions are deliberately not uniform. $\texttt{EXEC}$ names the pathname the caller
supplied because that value is available and is what a policy author writes; the remaining
types name a resolved pathname because no unresolved pathname survives to the point at which
those operations are observed. The consequence is stated in §1.4.2 rather than concealed by a
uniform-sounding definition.

#### 1.4.1 A pathname is not an object identifier

> **Proposition 2 (Pathname is not object identity).** Neither implication holds:
> $$\text{same object} \;\not\Rightarrow\; \text{same reported pathname}$$
> $$\text{same reported pathname} \;\not\Rightarrow\; \text{same object}$$

This is an empirical claim about Linux, not a theorem. Both directions were measured, with
the inode serving as independent evidence of object identity
([`phase4c-findings.md`](phase4c-findings.md) §1):

- **Left to right fails.** One object (inode 1147) was reached under three pathnames that a
  policy naming the original would not match: a second hard link, a bind mount, and the name
  it was given by a rename.
- **Right to left fails.** After the object was deleted and a new file created under the same
  name, the pathname was unchanged while the object was different (inode 1147 became 1150).

A hard link is the clearest case: a file with several links has no distinguished name, so
there is nothing canonical for the kernel to report, and the reported pathname is whichever
one the operation used.

#### 1.4.2 What a policy therefore constrains

A policy naming a pathname constrains operations that reach an object **by that pathname**.
It does not constrain operations reaching the same object by another pathname, and it does
not distinguish that object from a different object later given the same pathname.

$\texttt{EXEC}$ is additionally weaker than the other three with respect to symbolic links,
because it names the supplied pathname: execution through a symbolic link does not match a
policy naming the link's target, whereas opening through a symbolic link does match a policy
naming the target. This asymmetry is a consequence of which value each hook makes available.
It is a difference of degree rather than of kind, since §1.4.1 establishes that none of the
four types provides object identity.

#### 1.4.3 Identity models not adopted

| Model | Property | Why not adopted in v1 |
|---|---|---|
| Pathname as supplied | human-readable; can name a path that does not yet exist | not object-invariant; symbolic links evade |
| Resolved pathname | removes symbolic-link ambiguity | still names a route; hard links, bind mounts, renames evade; replacement produces a false match |
| Device and inode | identifies an object directly; resists every evasion measured | cannot name an object that does not yet exist; identity changes when an object is deleted and recreated, so the binding an attacker breaks trivially; not writable by a human |
| Label carried on the object | identity independent of any pathname; expressible in policy text | requires a trusted labelling mechanism, a lifecycle for labels, and a different policy language; a larger design than v1 |

Label-based identity is the principled answer to §1.4.1 and is recorded here as future work
rather than omitted. Adopting it would change the policy language and the semantics of
Definition 1, and would require its own feasibility phase.

---

## 2. Syntax

The v1 core language is defined by the following grammar, in EBNF. Terminals are quoted.

```ebnf
policy      = "POLICY" identifier
              "VERSION" number
              rule ;

rule        = "ON" event { "THEN" event } action ;

event       = event-type "(" string ")" ;

event-type  = "EXEC" | "WRITE" | "OPEN" | "DELETE" ;

action      = "DENY" | "ALERT" ;

identifier  = letter { letter | digit | "_" } ;
number      = digit { digit } ;
string      = '"' { character - '"' } '"' ;
```

**Design restriction.** The language is deliberately confined to a regular,
sequential event-pattern fragment. It provides no boolean connectives, no negation, no
quantification, no arithmetic, no timing constraints, and no cross-process relational
constraints. This restriction is a design decision, not an oversight: it is what makes
deterministic compilation into finite-state automata possible and keeps the
compilation-correctness argument of §6 tractable and checkable by hand. Extensions are
discussed in §8.

### 2.1 Abstract syntax and well-formedness

A **policy** is a tuple

$$P = (\mathit{name}, \mathit{ver}, \sigma, \alpha)$$

where $\mathit{name}$ is an identifier, $\mathit{ver} \in \mathbb{N}$ is a version number,
$\sigma = \langle e_1, \dots, e_n\rangle \in \Sigma^{*}$ is the **event pattern**, and
$\alpha \in \mathcal{A}$ is the **action**, where

$$\mathcal{A} = \{\texttt{DENY}, \texttt{ALERT}\}.$$

$P$ is **well-formed** iff

- **WF1.** $n \ge 1$ (the pattern contains at least the `ON` event);
- **WF2.** $\mathit{ver} \ge 1$;
- **WF3.** $\mathit{name}$ is a non-empty identifier;
- **WF4.** every $e_i = (t_i, a_i)$ has $t_i \in \mathcal{T}$ and $a_i \neq \epsilon$
  (no empty argument).

All statements below are made for well-formed policies. Well-formedness is decidable by
inspection and is checked by the validator of the reference implementation.

---

## 3. Trace semantics

The meaning of a policy is the set of traces that violate it.

> **Definition 1 (Violation).** For a well-formed policy $P = (\mathit{name}, \mathit{ver}, \sigma, \alpha)$
> and a trace $\tau \in \Sigma^*$,
> $$\tau \models P \quad :\iff \quad \sigma \sqsubseteq \tau.$$

> **Definition 2 (Violation language).** $L(P) = \{\, \tau \in \Sigma^* \mid \tau \models P \,\}$.

Note that Definition 1 is given directly on the abstract syntax of $P$ and makes no
reference to any automaton, compiler, or implementation. This independence is what makes
it usable as a specification against which the compiler is judged, and as the oracle for
the differential testing described in §9.

> **Definition 3 (Decision).** The decision function $D : \mathcal{P} \times \Sigma^* \to \mathcal{D}$
> is
> $$D(P, \tau) = \begin{cases} \alpha & \text{if } \tau \models P \\ \texttt{ALLOW} & \text{otherwise.} \end{cases}$$

where the **decision domain** is

$$\mathcal{D} = \mathcal{A} \cup \{\texttt{ALLOW}\} = \{\texttt{DENY}, \texttt{ALERT}, \texttt{ALLOW}\}.$$

**Actions and decisions are different sets.** *Revised in v1.5.* Earlier revisions wrote both
as $\mathcal{A}$, and that conflation is what made an `ALLOW` action meaningless: with
$\texttt{ALLOW} \in \mathcal{A}$, both branches of Definition 3 returned `ALLOW` for such a
policy, so its decision was the same whether it had fired or not. The sets are now
distinguished. An author may write `DENY` or `ALERT`; the evaluator may return either of those
or `ALLOW`.

An `ALLOW` decision therefore means "no policy violation was established", not "the trace
was affirmatively permitted by a rule" — and no policy can request it, because it is not an
action. §8 discusses the consequences.

---

## 4. Security automata

> **Definition 4 (Security automaton).** A security automaton is a tuple
> $$A = (Q, \Sigma, \delta, q_0, F)$$
> where $Q$ is a finite set of states, $\Sigma$ is the event alphabet, $\delta : Q \times \Sigma \to Q$
> is a **total** transition function, $q_0 \in Q$ is the initial state, and $F \subseteq Q$
> is the set of violation states.

The **extended transition function** $\delta^{*} : Q \times \Sigma^{*} \to Q$ is defined by
structural recursion on traces:

$$\delta^{*}(q, \varepsilon) = q, \qquad \delta^{*}(q, \tau \cdot e) = \delta\big(\delta^{*}(q, \tau),\, e\big).$$

> **Definition 5 (Acceptance).** $A$ **accepts** $\tau$ iff $\delta^{*}(q_0, \tau) \in F$.
> We write $L(A) = \{\tau \in \Sigma^* \mid A \text{ accepts } \tau\}$.

**Remark (finiteness of the alphabet).** $\Sigma = \mathcal{T} \times \mathcal{S}$ is
countably infinite, whereas finite automata are conventionally defined over a finite
alphabet. This is a presentational matter only. Fix a policy $P$ with pattern
$\langle e_1,\dots,e_n\rangle$ and define the equivalence

$$e \sim_P e' \quad :\iff \quad \forall i \in \{1,\dots,n\}:\ (e = e_i \leftrightarrow e' = e_i).$$

$\sim_P$ has at most $n+1$ classes, and the transition function constructed in §5 is
constant on each class, so it factors through the finite quotient $\Sigma/{\sim_P}$. The
automaton is therefore a genuine finite automaton over an alphabet of size at most $n+1$,
and the implementation realises this by finitely many equality tests rather than by
tabulating $\Sigma$.

---

## 5. Compilation

> **Definition 6 (Compiler).** The compilation function $C$ maps a well-formed policy
> $P = (\mathit{name}, \mathit{ver}, \langle e_1,\dots,e_n\rangle, \alpha)$ to the automaton
> $C(P) = (Q, \Sigma, \delta, q_0, F)$ where
>
> - $Q = \{q_0, q_1, \dots, q_n\}$,
> - $F = \{q_n\}$,
> - and $\delta$ is defined for all $e \in \Sigma$ by
>
> $$\delta(q_i, e) = \begin{cases}
> q_{i+1} & \text{if } i < n \text{ and } e = e_{i+1} \\
> q_i & \text{if } i < n \text{ and } e \neq e_{i+1} \\
> q_n & \text{if } i = n.
> \end{cases}$$

Informally: state $q_i$ records that the first $i$ events of the pattern have been matched.
Each non-final state has exactly one **advancing** edge, on the next pattern event; every
other event is a self-loop, which is precisely what realises the embedding semantics of
Definition 1. The violation state $q_n$ is absorbing.

The construction is linear: $|Q| = n+1$ and the representation of $\delta$ requires $n$
advancing edges, so compilation is $O(n)$ in time and space for a policy of pattern length $n$.

---

## 6. Formal results

### 6.1 Determinism

> **Theorem 1 (Determinism).** For every well-formed policy $P$, the transition function
> $\delta$ of $C(P)$ is total and single-valued. Consequently, for every trace
> $\tau \in \Sigma^{*}$ there is exactly one state $q$ with $\delta^{*}(q_0,\tau) = q$, and
> hence exactly one decision $D(P,\tau)$.

**Proof.** Fix $q_i \in Q$ and $e \in \Sigma$. Exactly one of the three cases in Definition 6
applies: if $i = n$ the third case applies and no other; if $i < n$ then, since equality on
$\Sigma$ is decidable and total, exactly one of $e = e_{i+1}$ and $e \neq e_{i+1}$ holds, so
exactly one of the first two cases applies. Hence $\delta(q_i,e)$ is defined and unique, i.e.
$\delta$ is a total function.

That $\delta^{*}$ is a total function follows by induction on $|\tau|$. For $\tau = \varepsilon$,
$\delta^{*}(q_0,\varepsilon) = q_0$ is unique. For $\tau \cdot e$, by the induction hypothesis
$\delta^{*}(q_0,\tau)$ is a unique state $q$, and by the argument above $\delta(q,e)$ is a
unique state. Uniqueness of the decision then follows from Definition 3, since $D$ is a
function of $P$ and of whether $\delta^*(q_0,\tau) \in F$. $\blacksquare$

**Corollary 1.1 (Reproducibility).** For a fixed policy $P$ and fixed trace $\tau$, repeated
evaluations yield identical final states and identical decisions. No component of the
evaluation depends on time, scheduling, randomness, or accumulated state beyond $(P,\tau)$.

This corollary is what licenses the deterministic-replay mechanism planned in a later
phase: replaying a recorded $(P,\tau)$ must reproduce the recorded decision, and any
discrepancy indicates an implementation defect rather than expected nondeterminism.

### 6.2 Compilation correctness

The proof rests on a characterisation of the state reached after a trace. Define, for a
policy with pattern $\sigma = \langle e_1,\dots,e_n\rangle$ and a trace $\tau$,

$$\mathrm{match}(\tau) \;=\; \max \{\, k \in \{0,1,\dots,n\} \;\mid\; \langle e_1,\dots,e_k\rangle \sqsubseteq \tau \,\}.$$

The set is non-empty (it contains $0$) and bounded above by $n$, so $\mathrm{match}(\tau)$ is
well defined.

> **Lemma 1 (State characterisation).** For every well-formed $P$ and every $\tau \in \Sigma^{*}$,
> $$\delta^{*}(q_0, \tau) = q_{\mathrm{match}(\tau)}.$$

**Proof.** By induction on $|\tau|$.

*Base case.* $\tau = \varepsilon$. Then $\delta^{*}(q_0,\varepsilon) = q_0$. Also
$\mathrm{match}(\varepsilon) = 0$: the empty pattern embeds in $\varepsilon$, while for
$k \ge 1$ the pattern $\langle e_1,\dots,e_k\rangle$ requires at least one index in a trace of
length $0$ and so does not embed. Hence the claim holds.

*Inductive step.* Let $\tau = \langle f_1,\dots,f_m\rangle$ and assume
$\delta^{*}(q_0,\tau) = q_k$ with $k = \mathrm{match}(\tau)$. Consider $\tau' = \tau \cdot e$,
so $\tau' = \langle f_1,\dots,f_m,f_{m+1}\rangle$ with $f_{m+1} = e$. We must show
$\delta^{*}(q_0,\tau') = q_{\mathrm{match}(\tau')}$, and by the definition of $\delta^{*}$ it
suffices to show $\delta(q_k, e) = q_{\mathrm{match}(\tau')}$.

**Case 1: $k = n$.** Then $\delta(q_n, e) = q_n$ by Definition 6. Also
$\mathrm{match}(\tau') = n$: we have $\mathrm{match}(\tau') \ge \mathrm{match}(\tau) = n$ because
$\sqsubseteq$ is monotone under extension of the right argument, and $\mathrm{match}(\tau') \le n$
by definition. Hence both sides are $q_n$.

**Case 2: $k < n$ and $e = e_{k+1}$.** Then $\delta(q_k, e) = q_{k+1}$. We show
$\mathrm{match}(\tau') = k+1$.

*Lower bound.* Since $\mathrm{match}(\tau) = k$, there are indices
$j_1 < \cdots < j_k \le m$ embedding $\langle e_1,\dots,e_k\rangle$ into $\tau$. Extending by
$j_{k+1} = m+1$ gives $j_1 < \cdots < j_k < m+1$ with $f_{m+1} = e = e_{k+1}$, so
$\langle e_1,\dots,e_{k+1}\rangle \sqsubseteq \tau'$ and thus $\mathrm{match}(\tau') \ge k+1$.

*Upper bound.* Suppose for contradiction $\mathrm{match}(\tau') \ge k+2$, witnessed by indices
$j_1 < \cdots < j_{k+2} \le m+1$ embedding $\langle e_1,\dots,e_{k+2}\rangle$ into $\tau'$.
Since the indices are strictly increasing, at most one can equal $m+1$, and if one does it
must be $j_{k+2}$. Hence $j_1 < \cdots < j_{k+1} \le m$, which embeds
$\langle e_1,\dots,e_{k+1}\rangle$ into $\tau$ and gives $\mathrm{match}(\tau) \ge k+1$,
contradicting $\mathrm{match}(\tau) = k$. Therefore $\mathrm{match}(\tau') = k+1$.

**Case 3: $k < n$ and $e \neq e_{k+1}$.** Then $\delta(q_k,e) = q_k$. We show
$\mathrm{match}(\tau') = k$.

*Lower bound.* $\mathrm{match}(\tau') \ge \mathrm{match}(\tau) = k$ by monotonicity.

*Upper bound.* Suppose for contradiction $\mathrm{match}(\tau') \ge k+1$, witnessed by
$j_1 < \cdots < j_{k+1} \le m+1$ embedding $\langle e_1,\dots,e_{k+1}\rangle$ into $\tau'$.
Either $j_{k+1} \le m$, in which case the same indices embed
$\langle e_1,\dots,e_{k+1}\rangle$ into $\tau$ and contradict $\mathrm{match}(\tau) = k$;
or $j_{k+1} = m+1$, in which case $f_{m+1} = e_{k+1}$, i.e. $e = e_{k+1}$, contradicting the
case hypothesis. Therefore $\mathrm{match}(\tau') = k$.

The three cases are exhaustive, completing the induction. $\blacksquare$

> **Theorem 2 (Compilation correctness).** For every well-formed policy $P$ and every finite
> trace $\tau \in \Sigma^{*}$,
> $$\tau \models P \quad\iff\quad C(P) \text{ accepts } \tau.$$
> Equivalently, $L(P) = L(C(P))$.

**Proof.** By Definition 5, $C(P)$ accepts $\tau$ iff $\delta^{*}(q_0,\tau) \in F = \{q_n\}$,
i.e. iff $\delta^{*}(q_0,\tau) = q_n$. By Lemma 1, $\delta^{*}(q_0,\tau) = q_{\mathrm{match}(\tau)}$,
and since the states $q_0,\dots,q_n$ are distinct, this equals $q_n$ iff $\mathrm{match}(\tau) = n$.

It remains to show $\mathrm{match}(\tau) = n \iff \sigma \sqsubseteq \tau$. If
$\mathrm{match}(\tau) = n$ then $\langle e_1,\dots,e_n\rangle = \sigma$ embeds in $\tau$ by the
definition of $\mathrm{match}$. Conversely, if $\sigma \sqsubseteq \tau$ then
$\mathrm{match}(\tau) \ge n$, and since $\mathrm{match}(\tau) \le n$ always, equality holds.

Chaining the equivalences: $C(P)$ accepts $\tau$ iff $\mathrm{match}(\tau) = n$ iff
$\sigma \sqsubseteq \tau$ iff $\tau \models P$ (Definition 1). $\blacksquare$

**Corollary 2.1 (Decision correctness).** For every well-formed $P$ and every $\tau$, the
decision computed by executing $C(P)$ on $\tau$ — namely $\alpha$ if the final state is $q_n$
and `ALLOW` otherwise — equals $D(P,\tau)$ of Definition 3.

**Proof.** Immediate from Theorem 2 and Definition 3. $\blacksquare$

### 6.3 Absorption and early decision

> **Theorem 3 (Absorption).** If $\delta^{*}(q_0,\tau) = q_n$ then for every
> $\rho \in \Sigma^{*}$, $\delta^{*}(q_0, \tau\rho) = q_n$.

**Proof.** By induction on $|\rho|$. If $\rho = \varepsilon$ the claim is the hypothesis. If
$\rho = \rho' \cdot e$ then by the induction hypothesis $\delta^{*}(q_0,\tau\rho') = q_n$, and
by the third case of Definition 6, $\delta(q_n, e) = q_n$. $\blacksquare$

**Corollary 3.1 (Soundness of halting).** An implementation that stops consuming events as
soon as it reaches $q_n$, and reports the decision $\alpha$, computes the same decision as
one that consumes the entire trace.

This corollary is the formal justification for the early-exit behaviour of the reference
executor, which halts at the violation state rather than draining the remaining trace.

### 6.4 Enforcement soundness

> **Corollary 4 (Enforcement soundness).** Let $P$ be well-formed. If $\tau \models P$ then
> $D(P,\tau) \neq \texttt{ALLOW}$.

**Proof.** By Definition 3, $\tau \models P$ gives $D(P,\tau) = \alpha \in \mathcal{A} =
\{\texttt{DENY},\texttt{ALERT}\}$, and $\texttt{ALLOW} \notin \mathcal{A}$. $\blacksquare$

*Strengthened in v1.5.* The statement previously carried the hypothesis
$\alpha \in \{\texttt{DENY},\texttt{ALERT}\}$, which existed solely to exclude policies whose
action was `ALLOW`. With `ALLOW` removed from $\mathcal{A}$ no such policy exists, the
hypothesis is vacuous, and the corollary holds for every well-formed policy. This is the only
formal result affected by the revision, and it is affected by becoming stronger.

Corollary 4 is deliberately weak in exactly one respect: it is a statement about the
*decision function*, not about the *deployed system*. Whether a `DENY` decision actually
prevents the operation on a running host depends on the enforcement path, which is outside
the scope of this document and is governed by the assumptions of §7.

---

## 7. Assumptions and observation model

The results of §6 are mathematical statements about $C$, $\delta^{*}$ and $D$. Transferring
them to claims about a running system requires assumptions that are stated here explicitly
and must be restated wherever system-level guarantees are claimed.

- **A1 (Observation completeness).** Every event in $\Sigma$ that a policy's pattern names is
  observed and delivered to the evaluator whenever it occurs on the monitored host.
- **A1b (Descriptor provenance).** A $\texttt{WRITE}(p)$ event is generated when, and only
  when, the descriptor being written can be associated with a filesystem object whose opening
  was observed by the monitoring component. Writes to descriptors opened before the monitor
  attached, inherited across `fork`, or referring to non-filesystem objects such as pipes and
  sockets do not yield a $\texttt{WRITE}(p)$ event for any $p$; they fall outside $\Sigma$
  rather than being reported with an empty or guessed argument.
- **A1c (Pathname observation).** *Added in revision v1.1.* The pathname carried by an event
  is one pathname by which the operation reached its object, as defined per type in §1.4. It
  is neither canonical nor unique: the same object may be reached under other pathnames that
  produce no matching event, and the same pathname may at another time denote a different
  object. Guarantees stated over pathnames are therefore guarantees about named routes, not
  about objects.
- **A2 (Order preservation).** Events are delivered to the evaluator in the order in which
  they occurred.
- **A3 (State integrity).** The automaton state associated with a policy instance is not
  modified except by $\delta$.
- **A4 (Policy integrity).** The compiled policy evaluated at runtime is the compilation of
  the policy the administrator authorised.
- **A5 (Enforcement-path integrity).** The trusted components — the in-kernel observation
  hooks, the evaluator, and the enforcement actuator — are not compromised.

> **Proposition 1 (Conditional completeness).** Under A1, A1b, A1c, A2–A5, if the events occurring
> on the monitored host form a trace $\tau$ with $\tau \models P$, then the deployed system
> reaches the violation state $q_n$ for $P$ and issues $D(P,\tau)$.

**Proof sketch.** A1 and A2 imply that the trace presented to the evaluator is $\tau$ itself,
restricted to the events relevant to $P$; by the self-loop construction, events outside the
pattern do not affect the reached state, so the reached state is as in Lemma 1. A3 and A4
imply the evaluator runs $C(P)$ on that trace with state evolving only by $\delta$. Theorem 2
then gives acceptance, and Corollary 2.1 gives the decision. A5 ensures the decision is the
one acted upon. $\blacksquare$

**What is not claimed.** SentinelFS does not claim to detect attacks in general, nor to
detect behaviours not expressible in the policy language of §2, nor to remain sound if the
assumptions fail. In particular, an adversary who can suppress events (violating A1),
reorder them (A2), arrange for writes through descriptors the monitor never saw opened
(A1b), or compromise the enforcement path (A5) is outside the threat model. These
assumptions are load-bearing and any evaluation must report how far the deployed system
actually satisfies them.

**Naming evasions are outside the threat model.** *Added in revision v1.1.* A1c admits a
class of adversary explicitly rather than by implication. Each of the following reaches a
protected object without producing an event that matches a policy naming it, and each was
measured ([`phase4c-findings.md`](phase4c-findings.md) §1):

| Evasion | Privilege required |
|---|---|
| create a hard link to the object and use it | none beyond write access to some directory |
| create a symbolic link and execute through it (`EXEC` only, §1.4.2) | none |
| access the object through a bind mount | root, or an unprivileged user namespace where permitted |
| rename the protected object, then operate on it | write access to the containing directory |
| operate from a different mount namespace | ability to create one |

Conversely, deleting a protected object and creating a different object under the same
pathname causes a policy to continue matching, now applying to an object it was not written
for. An adversary able to do any of these is outside the threat model; a deployment that
cannot exclude them should not rely on pathname-based policies for the objects concerned.

**Correlation-capacity exhaustion.** *Added in revision v1.3.* A1b establishes that a
$\texttt{WRITE}(p)$ event exists only where the descriptor's opening was observed. An
implementation maintains that association in a structure of finite capacity, written here as

$$C = \text{the maximum number of simultaneously maintained write correlations.}$$

An adversary able to cause more simultaneously tracked writable file associations than $C$
can cause subsequent writes to become unresolved under A1b. Such writes do not generate
$\texttt{WRITE}(p)$ events for any $p$, and therefore cannot advance any policy through its
$\texttt{WRITE}$ transition.

It is important to state this precisely. These are **not** events that were generated and
then lost in transport. Under A1b the event was never generated, because its argument could
not be established. The distinction matters wherever event loss and evidence integrity are
assessed: a system reporting no loss may still have produced no event.

Three requirements follow, and each binds the implementation:

1. **$C$ is a declared security parameter, not a tuning parameter.** It determines how many
   descriptors an adversary must hold to suppress $\texttt{WRITE}$ enforcement. Choosing it
   is a threat-model decision and it must be documented as one.
2. **Capacity pressure must not be resolved by eviction.** Evicting a correlation makes
   subsequent writes through that descriptor unresolved, which is the same condition reached
   deliberately by an adversary. An implementation must therefore not use a structure that
   evicts silently, such as an LRU map, unless this specification is first revised to say
   which writes are thereby placed outside $\Sigma$.
3. **Correlation insertion failure must be observable.** Without it, a deployment cannot
   distinguish a policy that is protecting from one whose $\texttt{WRITE}$ coverage has
   degraded. The two are different security states and must not be reported identically.

The threshold is reachable by construction rather than only under extreme load: with a
capacity of 64, holding 160 descriptors open produced exactly 96 unresolvable writes. See
[`phase5a-e3-findings.md`](phase5a-e3-findings.md) §2.

**Empirical status.** A1 and A2 are empirical claims about a deployment, not theorems. The
Phase 2 feasibility study provides supporting evidence for both under the conditions it
tested: 4,514 of 4,516 required events observed with no losses and no ordering inversions,
across four scenarios on one kernel, with the two mismatches attributable to the since-removed
$\texttt{SPAWN}$ construct rather than to event loss. That is support under those conditions,
not a general guarantee; the bounds of the evidence are recorded in
[`phase2-findings.md`](phase2-findings.md) §5. A1b was introduced as a direct result of that
study.

---

## 8. Scope, limitations, and asymmetry of ALLOW

**No policy can grant an exception.** *Added in revision v1.5.* The action domain is
$\{\texttt{DENY}, \texttt{ALERT}\}$: a policy may forbid an operation or record it, and cannot
permit one. Permission is the default and is not expressible as a policy outcome, so there is
no way to write a rule that exempts something from another rule.

This is a real limitation and not a simplification. A deployment needing an exception must
express it by narrowing the pattern that would otherwise match, which is possible only when
the distinction is expressible in the event alphabet — and §1.4 already bounds what that
alphabet can say.

`ALLOW` was previously admitted as an action and could not have supplied this, for two
independent reasons recorded in [`phase5b0f-decision-domain.md`](phase5b0f-decision-domain.md).
Read as a request it was inert, because Definition 3 returned `ALLOW` for such a policy
whether or not it fired. Read as an override it was unavailable: the violated set is monotone
under Definition 1 and the violation state is absorbing under Theorem 3, so a single matching
event would have suppressed denial for every `DENY` policy, host-wide, for the remaining
lifetime of the policy set. Making the override reading work would require coordinated changes
to state persistence, scope and reset behaviour, all three of which are deferred constructs.

Affirmative permission is therefore recorded below as a deferred construct rather than
silently absent.

**Pathname-oriented, not object-oriented.** *Added in revision v1.1.* The language describes
operations on named routes, and §1.4 establishes that it cannot describe operations on
objects. A policy cannot say "this file, however it is reached"; it can only say "this
pathname". Every expressiveness statement below should be read subject to that, and the
security claim the system supports is correspondingly:

> SentinelFS enforces policies over observed pathname-based event traces, under the stated
> observation and enforcement assumptions and the documented pathname-identity limitations.

and not:

> SentinelFS protects a filesystem object regardless of how that object is reached.

**Expressiveness.** The v1 language expresses exactly the properties of the form
"this finite sequence of concrete events occurs, in order, possibly with other events
interleaved". It cannot express: absence of an event, disjunction over alternatives,
constraints relating a process to its ancestors beyond what the pattern names literally,
timing or rate conditions, or any condition on event arguments other than exact equality.

**The alphabet is syscall-granular, not intent-granular.** $\Sigma$ is populated by events
the kernel actually reports, which do not correspond one-to-one with a policy author's
notion of an action. Writing to a file entails an `openat` and a `write`, and both are
observed; a policy naming only $\texttt{WRITE}(p)$ therefore does not fire on a process that
opens $p$ and never writes, and a policy intending to catch any access to $p$ must name
$\texttt{OPEN}(p)$ as well. This is a property of the interface rather than a defect, but it
determines what an author is in fact writing, and policies must be read accordingly. The
point was identified in the Phase 2 study, where a ground-truth record kept at the level of
intended actions disagreed with the kernel and produced spurious ordering violations; see
[`phase2-findings.md`](phase2-findings.md) §4.3.

**Asymmetry of `ALLOW`.** By Definition 3, `ALLOW` is the absence of an established
violation, not an affirmative permission. A trace receives `ALLOW` both when it is genuinely
benign and when it exhibits behaviour that no loaded policy describes. Presenting `ALLOW` as
a positive safety judgement would be unwarranted, and the implementation reports it as a
default outcome rather than as a verdict.

**Single-policy scope.** This document defines the semantics of a single policy. A policy
set $\{P_1,\dots,P_r\}$ is evaluated by running the $r$ compiled automata independently on
the same trace; because each $\delta_i$ is total and deterministic, the combined evaluation
is deterministic as well. Defining a combination operator on decisions — and with it the
conflict analysis sketched in the project roadmap — requires a decision lattice and is
deferred to a later version of this specification.

### Multi-policy evaluation

*Added in revision v1.4.* Independence has three consequences that follow from the existing
semantics, and one gap that does not. The three are stated here because each is a point at
which an implementation could deviate while appearing correct; the gap is stated because an
enforcement hook cannot proceed without it.

> **MP1 (Per-policy independence).** For each event $e$ and each active policy $P_i$ in state
> $q_i$, the resulting state is $\delta_i(q_i, e)$. No transition depends on the state or the
> decision of any other policy.

> **MP2 (Order-freedom).** For any permutation $\pi$ of the active policies, evaluating them
> in order $P_{\pi(1)},\dots,P_{\pi(r)}$ yields the same resulting states as evaluating them
> in order $P_1,\dots,P_r$.

MP2 follows from MP1: each automaton reads and writes only its own state, so there is no
interaction for an ordering to affect. It is worth stating because it is a property an
implementation must preserve: policy storage order, map iteration order, CPU scheduling and
dispatcher structure must not change the resulting states.

> **MP3 (State completeness).** Every active policy whose alphabet admits the event's type
> receives that event and performs its transition, whatever verdict the deployed system
> returns for the operation.

MP3 forbids a specific and tempting optimisation. If a combination rule were such that one
policy's decision already determined the verdict, an implementation might stop evaluating the
remainder. The verdict for that operation would be correct and the system would still be
wrong: a policy that did not receive the event has not advanced, so its state is incorrect for
every subsequent event. **A verdict may be short-circuited; a transition may not.**

**The gap.** With $r$ policies active there are $r$ decisions $D(P_1,\tau),\dots,D(P_r,\tau)$,
and an enforcement mechanism returns one. The specification does not define

$$F\bigl(D(P_1,\tau),\dots,D(P_r,\tau)\bigr)$$

and an implementation must not choose it. The question is not which priority ordering to
adopt; it is what object represents the collection of independent decisions, and how that
object maps to a single verdict. A total order on $\{\texttt{DENY},\texttt{ALERT},\texttt{ALLOW}\}$
would yield a verdict but discard the fact that several policies fired — which matters, since
`DENY` and `ALERT` request different things and are not alternatives.

Any candidate $F$ must yield a verdict that does not depend on the order in which the
policies were evaluated, which is the verdict-level counterpart of MP2. It is worth being
precise about which algebraic property supplies what, because these do not all follow from
MP2:

| Property | What it provides |
|---|---|
| commutativity | removes dependence on the order in which policy decisions are combined |
| associativity | makes grouping order-independent, so partial results may be reduced in parallel |
| idempotence | permits a contribution to be merged or reprocessed without changing the result |

Only the first is required by order-independence itself. Associativity is required if the
combination is to be computed as a parallel or incremental reduction rather than a single
left-to-right fold, which an implementation is likely to want. Idempotence does not follow
from MP2 at all; it matters only if the same policy's decision may reach the combination more
than once.

A join-like operator satisfying all three would provide order-independent and safely
composable aggregation, which is what §8's original paragraph anticipated by naming a lattice.
**The precise algebra remains a specification decision**, and the properties above constrain
it rather than determine it.

**Until $F$ is defined, this specification does not describe multi-policy enforcement**, and
no implementation can claim to provide it. Single-policy enforcement is unaffected. See
[`phase5b-combination.md`](phase5b-combination.md).

**Trace scope is the host, and patterns may match across processes.** *Added in revision
v1.2.* The trace of §1.2 is host-wide. It follows that there is one automaton instance per
policy, that events from any process advance it, and therefore that **a policy pattern may be
satisfied by events originating in unrelated processes**.

This is a consequence of Definition 1, not a defect in it, but it is easily missed. A policy
of the form

```
ON EXEC(a) THEN EXEC(b) THEN WRITE(c) DENY
```

reads naturally as a causal claim — that one process executed $a$, then $b$, then wrote to
$c$. The language cannot express that claim. What the policy means is that the events occurred
on the host in that order, by any processes whatever, with arbitrary unrelated activity
between them.

The consequence was measured rather than argued: a pattern naming three routinely occurring
executions was satisfied by three unrelated processes in a recorded host trace, driving the
automaton to its violation state. See
[`phase5a-state-analysis.md`](phase5a-state-analysis.md) §1.1.

Combined with Theorem 3, which makes the violation state absorbing, a policy naming events
that each occur in ordinary operation will reach its violation state during ordinary
operation, and remain there.

**An implementation must not narrow this.** Keying automaton state by process, by process
tree, or by any other unit smaller than the host produces a system that is narrower than this
specification while appearing to implement it: Theorem 2 would still hold of the compiler, and
the deployed system would still not decide what the specification says it decides. Scoping a
pattern to a process or a lineage is a language extension, recorded in the table below.

**There is no reset, and no window.** *Added in revision v1.2.* Theorem 3 establishes that
$q_n$ is absorbing, and the language provides no construct by which an instance returns to
$q_0$, expires, or restricts a pattern to a bounded interval. An instance that reaches its
violation state remains there for as long as it exists.

**An implementation must not add one.** Introducing expiry, a timeout, or a reset changes
which traces violate a policy, and is therefore a change to Definition 1 rather than an
implementation detail — including when the motivation is to bound memory. If a deployment
requires bounded state and the semantics do not permit it, that is a conflict to be resolved
by revising the semantics deliberately, not by an adapter quietly discarding state the
specification says is retained.

**Deferred constructs.** The following are named in the project roadmap or arise from the
findings above. None is part of the language, and each would require its own revision.

| Construct | Effect | Why deferred |
|---|---|---|
| `WHERE` | argument predicates | not yet formulated |
| `TIMEOUT` | bounded temporal windows | moves the language beyond the regular fragment unless the bound is discretised into event counts; whether Theorem 2 generalises depends on the formulation |
| pattern scoping | restrict a pattern to a process or a lineage | addresses the cross-process consequence above; requires a notion of process identity in the semantics, which §1.4 currently confines to evidence |
| reset or expiry | return an instance to $q_0$ | changes which traces violate a policy; interacts with Theorem 3 |
| affirmative permission | a policy outcome that permits, creating exceptions to other policies | requires coordinated changes to state persistence, scope and reset; the naive form is unavailable under monotone traces and absorbing violation states |
| decision combination ($F$) | a join over the decisions of several policies | **blocks multi-policy enforcement**, not only conflict analysis; see the multi-policy subsection above |

---

## 9. Relationship to the implementation

The reference implementation mirrors this document structurally:

| Document | Implementation |
|---|---|
| §2 grammar | `sentinelfs/dsl/lexer.py`, `sentinelfs/dsl/parser.py` |
| §2.1 well-formedness (WF1–WF4) | `sentinelfs/dsl/validator.py` |
| Definition 6 (compiler $C$) | `sentinelfs/compiler/automaton.py` |
| Definition 4–5 ($\delta^{*}$, acceptance) | `sentinelfs/runtime/executor.py` |
| Corollary 3.1 (halting at $q_n$) | early exit in `run_trace` |
| Definition 1 ($\tau \models P$) | reference oracle in `tests/test_semantics.py` |

**Differential testing.** `tests/test_semantics.py` implements Definition 1 directly as an
independent oracle and compares its verdict against the compiled automaton's decision over
randomly generated traces. This is empirical corroboration of Theorem 2 for the tested
policies, not a proof, and it is reported as such: a disagreement would falsify either the
theorem or the implementation's conformance to it, whereas agreement raises confidence in
conformance only.

The distinction matters for the eventual paper. Theorem 2 is a statement about the
mathematical function $C$ of Definition 6. That the Python (and later Rust, and later
in-kernel) code implements that function is a separate claim, supported here by testing
rather than by verification, and it should be described that way.

---

## 10. Summary of results

| Result | Statement |
|---|---|
| Theorem 1 | $\delta$ is total and single-valued; each $(P,\tau)$ yields exactly one decision |
| Corollary 1.1 | Decisions are reproducible; nothing depends on time, scheduling, or randomness |
| Lemma 1 | $\delta^{*}(q_0,\tau) = q_{\mathrm{match}(\tau)}$ |
| Theorem 2 | $\tau \models P \iff C(P)$ accepts $\tau$; that is, $L(P) = L(C(P))$ |
| Corollary 2.1 | The executed decision equals $D(P,\tau)$ |
| Theorem 3 | $q_n$ is absorbing |
| Corollary 3.1 | Halting at $q_n$ is sound |
| Corollary 4 | A violating trace never yields `ALLOW`, for every well-formed policy |
| Proposition 1 | Conditional completeness, under assumptions A1, A1b, A1c, A2–A5 only |
| Proposition 2 | A pathname is not an object identifier, in either direction (empirical) |
