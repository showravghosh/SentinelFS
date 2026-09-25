# SentinelFS: Formal Semantics of the Core Policy Language (v1)

**Status:** working specification for the core language, at revision **v1.1**.

**Revision history.** v1.0 was frozen at tag `v1.0-spec`. Revision v1.1 adds §1.4 (event
identity), assumption A1c, Proposition 2, and the naming-evasion threat-model statement in
§7. It does not change the alphabet, the grammar, the compilation function, or any of
Theorems 1-3, Lemma 1 or the corollaries: those are statements about an automaton over
$\Sigma$ and are indifferent to what the arguments denote. What changes is that the
specification now says what the arguments denote, which v1.0 left implicit. The change was
forced by measurement rather than by design preference; see
[`phase4c-findings.md`](phase4c-findings.md). This document defines the
syntax, the trace semantics, the compilation function, and states and proves the
determinism and compilation-correctness theorems. It is the normative reference: the
Python reference implementation and any future implementation (Rust, in-kernel) are
correct exactly insofar as they agree with this document.

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

action      = "DENY" | "ALERT" | "ALLOW" ;

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
$\alpha \in \mathcal{A} = \{\texttt{DENY}, \texttt{ALERT}, \texttt{ALLOW}\}$ is the **action**.

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

> **Definition 3 (Decision).** The decision function $D : \mathcal{P} \times \Sigma^* \to \mathcal{A}$
> is
> $$D(P, \tau) = \begin{cases} \alpha & \text{if } \tau \models P \\ \texttt{ALLOW} & \text{otherwise.} \end{cases}$$

An `ALLOW` decision therefore means "no policy violation was established", not "the trace
was affirmatively permitted by a rule". §8 discusses this asymmetry.

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

> **Corollary 4 (Enforcement soundness).** Let $P$ be well-formed with action
> $\alpha \in \{\texttt{DENY}, \texttt{ALERT}\}$. If $\tau \models P$ then $D(P,\tau) \neq \texttt{ALLOW}$.

**Proof.** By Definition 3, $\tau \models P$ gives $D(P,\tau) = \alpha \in \{\texttt{DENY},\texttt{ALERT}\}$,
and `ALLOW` is distinct from both. $\blacksquare$

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

**Deferred constructs.** `WHERE` (argument predicates) and `TIMEOUT` (bounded temporal
windows) are named in the project roadmap but are deliberately absent from v1. `TIMEOUT` in
particular moves the language beyond the regular fragment unless the time bound is
discretised into event counts; the choice of formulation will determine whether Theorem 2
generalises, and it should not be adopted before that is settled.

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
| Corollary 4 | A violation of a `DENY`/`ALERT` policy never yields `ALLOW` |
| Proposition 1 | Conditional completeness, under assumptions A1, A1b, A1c, A2–A5 only |
| Proposition 2 | A pathname is not an object identifier, in either direction (empirical) |
