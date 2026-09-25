# Phase 5A.9: Minimum State Contract, and the Elimination of a Candidate Architecture

**Purpose.** Derive, from the semantics alone, the state an enforcement implementation must
hold and the operations it must perform — before considering any mechanism. Then determine
which mechanisms can satisfy that contract.

**Result.** The contract is small, and one of the three candidate architectures is not
available on the inspected Linux/BPF interface. That was established by inspecting the
interface rather than by measuring the candidate's latency, which would have measured a
mechanism that does not exist. It does not establish that either surviving option is
feasible; §4 lists what would.

---

## 1. The contract

Derived from v1.2. Each row cites what requires it.

### 1.1 On the synchronous decision path

| # | Operation | Required by | Notes |
|---|---|---|---|
| 1 | Retrieve the policy's current automaton state | Definition 4, $\delta$ is a function of the current state | |
| 2 | Receive one event from the host-wide trace | §1.2 | one trace, not per-process |
| 3 | Extract the event's argument | §1.4, per type | `EXEC` reads the supplied pathname; `OPEN` the resolved one |
| 4 | Evaluate the transition | Definition 6 | equality against at most one advancing edge |
| 5 | Persist the resulting state | $\delta^{*}$ is defined over the whole trace | a later event must observe it |
| 6 | Preserve the violation state once reached | Theorem 3 | absorbing; §8 forbids discarding it |
| 7 | Return the decision | Definition 3 | the hook's return value *is* the enforcement |
| 8 | For `WRITE`: resolve the argument via correlation | A1b, §1.4 | no other means exists at the write hook |

### 1.2 Off the decision path

| # | Operation | Why it may be asynchronous |
|---|---|---|
| 9 | Create the `WRITE` correlation entry | at `file_open`, before any write to that descriptor |
| 10 | Release the correlation entry | at `file_free_security`, after the last write |
| 11 | Emit evidence | the decision is already made |
| 12 | Hash and chain evidence | Phase 6 concern; no event depends on it |
| 13 | Report and export | |

Operations 1–8 must complete inside the security hook. Everything in 9–13 may be deferred.
**That division is the contract**, and it is what the architecture must satisfy.

---

## 2. Two distinct state problems

Conflating these would distort every capacity estimate.

### 2.1 Policy automaton state

$$\text{policy identifier} \;\mapsto\; \text{automaton state index}$$

Under §1.2's host-wide trace, there is **one instance per policy**. The state is an index into
$\{q_0,\dots,q_n\}$, so it fits in a single byte for any policy of pattern length under 255.

**Total: one small integer per policy.** A thousand policies is on the order of a kilobyte.

This is worth stating plainly because it inverts an intuition. Under host-wide semantics the
automaton state is *negligible*. It is the scoping decision that would change this: keying by
process would make it $O(\text{policies} \times \text{live processes})$, and by lineage
unbounded. §8 of v1.2 forbids an implementation making that change on its own, and this is the
quantitative reason it matters.

### 2.2 `WRITE` descriptor correlation

$$\text{descriptor identity} \;\mapsto\; \text{observed pathname}$$

Tied to the file lifecycle, not to any policy trace. Created at open, released at file
release. Its size scales with the number of simultaneously open descriptors the policy set
cares about — a property of host activity, not of the policy count.

**These are the two state structures. They have different keys, different lifetimes, and
different growth behaviour, and they should not share a representation.**

---

## 3. A synchronous userspace round trip is not implementable with BPF

Option B assumed a hook could consult a userspace evaluator and block for the verdict. Before
measuring that path's latency, it was worth establishing that the path exists.

**On the inspected interface, it does not.** This is a version-specific finding about the
interface as shipped, not a statement about Linux in general:

| Component | Version inspected |
|---|---|
| kernel | `7.0.12+kali-amd64` |
| `linux-libc-dev` (source of `linux/bpf.h`, `linux/fanotify.h`) | `7.1.5-1kali1` |
| libbpf | `1.7.0` |

Of the **212** helpers declared in that `linux/bpf.h`, none blocks on, waits for, or queries
userspace. Every helper directed at userspace is one-way and asynchronous:

| Helper family | Direction | Synchronous? |
|---|---|---|
| `bpf_ringbuf_*`, `bpf_perf_event_output` | kernel → userspace | no |
| `bpf_user_ringbuf_drain` | userspace → kernel | reads data userspace already wrote; not a request |
| map lookups | shared memory | userspace must have written the value beforehand |

A map can carry a *precomputed* answer. It cannot carry an answer to a question the kernel has
not yet asked. And a BPF program cannot wait: sleepable LSM programs (`lsm.s/`) may sleep, but
sleeping is not consulting, and there is no helper that would wake them on a userspace reply.

**Option B is not an available implementation of the v1.2 synchronous semantics on the
inspected Linux/BPF interface.** It is eliminated by interface capability, not because it
would be too slow — its latency was never measured, because the mechanism whose latency would
be measured does not exist. A future kernel offering a synchronous request/response helper
would reopen the question, and the finding should be re-established against any kernel on
which the system is deployed.

### 3.1 fanotify is the exception, and covers half the alphabet

Linux does provide one mechanism that blocks a syscall pending a userspace verdict. On the
tested configuration `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`, and the permission events
declared in the inspected `linux/fanotify.h` are:

| fanotify event | v1 event it could gate |
|---|---|
| `FAN_OPEN_PERM` | `OPEN` |
| `FAN_OPEN_EXEC_PERM` | `EXEC` |
| `FAN_ACCESS_PERM` | read — not in the alphabet |

On the tested configuration, fanotify provides permission events for open- and
exec-related operations but no corresponding synchronous permission event for write or
delete. The complete set of `FAN_*_PERM` constants in the inspected header is
`FAN_ACCESS_PERM`, `FAN_OPEN_PERM`, `FAN_OPEN_EXEC_PERM`, `FAN_ALL_PERM`.

So fanotify can gate **two of the four** event types. It cannot implement `WRITE` or `DELETE`,
which are precisely the destructive ones. A userspace evaluator built on fanotify would
enforce a strict subset of the language, which §8 of v1.2 forbids an implementation from doing
silently.

### 3.2 Consequence

**The decision must be made in the kernel.** Userspace can hold policy, receive evidence, and
report; it cannot participate in the verdict. This is a property of the platform, not a
preference, and it collapses the architecture space:

| Option | Status |
|---|---|
| A — kernel-resident decision, userspace evidence | **not eliminated**; feasibility not yet established (§4) |
| B — userspace evaluator on the decision path | **eliminated**: no mechanism (§3), and fanotify covers only `OPEN` and `EXEC` (§3.1) |
| C — hybrid: kernel decision, userspace evidence and management | as A on the decision path; differs only off it |

A and C differ only in where non-decision work happens, which the contract already places off
the synchronous path.

**This does not establish that A is feasible.** What is established is narrower: *if* the
complete v1.2 alphabet is to be enforced synchronously on the inspected interface, the
decision must be kernel-resident, because no other mechanism can produce a verdict for
`WRITE` or `DELETE`. Whether the state and transitions of §1 can actually be expressed within
BPF and LSM constraints — verifier limits, map capacity, the cost of evaluating every active
policy per event — is unmeasured, and §4 is what would measure it.

---

## 4. What the latency experiment should now measure

5A-E2 was scoped to measure hook-to-verdict latency for a userspace round trip. That
measurement is void: there is nothing to measure. The experiment should be re-aimed at the
architecture that survives:

1. **Transition cost in-kernel.** The added latency of lookup, compare, update and return,
   against an unattached baseline, at increasing event rates.
2. **Scaling in the number of policies.** Every event must be evaluated against every active
   policy whose alphabet includes that event type. At 1,000 policies this is 1,000 comparisons
   inside a security hook, which connects directly to the Phase 8 scalability requirement.
3. **Verifier limits.** Whether the transition logic for a realistic policy set fits within
   instruction and complexity limits — and what happens to the design if it does not.
4. **Correlation map capacity.** What occurs when the `WRITE` correlation map is full. The
   specification forbids evicting policy state; whether it permits evicting *correlation*
   state is a separate question, and the answer determines whether `WRITE` enforcement
   degrades gracefully or silently.
5. **Ring-buffer saturation.** Still unmeasured, and now purely an evidence-path concern
   rather than a decision-path one — which lowers its severity but does not remove it, since
   dropped evidence is dropped evidence.

Item 4 deserves emphasis. A full correlation map means a `WRITE` whose pathname cannot be
resolved, which by A1b is **not a `WRITE(p)` event for any p**. The enforcement does not fail
open in the sense of allowing a matched violation; it fails to *observe* the event at all. That
is consistent with the specification, and it is also exactly how an adversary would evade a
`WRITE` policy: exhaust the map.

---

## 5. Status

| Step | Status |
|---|---|
| 5A.1 – 5A.6 | established; see [`phase5a-state-analysis.md`](phase5a-state-analysis.md), [`phase5a-e1-findings.md`](phase5a-e1-findings.md) |
| 5A.7 scoping | recorded in v1.2 §8; not resolved |
| 5A.8 reset/expiry | recorded in v1.2 §8; not resolved |
| **5A.9 state contract** | **§1 above** |
| Architecture | B eliminated (§3); A and C differ only off the decision path |
| 5A-E2 | re-aimed (§4); not yet run |

No adapter code has been written. The contract in §1 is what it will have to satisfy, and §3
is why it will have to satisfy it in the kernel.
