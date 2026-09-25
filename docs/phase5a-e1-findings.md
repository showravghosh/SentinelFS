# Phase 5A-E1 Findings: Concurrent Host-Wide Ordering

**Question.** Assumption A2 asserts that events reach the evaluator in the order they
occurred. Phase 2 tested it with a single-process workload, which cannot distinguish order
preservation from there having been only one order. The v1.1 semantics define a single
host-wide trace (§1.2), so under concurrency the question becomes what the order *is* when
events occur on different CPUs — and whether the candidate architectures would agree on it.

**Method.** Three orderings were captured for every event and compared against each other and
against a known ground truth:

| Ordering | Source | Which architecture applies transitions in it |
|---|---|---|
| `seq` | an atomic counter incremented **inside the hook** | a kernel-resident automaton, which transitions inline |
| `ts_ns` | `bpf_ktime_get_ns()` at the same point | neither directly; tests whether timestamps are trustworthy |
| delivery | position of the record in the collector's output | a userspace automaton reading the ring buffer |

The sequence number is claimed *before* ring-buffer space is reserved, so a dropped record
leaves a gap in `seq`. Loss is therefore identified exactly rather than inferred from a count
mismatch. The counter is a single global cell, deliberately: that is the contention a single
host-wide automaton state would experience under §1.2.

Platform: kernel `7.0.12+kali-amd64`, 4 CPUs (Intel i5-8250U). Observe-only.

---

## 1. Results

| | W1 synchronised | W2 contention |
|---|---|---|
| Events | 600 | 6,004 of 6,000 expected |
| CPUs exercised | 0 and 2 | 0, 1, 2, 3 |
| `seq` gaps (dropped records) | **0** | **0** |
| delivery order == hook order | **yes** | **yes** |
| timestamp order == hook order | **yes** | **yes** |

Probe counters across the whole run: **6,606 events sequenced, 0 dropped**. The W1 figure of
600 above is the corrected count; the first run recorded 602 and the discrepancy is traced in
§3.

### 1.1 Happens-before across CPUs was preserved in the tested workloads

W1 pinned two processes to CPUs 0 and 2 and synchronised them through a pair of pipes, so
that A_i strictly precedes B_i, which strictly precedes A_(i+1). The true order is therefore
known by construction rather than inferred.

Over 300 rounds — 600 events:

| | Result |
|---|---|
| Alternation violations in hook order | **0** |
| Timestamp inversions within the chain | **0** |
| First ten roles | `ABABABABAB` |
| Last ten roles | `ABABABABAB` |

A happens-before relationship established in userspace across two CPUs survived to the
observation point intact.

### 1.2 The three orderings agreed

In both workloads, delivery order, hook-execution order, and timestamp order were identical.
Under the load tested, a userspace automaton reading the ring buffer would apply transitions
in the same order as a kernel-resident automaton transitioning inline.

---

## 2. What this constrains, and what it does not

**A2 held under the tested concurrent workloads.** This extends Phase 2's single-process
evidence to four CPUs with a known cross-CPU ground truth. It is not a proof and not a
statement about Linux's ordering behaviour in general: the workloads were bounded, the machine
has four cores, and no competing system load was applied.

**The experiment establishes no conclusion about ring-buffer saturation, cross-hook
interleaving, or synchronous decision latency.** Each is listed in §4 and each remains open.

**Ordering does not rule out either architecture.** The result is a negative one in the useful
sense: the disagreement that would have eliminated a userspace evaluator did not occur. Both
Option A (kernel-resident) and Option B (userspace) see the same order under this load.

**Ordering was the wrong reason to reject Option B.** The remaining objection to a userspace
evaluator on the decision path is *latency* — the hook must block until a verdict returns —
and that is untouched by this experiment. Phase 5 should not treat Option B as eliminated;
it should measure the latency it was actually suspected of.

**The single global counter did not become a bottleneck at this rate.** 6,606 atomic
increments across four CPUs with no drops and no gaps. That is not a throughput measurement,
and it does not establish behaviour at the rates Phase 2 recorded for an active host, but it
is evidence that a single shared state cell is not obviously unworkable.

---

## 3. Measurement correction

The first run reported 602 events where 600 were expected, and one happens-before violation.

Both had one cause. Each child process created its own target file with
`open(target, "wb")` at startup, inside the measurement window, contributing one extra `OPEN`
event per process. The alternation check then saw A's setup open immediately followed by A's
first round event — two consecutive A records — and reported a violation at index 1.

Excluding one setup open per process leaves exactly 600 events with zero alternation
violations and zero timestamp inversions. The corrected figures are those in §1.

This is the fourth occurrence of the pattern rule M4 exists for, and the second in which it
changed a stated conclusion rather than merely inflating a count. The harness now creates
every file the workloads touch before the probe attaches, so no setup operation falls inside
the measurement interval. See [`../feasibility/METHODOLOGY.md`](../feasibility/METHODOLOGY.md)
M4.

That the violation was investigated rather than reported is the reason the finding is
"happens-before preserved" rather than "happens-before violated once in 300 rounds" — a
conclusion which would have been wrong, and which a single aggregate number would have
supported.

---

## 4. Limitations

- **Four CPUs, one machine, bounded workloads.** 6,000 events is not a stress test. Phase 2
  recorded 148–1,355 events/s on an idle host; a busy server differs by orders of magnitude.
- **No competing load.** The workloads ran on an otherwise quiet machine. Contention with
  unrelated activity is untested.
- **Only `OPEN` events.** All records came from `lsm/file_open`. Whether hooks on different
  paths — `bprm_check_security`, `file_permission`, the rename hooks — interleave consistently
  with each other is not established by a single-hook experiment.
- **Ring-buffer capacity was not approached.** The buffer was 16 MiB for 6,606 records. What
  happens to ordering and loss when it fills is exactly the case that matters for a userspace
  evaluator, and it was not tested.
- **Latency unmeasured**, which is the open question for Option B (§2).

---

## 5. Status of the Phase 5A sequence

| Step | Status |
|---|---|
| 5A.1 host-wide state ownership | established |
| 5A.2 cross-process consequence | demonstrated |
| 5A.3 violation lifetime | established |
| 5A.4 `WRITE` correlation lifetime | established |
| 5A.5 synchronous decision set | established |
| **5A.6 concurrent ordering** | **measured — A2 held in the tested workloads; both architectures agree** |
| 5A.7 scoping decision | open; to be recorded, not silently changed |
| 5A.8 reset/expiry decision | open; to be recorded, not silently changed |
| 5A.9 derive architecture | blocked on 5A.7 and 5A.8 |

The two remaining items are specification decisions, not measurements. Neither should be
resolved by an implementation choosing a convenient map key or adding a timeout because the
map would otherwise grow.
