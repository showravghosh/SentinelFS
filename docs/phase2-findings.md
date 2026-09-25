# Phase 2 Findings: Linux Event-Observation Feasibility

**Purpose.** The formal results in [`formal-semantics.md`](formal-semantics.md) are statements
about the compilation function and the decision function. Transferring them to a running
system requires the assumptions A1, A1b, and A2–A5 of §7 of that document. This study tests
the two assumptions that are empirical rather than architectural:

- **A1 (observation completeness):** every event named by a policy is observed and delivered.
- **A2 (order preservation):** events are delivered in the order in which they occurred.

The study is deliberately a feasibility probe, not an implementation. It observes; it does
not enforce. Its purpose is to determine whether the observation model underlying
Proposition 1 is realisable before committing to a production implementation.

---

## 1. Method

**Platform.** Kali Linux, kernel `7.0.12+kali-amd64`, x86-64 virtual machine.
`CONFIG_BPF_LSM=y`, BTF present at `/sys/kernel/btf/vmlinux`, active LSMs include `bpf`.
Observation via `bpftrace` v0.26.0 attached to eight tracepoints.

**Event sources.** The four event types of the v1 alphabet were mapped to kernel
tracepoints as follows.

| Formal type | Tracepoint | Argument source |
|---|---|---|
| `EXEC` | `sched:sched_process_exec` | kernel-resolved executable path |
| `SPAWN` | `sched:sched_process_fork` | child `comm` (see §4.1) |
| `OPEN` | `syscalls:sys_enter_openat` | pathname as passed by userspace |
| `WRITE` | `syscalls:sys_enter_write` | path recovered by fd correlation (see §4.2) |

**Ground truth.** Rather than compare observations against expectation, a workload records
what it actually did: each operation is logged with the process identifier and a
`CLOCK_MONOTONIC` timestamp taken immediately after the syscall returns. The probe stamps
its records with `nsecs`, which is the same clock, so observed and actual timelines are
directly comparable. Coverage is then measured by matching each ground-truth operation to
an observed record of the same type and argument within a 50 ms window, and A2 is tested by
checking that the observed timestamps of matched events are non-decreasing in ground-truth
order.

**Scenarios.**

| Scenario | Operations | Tests |
|---|---|---|
| `attack_chain` | the canonical `EXEC → EXEC → WRITE` pattern | can a policy-relevant chain be observed at all |
| `interleaved` | the same chain with unrelated events between | does embedding semantics survive real noise |
| `ordering` | 100 rounds of write/open/write on distinct paths | A2 |
| `volume` | 2,000 writes as fast as the workload can issue them | A1 under load |

All file operations target decoy paths under `/tmp/sentinelfs-gt`. No protected system file
was modified at any point.

---

## 2. Results

| Scenario | Ground truth | Matched | Coverage | Ordering inversions | Identity exact |
|---|---|---|---|---|---|
| `attack_chain` | 6 | 5 | 83.3% | 0 | 5/5 |
| `interleaved` | 10 | 9 | 90.0% | 0 | 9/9 |
| `ordering` | 500 | 500 | 100.0% | 0 | 500/500 |
| `volume` | 4,000 | 4,000 | 100.0% | 0 | 4,000/4,000 |
| **Total** | **4,516** | **4,514** | **99.96%** | **0** | **4,514/4,514** |

The table reports counts. Whether these counts support A1 and A2, and under what
conditions, is discussed below; the table itself asserts nothing about the assumptions.

**A1.** These experiments provide empirical support for A1 under the defined observation
conditions: 4,514 of the 4,516 required events were observed, and the two remaining
mismatches are attributable to the original `SPAWN` semantic definition (§4.1) rather than
to event loss. No event was lost in any scenario. The `volume` scenario issued 4,000 events
at a measured 73,828 events/s with complete delivery and exact path resolution.

This is support, not proof. A1 is a statement about all executions; what is established here
is that no counterexample arose across the event types, rates, and host conditions tested.
§5 records the conditions under which that evidence was obtained.

**A2.** A2 was empirically supported across all four tested scenarios, with no observed
ordering inversions, including 100 rounds of strictly alternating operations and 4,000
events issued at the maximum rate the workload could achieve. The same qualification
applies: these are the scenarios tested, not a general guarantee.

**Process identity.** Every matched event was attributed to the correct process identifier:
4,514 of 4,514.

**Background load.** With the probe's own activity excluded, the host produced 148 to 1,355
events/s across the four runs. This figure is specific to a largely idle desktop virtual
machine and must not be generalised; see §5.

**End-to-end.** Events observed from the kernel were fed to the compiled automaton of an
actual SentinelFS policy. The automaton reached its violation state `q3` and issued `DENY`.

This is a demonstration that the two layers connect: the records the probe produced were
consumable by the executor without modification, and on this run they drove it to the
decision the policy prescribes. It is not a claim that kernel observation is sufficient in
general. Whether the events a policy names will be observed on an arbitrary host is exactly
what A1 and A1b assert, and those remain assumptions supported by the measurements in this
section rather than consequences of this one execution.

---

## 3. Measurement artefacts identified and corrected during feasibility validation

Three artefacts were found and corrected before these results were accepted. They are
recorded here because each produced a plausible but false finding, and because the
corrections are part of the method rather than incidental to it. Each was detected by
checking a result that looked implausible rather than by accepting the first attractive
numbers the apparatus produced.

**3.1 Probe self-observation.** The first run reported a background rate of 187,564
events/s. Diagnosis showed that 1,231,843 of 1,231,924 observed `WRITE` events — 100.0% —
were produced by `bpftrace` itself: the probe's output writes were observed by the probe,
which produced more output. The probe now excludes its own process. The corrected
background rate is three orders of magnitude lower.

**3.2 Ordering measured on output position.** The first A2 metric compared the positions of
matched records in the output file. This conflated arrival order with the matcher's own
selection among candidates and reported 100 spurious inversions. A2 is now measured on
observed timestamps, which is what the assumption actually concerns.

**3.3 Ground truth at the wrong granularity.** After 3.2 was fixed, A2 still reported exactly
one inversion per round. The cause was that the workload's write helper performed an
`openat` before each `write`, and recorded only the write. The kernel observed both. The
matcher therefore paired the ground-truth `OPEN` with an earlier open generated by a write,
producing a phantom inversion. The ground truth now records events at syscall granularity.

The general lesson is stated in §4.3, because it bears on the formal model and not only on
this study.

---

## 4. Findings that affect the formal model

### 4.1 `SPAWN(x)` is not observable as specified

Two ground-truth events failed to match in every run: `SPAWN("/bin/bash")`. This is not a
delivery failure and no instrumentation change will resolve it.

At `fork` time the child process is a copy of the parent. Its `comm` is the parent's, and
the binary it will execute has not yet been named: `execve` happens afterwards, in the
child. The kernel cannot report at fork time what a process will become.

The v1 grammar admits `SPAWN("/bin/bash")`, whose natural reading is "a child process
running `/bin/bash` is created". No single kernel event corresponds to this. Three
resolutions are available, each with consequences for §2 and §3 of the specification.

1. **Redefine `SPAWN(x)` as fork-then-exec.** The event holds when a child process is
   created and subsequently executes `x`. This preserves the intended meaning, but the
   observation layer must correlate two kernel events, and the event is only determined at
   the later of the two — which shifts the point at which a policy can fire, and therefore
   the point at which enforcement is still possible.
2. **Make `SPAWN` nullary.** `SPAWN` denotes only that a child was created. The pattern
   `EXEC(python3) THEN SPAWN THEN WRITE(shadow)` remains expressible; naming the child does
   not. This is the smallest change to the semantics.
3. **Remove `SPAWN`; express the pattern with `EXEC` and ancestry.** The chain becomes
   `EXEC(python3) THEN EXEC(bash) THEN WRITE(shadow)` together with a constraint that the
   second `EXEC` occurs in a descendant of the first. This requires relational constraints,
   which v1 deliberately excludes.

Note that the end-to-end check in §2 succeeded precisely because it used resolution 3's
shape: the policy was written with two `EXEC` events rather than `EXEC` followed by `SPAWN`.

**Decision: `SPAWN` is removed from the v1 core language.** Resolutions 1 and 2 were both
rejected. Resolution 1 makes an event's identity depend on a later event, which shifts the
moment a policy can fire and therefore the moment enforcement remains possible — a
substantive change that should not be made to accommodate a construct the language does not
need. Resolution 2 retains a keyword carrying almost no information. Resolution 3's
relational constraint is not adopted either, since v1 excludes relational constraints by
design.

What remains is the observation that `EXEC(path)` corresponds directly to a single
observable kernel event which carries the path, and that the chain of interest is
expressible without `SPAWN` at all:

```
ON EXEC("/usr/bin/python3")
THEN EXEC("/bin/bash")
THEN WRITE("/etc/shadow")
DENY
```

This is strictly better for the formal model: every symbol of the alphabet now corresponds
to a kernel event that names its own argument. Process lineage may be retained internally by
the observation layer, and may be reintroduced in a later version as an explicit relational
construct, but an unobservable future process identity does not belong in the core language.

### 4.2 `WRITE` path resolution depends on observing the open

`sys_enter_write` carries a file descriptor, not a path. The probe recovers the path by
recording the pathname at `openat` and associating it with the returned descriptor.

Where the open was observed, resolution was exact: 4,000 of 4,000 writes in the `volume`
scenario resolved to the correct path. Across all processes on the host, however, 4.4% to
95.7% of writes were unresolved, depending on the scenario. The unresolved cases are writes
to descriptors that were opened before the probe attached, inherited across `fork`, or
obtained by means other than `openat` — pipes, sockets, and `memfd` among them.

This has a direct consequence for the observation model. A1 as originally written assumes
events are observed whenever they occur. For `WRITE`, what is actually available is weaker:
the argument of a `WRITE` event is recoverable only for descriptors whose creation was
observed. A deployment that attaches the monitor after a process has started cannot resolve
that process's pre-existing descriptors at all.

**Decision: the observation model is qualified rather than the guarantee overstated.** A
`WRITE(p)` event is generated when, and only when, the descriptor being written can be
associated with a filesystem object whose opening was observed by the monitoring component.
The corresponding assumption is stated explicitly in the specification as A1b:

> **A1b (descriptor provenance).** A `WRITE` event carries a path argument only if the
> creation of the written descriptor was observed. Writes to descriptors opened before the
> monitor attached, inherited across `fork`, or referring to non-filesystem objects do not
> yield a path-carrying `WRITE` event.

Writes that cannot be resolved are not silently reported with a wrong or empty path: they
fall outside the alphabet and are not `WRITE(p)` events for any `p`. This keeps $\Sigma$
well defined and keeps the enforcement soundness statement honest, at the cost of making the
coverage of `WRITE` policies explicitly conditional on monitor attachment time.

Recovering the mapping from `/proc/<pid>/fd` at attach time would narrow the gap, but it is
inherently racy — the descriptor table can change between enumeration and use — and would
need its own justification before being relied upon. It is not adopted in v1.

### 4.3 The event alphabet is syscall-granular, not intent-granular

Correction 3.3 arose because "write to a file" denotes one action to a policy author and two
syscalls to the kernel. The alphabet $\Sigma$ of §1.1 is populated by observable kernel
events, so a policy written as `WRITE("/etc/shadow")` matches the `write` syscall and not
the `openat` that necessarily preceded it.

This is not a defect, but it is a fact that must be stated in the specification, because it
determines what a policy author is actually writing. A policy intending to catch any access
to a file must name `OPEN` as well as `WRITE`; a policy naming only `WRITE` will not fire on
a process that opens a file and never writes to it. §8 of the specification should record
this explicitly under expressiveness.

---

## 5. Limitations of this study

- **Single host, single kernel.** All measurements come from one virtual machine running
  `7.0.12+kali-amd64`. The kernel was upgraded to `7.1.5+kali-amd64` during tool
  installation but has not been booted; results must be re-established on any kernel used
  for the final evaluation.
- **The background rate is not representative.** 148–1,355 events/s reflects an idle desktop
  VM. A production server, a container host, or a build machine will differ by orders of
  magnitude. No conclusion about the feasibility of userspace evaluation should be drawn
  from this number; that question is deferred to the Phase 7 evaluation on realistic
  workloads.
- **Observation only.** No enforcement path was exercised. That `bpf` appears among the
  active LSMs, and that `CONFIG_BPF_LSM=y`, indicates enforcement hooks are available, but
  this study does not demonstrate that a decision can be applied before the operation
  completes. A1 and A2 concern observation; enforcement raises separate questions of
  latency and of blocking semantics.
- **Maximum rate not established.** The `volume` scenario showed no loss at 73,828 events/s,
  but that is the rate the workload achieved, not the rate at which the probe begins to drop
  events. The loss threshold remains unmeasured.
- **Favourable matching.** The matcher accepts a basename match where paths differ, so
  reported coverage is an upper bound on what exact matching would yield. Exact-argument
  agreement is reported separately in the per-scenario output and was 4,514 of 4,514 for
  everything except the `SPAWN` cases and one `EXEC` whose interpreter path differed.

---

## 6. Conclusion

For the event types, rates, and host conditions exercised here, **A1 and A2 are empirically
supported**: no event was lost, no event arrived out of order, and process attribution was
exact in every matched case. Kernel-observed events were sufficient to drive the compiled
automaton to a correct decision end to end. This is evidence that the observation model
underlying Proposition 1 is realisable on a current Linux kernel for the v1 alphabet; it is
not a proof that it always is, and §5 bounds what was actually tested.

The study's more consequential outcome is the two specification changes it forced, both
arising from properties of Linux rather than from defects in the implementation:

- **`SPAWN` is removed from the core language** (§4.1). At `fork` time the kernel cannot
  name the binary a child will later execute, so `SPAWN(x)` was unobservable as defined. The
  chain of interest is expressible with `EXEC` alone, and every remaining symbol of the
  alphabet now corresponds to a kernel event that names its own argument.
- **The `WRITE` observation model is qualified by A1b** (§4.2). A path-carrying `WRITE`
  event exists only where the descriptor's creation was observed.

Both changes narrow what the language claims, and both make the claims that remain
defensible. Finding them before the production core was written is the outcome this phase
existed to produce.

### Consequences for subsequent phases

The specification and reference implementation must be updated to reflect these two changes,
and the DSL frozen, before the Rust core is written. The Rust implementation should then
conform to the Python reference rather than revisit the semantics during the port: the
existing test suite, including the theorem-conformance tests, is the conformance target, and
identical input traces must yield identical automata and identical decisions.
