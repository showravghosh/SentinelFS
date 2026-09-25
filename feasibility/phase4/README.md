# Phase 4: Synchronous Enforcement Feasibility

> **Phase 4 evaluates whether the frozen v1 event alphabet can be implemented as
> synchronous kernel enforcement events. The feasibility experiment does not modify the v1
> specification.**
>
> If a hook cannot provide an event faithfully, the experiment stops and reports the
> mismatch. It does not redefine the event around whatever the hook happens to offer. The
> specification was frozen at [`v1.0-spec`](../../docs/formal-semantics.md); a mismatch found
> here is evidence for a deliberate revision, not licence to make one.
>
> **Outcome.** No mapping required changing the alphabet or the grammar. One gap was found
> that the specification had left implicit rather than decided — what the argument of an
> event denotes — and that was settled by deliberate revision to v1.1 after the measurements
> were complete, not during the experiments. See §1.4 of the specification.

This is a feasibility probe, not an adapter. It answers four questions and stops.

## Why this phase exists

Phase 2 established that the v1 alphabet can be **observed** on a running kernel, using
tracepoints. Tracepoints fire after the fact, which is sufficient for detection and useless
for enforcement: by the time a tracepoint reports a write, the write has happened.

Enforcement requires hooks that run **before** the operation and whose return value decides
whether it proceeds. On Linux that means BPF LSM. The hooks are a different interface
exposing different arguments, so whether they can carry the same alphabet is an open
question, not a corollary of Phase 2.

Phase 2 also found that `SPAWN` was unobservable as specified, which removed it from the
language. The same outcome is possible here.

## The four questions

### P1 — Event mapping

Can the enforcement hooks represent the frozen alphabet without changing its meaning?

```
EXEC(path)    -> ?   pre-execution hook
OPEN(path)    -> ?   pre-open hook
WRITE(path)   -> ?   pre-write hook
DELETE(path)  -> ?   pre-unlink hook
```

The candidate hooks are recorded in `results/summary.json` as measured, not assumed. A
candidate is only accepted if the event it yields means what the specification says the
event means.

### P2 — Path availability, and assumption A1b

For each event type, determine whether the hook can identify the filesystem object, and at
what cost.

`WRITE` is the case of interest. Assumption A1b already says a `WRITE(p)` event exists only
where the descriptor's provenance was observed. In observation mode an unresolvable write was
a gap in the data. In enforcement mode the kernel is asking for a verdict regardless, so the
question becomes sharper: if the hook cannot name the object, what is SentinelFS being asked
to decide, and is that decision expressible in the frozen semantics at all?

### P3 — Synchronous enforcement

The measurement is not that the hook observed the operation. It is that the decision was
made **before the operation was permitted to complete**, and that a `DENY` prevented it.

```
operation requested
       |
       v
   BPF LSM hook
       |
       v
 SentinelFS decision
       |
  +----+----+
  |         |
ALLOW     DENY
  |         |
  v         v
proceeds   -EPERM, operation never occurs
```

The evidence required is the operation's observable effect: a denied write must leave the
file unchanged. A returned error code alone is not sufficient evidence that nothing happened.

### P4 — State placement

Where does the automaton state live? This is the architectural question and it is left open
deliberately.

```
Option A                  Option B                  Option C
BPF LSM                   BPF LSM                   BPF LSM
   |                         |                         |
kernel-resident state     userspace executor        bounded kernel automaton
   |                         |                         |
decision                  decision                  decision
                                                       |
                                                  userspace for evidence only
```

Option B is suspected to be unworkable for synchronous blocking, because a userspace round
trip inside a security hook introduces latency and a race. That suspicion is to be measured,
not assumed. Option C is the interesting case if the kernel's constraints permit it.

## Method

The first experiment is a single end-to-end chain on a controlled file:

```
POLICY phase4_probe
VERSION 1
ON EXEC("/usr/bin/python3")
THEN EXEC("/bin/bash")
THEN WRITE("/tmp/sentinel-test")
DENY
```

For each step the run records:

| Field | Meaning |
|---|---|
| `event_observed` | did the hook fire |
| `path_resolved` | could the hook name the object |
| `state_before` / `state_after` | automaton transition |
| `decision` | ALLOW / ALERT / DENY |
| `kernel_return` | what the hook returned |
| `effect_occurred` | did the operation actually happen |

The last row is the one that matters: a `DENY` that returns `-EPERM` but leaves the file
modified has not enforced anything.

## Safety

All operations target `/tmp/sentinel-test`. No policy in this phase names a real system
path, and no probe denies any operation outside the controlled test file. An LSM program
that denies broadly can make a machine unusable; the probes here are scoped to a single
path and are detached when the run ends.

## Contents

| Path | Role |
|---|---|
| `probes/*.bpf.c` | BPF LSM programs; `vmlinux.h` is generated by `scripts/build.sh` and not committed |
| `scripts/` | build, collectors, workloads, and per-experiment harnesses |
| `out/` | compiled objects and raw traces — **not committed** |

The measurements are reported in [`../../docs/phase4-findings.md`](../../docs/phase4-findings.md),
[`phase4b-findings.md`](../../docs/phase4b-findings.md) and
[`phase4c-findings.md`](../../docs/phase4c-findings.md). `out/` is excluded for the same
reasons as the Phase 2 traces: the compiled objects and `vmlinux.h` are rebuilt from committed
sources, and the observed traces record whatever else the host was doing while the probes ran.

Reproducing a phase:

```bash
./scripts/build.sh
cc -O2 -Wall -o out/loader     scripts/loader.c     -lbpf
cc -O2 -Wall -o out/collector  scripts/collector.c  -lbpf
cc -O2 -Wall -o out/collector_b scripts/collector_b.c -lbpf
cc -O2 -Wall -o out/collector_c scripts/collector_c.c -lbpf

sudo python3 scripts/experiment1.py   # synchronous enforcement (P3)
sudo python3 scripts/experiment2.py   # hook/alphabet correspondence (P1, P2)
sudo python3 scripts/experiment3.py   # event identity and coverage (4B)
sudo python3 scripts/experiment4.py   # stability of path identity (4C)
```

`scripts/reanalyse2.py` re-derives experiment 2's `WRITE` conclusion from its raw records,
filtering by access mask; it exists because the first analysis did not, and reported the
opposite conclusion.

## Decided mappings

Phase 4 is closed. The mappings below are the result, and they are what a Phase 5 adapter must
implement. Each is stated with the specification definition it realises
([`../../docs/formal-semantics.md`](../../docs/formal-semantics.md) §1.4) and the finding that
established it.

| Event | Hook | Value read | Established by |
|---|---|---|---|
| `EXEC(p)` | `lsm/bprm_check_security` | `bprm->filename` — **not** `bpf_d_path` | 4B §1 |
| `OPEN(p)` | `lsm/file_open` | `bpf_d_path(&file->f_path, …)` | 4B §3 |
| `WRITE(p)` | `lsm/file_permission`, filtered on `MAY_WRITE` | correlation map keyed by `struct file *`, populated at `file_open`, released at `file_free_security` | 4 §2, §3.3 |
| `DELETE(p)` | `lsm/path_unlink`, `lsm/path_rmdir`, **`lsm/path_rename`** | dentry name with directory path; for rename, destruction is `dest_exists && !(flags & RENAME_EXCHANGE)` | 4B §2 |

Four constraints on any implementation, each found by measurement rather than documentation:

1. **`bpf_d_path` requires a trusted pointer.** Reading a field with `BPF_CORE_READ` first
   yields an untrusted scalar and the program is rejected. Dereference the hook's own context
   argument directly. (4 §3.1)
2. **`bpf_d_path` is forbidden on `lsm/file_permission`.** It is permitted only on hooks in
   the sleepable set, which the write path is not. `WRITE` paths must come from the
   correlation map. (4 §3.2)
3. **`inode_rename` carries no flags argument** and cannot distinguish a destructive rename
   from a `RENAME_EXCHANGE`. Only `path_rename` can, and it is gated on
   `CONFIG_SECURITY_PATH`. (4B §2.1)
4. **`EXEC` must read `bprm->filename`.** Resolving the executable instead yields
   `/usr/bin/python3.13` where the policy says `/usr/bin/python3`, and the policy compiles,
   loads, validates and never fires. (4 §4.1, corrected in 4B §1)

## Outcomes against the four questions

| | Question | Outcome |
|---|---|---|
| P1 | Can the hooks represent the alphabet? | yes, with the mappings above |
| P2 | Is the object nameable at each hook? | yes, subject to A1b for `WRITE` |
| P3 | Can enforcement be synchronous? | yes — demonstrated, file verifiably unchanged |
| P4 | Where does state live? | **open.** Object-identification state must be kernel-resident and available synchronously; whether the automaton can be is not answered |

## What Phase 4 did not settle

- **P4, state placement.** The correlation map showed that some state must be kernel-resident
  and synchronously available. Nothing here establishes bounds for a kernel-resident
  automaton.
- **Enforcement beyond `file_open`.** Experiment 1 demonstrated denial at one hook.
  Experiments 2, 3 and 4 were observe-only. That `file_permission`, `path_rename` and the
  `bprm` hooks can deny, and at what latency, is unmeasured.
- **Performance.** `file_permission` fired 1,142 times during a 26-operation workload. No
  overhead figure exists.
- **Filesystems other than tmpfs.** All identity results are from tmpfs. Overlayfs, which
  containers use, is untested.

## Status

**Closed.** The four questions are answered or explicitly deferred, the mappings are decided,
and the specification has been revised to v1.1 to define event identity
([`../../docs/formal-semantics.md`](../../docs/formal-semantics.md) §1.4, A1c, Proposition 2).

Experimental method is governed by [`../METHODOLOGY.md`](../METHODOLOGY.md); four of its six
rules were adopted as a result of corrections made during this phase.
