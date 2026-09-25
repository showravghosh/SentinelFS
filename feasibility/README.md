# Phase 2: Linux Event-Observation Feasibility Study

> **These are Phase 2 feasibility artefacts, based on the pre-freeze event model.**
> The scripts in this directory implement the event alphabet as it stood *before* DSL v1 was
> frozen, and in particular they still observe and record `SPAWN`. They are retained in that
> state deliberately: they are the apparatus that produced the measurements reported in
> `../docs/phase2-findings.md`, and the `SPAWN` result is the finding that caused the
> specification to change.
>
> They are **not** an implementation of the frozen v1 language, and should not be read as
> one. For the frozen alphabet — `EXEC`, `WRITE`, `OPEN`, `DELETE` — see
> [`../docs/formal-semantics.md`](../docs/formal-semantics.md) §1.1.

This directory contains the experimental apparatus for the study reported in
[`../docs/phase2-findings.md`](../docs/phase2-findings.md).

The study tests whether the observation assumptions of
[`../docs/formal-semantics.md`](../docs/formal-semantics.md) §7 are realisable on a current
Linux kernel:

- **A1** — every event a policy names is observed and delivered
- **A2** — events are delivered in the order they occurred

It observes only. It performs no enforcement and cannot block or terminate anything.

## Contents

| File | Role |
|---|---|
| `probe.bt` | eBPF observation probe (`bpftrace`), attaches to eight tracepoints |
| `groundtruth.py` | workload that performs a known operation sequence and records exactly what it did |
| `run_feasibility.sh` | orchestrates probe and workload for each scenario; requires root |
| `analyse.py` | compares ground truth against observations; emits the summary |
| `diagnose.py` | investigates specific suspicious results (see "Measurement artefacts" below) |
| `results/summary.json` | aggregate measurements, committed |
| `out/` | raw traces and ground-truth records, **not committed** (see below) |

## Requirements

- Linux kernel with `CONFIG_BPF_SYSCALL=y` and BTF at `/sys/kernel/btf/vmlinux`
- `bpftrace` (tested with v0.26.0)
- Python 3.10 or later
- root, for attaching the probe

```bash
sudo apt install -y bpftrace
```

## Reproducing the study

```bash
cd feasibility
sudo ./run_feasibility.sh
python3 analyse.py --json results/summary.json
```

The first command runs four scenarios, each attaching the probe, running the workload as the
invoking (non-root) user, and stopping the probe. The second compares what the workload
actually did against what the kernel reported, prints the findings, and writes the aggregate
summary.

Individual scenarios may be selected:

```bash
sudo ./run_feasibility.sh attack_chain ordering
```

## Scenarios

| Scenario | Operations | Tests |
|---|---|---|
| `attack_chain` | the canonical policy pattern | whether a policy-relevant chain is observable at all |
| `interleaved` | the same chain with unrelated events between | whether embedding semantics survives real noise |
| `ordering` | 100 rounds of write/open/write on distinct paths | A2 |
| `volume` | 2,000 writes issued as fast as possible | A1 under load |

All file operations target decoy paths under `/tmp/sentinelfs-gt`. No protected system file
is read or modified. The workload never touches `/etc/shadow` or any other sensitive path,
despite the policy pattern naming it.

## Why `out/` is not committed

`out/observed-*.jsonl` is a recording of everything the host was doing while the probe ran:
process names, file paths, and process identifiers belonging to unrelated software on the
machine. In the reference run this included desktop-session processes, library load paths,
and the operator's home directory. That is host-identifying information with no scientific
value, and it does not belong in a source repository.

`out/truth-*.json` is likewise excluded: it is deterministic output of `groundtruth.py`,
regenerable by anyone running the study.

The reproducibility chain is therefore:

```
committed probe -> committed workload -> committed analysis
       -> raw local traces (not committed)
       -> results/summary.json (committed)
       -> measurements reported in docs/phase2-findings.md
```

A reviewer can reproduce every reported number from the committed code. If raw traces are
ever required for independent verification, they should be regenerated on a clean host that
is not someone's personal machine.

## Measurement artefacts

Three artefacts were identified and corrected during validation; each had produced a
plausible but false result. They are documented in `../docs/phase2-findings.md` §3 and are
summarised here because they constrain how the apparatus should be used.

1. **Probe self-observation.** The probe's own output writes were being observed, producing
   a feedback loop that accounted for 100% of reported write events. `probe.bt` now excludes
   its own process. Any new probe must do the same.
2. **Ordering measured on output position.** Order must be assessed on event timestamps, not
   on position in the output file; the latter conflates arrival order with the analysis's own
   matching choices.
3. **Ground truth at the wrong granularity.** The workload records events at *syscall*
   granularity, because that is what the kernel reports. Writing to a path entails an
   `openat` as well as a `write`; recording only the intended action makes the ground truth
   disagree with the kernel.

`diagnose.py` performs the checks that uncovered artefacts 1 and 2, and is retained so that
they can be re-checked after any change to the probe:

```bash
python3 diagnose.py
```

## Note on the alphabet

This study was run while `SPAWN` was still part of the v1 event alphabet. Its removal is a
direct result of the study: at `fork` time the kernel cannot name the binary a child will
later execute, so `SPAWN(x)` was unobservable as defined. See
[`../docs/phase2-findings.md`](../docs/phase2-findings.md) §4.1.

The scripts here are unchanged from the run that produced the reported measurements, so they
still reference `SPAWN`. This is deliberate: they document the experiment that motivated the
specification change, and altering them retrospectively would misrepresent what was tested.

The relationship between this apparatus and the frozen language is therefore:

```
Phase 2 apparatus (this directory)
    tested the pre-freeze alphabet, including SPAWN
        |
        v
    established that SPAWN was not observable as defined
        |
        v
specification changed (docs/formal-semantics.md)
        |
        v
DSL v1 frozen: EXEC, WRITE, OPEN, DELETE
        |
        v
subsequent implementations follow the frozen language
```

Re-running these scripts reproduces the reported measurements, including the two unmatched
`SPAWN` events. That mismatch is the result, not a defect to be corrected. An apparatus
targeting the frozen alphabet would be a different experiment and would not reproduce the
finding that motivated the freeze.
