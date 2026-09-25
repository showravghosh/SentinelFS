# Phase 2 Results

## `summary.json`

Aggregate measurements from the Linux event-observation feasibility study. This is the
committed record of the numbers reported in
[`../../docs/phase2-findings.md`](../../docs/phase2-findings.md).

### Regenerating it

```bash
cd feasibility
sudo ./run_feasibility.sh
python3 analyse.py --json results/summary.json
```

The first command requires root, because attaching an eBPF probe does. The workload itself
runs as the invoking user.

### What it contains

| Key | Meaning |
|---|---|
| `environment` | kernel release, architecture, `bpftrace` version — needed to interpret the measurements |
| `alphabet_tested` | the event types observed during this run |
| `totals` | ground-truth events performed, events matched, coverage, ordering inversions |
| `assumption_support` | per-assumption status, the evidence, and the caveat limiting it |
| `end_to_end_policy_detection` | whether kernel-observed events drove the compiled automaton to a violation |
| `scenarios` | per-scenario counts: coverage, inversions, identity and argument exactness, per-type matched/expected, workload and host event rates, unresolved write-path fraction |

### What it deliberately does not contain

**Aggregate measurements only.** No process names, no file paths, no process identifiers,
and no arguments of unmatched events.

The raw traces in `../out/` record everything the host was doing while the probe ran, which
is host-identifying and of no scientific value. Only counts and rates derived from them are
published here. `../out/` is excluded from version control for that reason; see
[`../README.md`](../README.md).

### Reading the numbers

`assumption_support` states each assumption's status as *empirically supported under the
tested conditions*, never as proved. A1 and A2 are claims about all executions of a deployed
system; this study establishes that no counterexample arose across the event types, rates,
and host conditions it exercised. The limits of that evidence are recorded in
[`../../docs/phase2-findings.md`](../../docs/phase2-findings.md) §5 — one host, one kernel,
an unrepresentative background load, no enforcement path exercised, and no loss threshold
established.

`alphabet_tested` includes `SPAWN`, which was removed from the language as a result of this
study. The two unmatched events in `totals` are that construct, not lost events.
