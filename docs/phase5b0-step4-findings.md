# Phase 5B.0 Step 4 Findings: Enforcement Capability of the Adopted Hooks

> **This experiment measures an implementation capability. It does not select a trace
> semantics, and it does not change the specification.**
>
> Phase 4 demonstrated pre-effect denial for `lsm/file_open` only, and recorded the other
> three events as unmeasured. This step measures them. The result answers whether the adopted
> hooks *can* refuse an operation before its effect. It does not answer what an event in the
> alphabet *means*, which is the open question at the 5B.0 gate and is decided by argument,
> not by measurement.

**Kernel: `7.1.5+kali-amd64`.** This is not the kernel Phase 4 ran on. See §4.

---

## Summary

| Arm | Hook(s) under test | Outcome |
|---|---|---|
| `EXEC` | `lsm/bprm_check_security` | 5 attempts, 4 denied, 1 control allowed |
| `WRITE` | `lsm/file_permission` + `MAY_WRITE` | 1 protected write denied, 1 control allowed |
| `DELETE` | `lsm/path_unlink`, `lsm/path_rmdir`, `lsm/path_rename` | all 5 protected cases denied, 1 control allowed |

All 13 cases produced the expected outcome. In every denied case the operation's effect was
absent: no process started, no bytes changed, no directory entry was removed.

One result from the first run was **withdrawn as a harness artefact** and is recorded in §5
rather than removed.

---

## 1. Why this experiment exists

Step 3 established that the specification is occurrence-based through assumptions A1 and A2,
while a synchronous `DENY` requires the enforcement point to be able to refuse an operation
before its effect. Those are different questions, and only the second is empirical.

Phase 4 measured the second question for one event. `phase4-findings.md` §7 states the gap
directly: *"Enforcement was demonstrated only for `file_open`. … That `file_permission`,
`path_unlink` and the `bprm` hooks can deny, and at what cost, has not been measured."*

Until that gap was closed, an objection stood against one of the two candidate trace models:
that pre-effect adjudication might be unavailable for three of the four events, making the
question moot for them. This experiment removes that objection. It does not settle the
question the objection was about.

## 2. Method

Each arm attaches its probe **inert**, performs setup, arms the probe, makes its attempts,
disarms, and only then evaluates post-conditions.

The arming is a map flag, not attachment. Detaching and reattaching around setup would not
have worked: attachment itself perturbs the system and the reattach would fall inside the
interval. Methodology rule M4 exists because setup work previously fell inside a measurement
interval and produced a phantom happens-before violation; here the separation is structural
rather than a matter of ordering discipline.

The loader takes commands on stdin and acknowledges each one, so the harness synchronises on
the acknowledgement rather than sleeping. A sleep-based harness would race the arming, and a
race would silently attribute an unarmed call to the measured interval.

Every case records the same chain:

```
before state -> attempt -> LSM return value -> hook counters -> after state
```

Counters distinguish *the hook never fired* from *the hook fired and allowed*, which a return
code alone cannot.

## 3. Results

### 3.1 `EXEC`

Four execution forms were tested because Phase 4B established the execution hooks do not
behave identically across them. The question here is not whether they produce identical
observations — they do not — but only whether returning a denial prevents the execution.

| Case | Invocation | errno | Program started |
|---|---|---|---|
| ELF | absolute path to a copied binary | `EPERM` | no |
| `#!` script | absolute path to a shell script | `EPERM` | no |
| symlink | a link whose **own name is not protected** | `EPERM` | no |
| relative | `./protected-elf` from the directory | `EPERM` | no |
| control | a binary outside the protected prefix | 0 | yes |

Counters: 5 hook calls, 5 paths resolved, 4 targets seen, 4 denied.

Two observations.

The symlink case is discriminating by construction. The link is named `sneaky-link`, so its
own pathname does not match the protected prefix and only its resolved target does. Had the
denial keyed on the passed name rather than the resolved one, this case would have been
allowed. It was denied.

In this denied run, the `#!` script produced **one** `bprm_check_security` call. Phase 4B
found the hook can fire twice for scripts, once for the script and once for the interpreter.
The single call here is consistent with that earlier two-call observation being associated
with the permitted execution path, because the denied first check prevents the subsequent
interpreter execution. The present experiment does not independently establish the complete
hook sequence for all permitted and denied script executions.

Started-despite-refusal: none.

### 3.2 `WRITE`

This arm carries the strongest control requirement, because the obvious mistake would produce
a convincing and worthless result. Phase 4 §2 established that `file_open` denotes intent
rather than the operation and cannot implement `WRITE(path)`. A denial at open time would
also leave the file unchanged, and would say nothing about write-time enforcement.

Three controls separate the two:

- `lsm/file_open` in this probe is **observe-only**. It records the A1b correlation and
  returns 0 unconditionally.
- The descriptor was **opened before arming**, so the open could not be the refused operation.
- The file content was sampled **while the probe was still armed**, so the observation cannot
  include anything done after the interval.

| Case | errno | Bytes unchanged in interval | Bytes unchanged after close |
|---|---|---|---|
| protected | `EPERM` | yes | yes |
| control | 0 | no, as expected | no, as expected |

Counters: 7 open calls, 6 correlations established, 24 `file_permission` calls, 10 with
`MAY_WRITE`, 2 lookup hits, 2 lookup misses, **0 stale**, 1 target seen, 1 denied.

The two lookup misses are writes through descriptors with no observed opening under the
watched prefix — unrelated host activity. Under A1b those are not a `WRITE(p)` for any `p`,
and the probe allows them rather than guessing a path.

`S_STALE = 0` matters: the correlation map is keyed by `struct file *`, and a stale hit would
mean refusing a write to an object the policy never named. The inode was rechecked at write
time and no mismatch occurred.

The denial therefore acted on a path established at an earlier opening, not on one resolvable
at the decision point. That is the structure A1b describes, and it is a consequence of
`bpf_d_path` being forbidden on `file_permission` rather than a design preference.

Refused-after-effect: none. See §5 for the first run, where this was recorded and withdrawn.

### 3.3 `DELETE`

All three mechanisms were exercised, not unlink alone. Phase 4 inferred a `DELETE` enforcement
bypass from unlink-only instrumentation and was wrong; Phase 4B retracted it after showing the
rename hooks cover the case. An arm testing only unlink could report success while rename-over
remained unprotected, so the retraction is the reason for the wider test.

| Case | Operation | errno | Entry present after |
|---|---|---|---|
| unlink | remove a protected file | `EPERM` | yes |
| rmdir | remove a protected directory | `EPERM` | yes |
| rename source | rename a protected name away | `EPERM` | yes |
| rename over | rename an unprotected name onto a protected one | `EPERM` | yes |
| `RENAME_EXCHANGE` | exchange an unprotected and a protected name | `EPERM` | yes |
| control | remove an unprotected file | 0 | no |

Counters: 6 unlink calls, 3 rmdir calls, 3 rename calls; denials 1 unlink, 1 rmdir, 1 rename
source, 2 rename destination; 1 exchange seen.

Rename-over and `RENAME_EXCHANGE` were both refused on the **destination** side, which is why
the destination counter reads 2. `DELETE(p)` means "the name `p` is removed" rather than "the
object at `p` is destroyed" (`phase4b-findings.md` §2.2), so the post-condition measured is
the presence of the directory entry, not the survival of the inode.

Removed-despite-refusal: none.

---

## 4. Relation to Phase 4

**This experiment ran on `7.1.5+kali-amd64`. Phase 4 ran entirely on `7.0.12+kali-amd64`.**

`phase4-findings.md` §7 records the reason this matters: *"All results are from
`7.0.12+kali-amd64`. The installed `7.1.5+kali-amd64` has not been booted. Hook availability,
and particularly which hooks are in the sleepable set, are kernel-version-specific and must be
re-established."*

Two consequences follow, and both are stated rather than left to inference.

**These results do not extend Phase 4's evidence to the newer kernel.** Phase 4's findings —
the hook-to-event mapping, the `bpf_d_path` constraints, the `WRITE` faithfulness counts, the
identity and ordering measurements — remain measurements on `7.0.12` and are not re-measured
here. Nothing in this document licenses restating them as properties of `7.1.5`.

**These results do re-establish, on `7.1.5`, the specific implementation behaviours this
experiment exercised**: that the adopted hooks load and attach, that `bpf_d_path` resolves on
`bprm->file->f_path` and on `file_open`, that it remains unusable on `file_permission` so the
correlation is still required, and that each hook's return value is honoured. That is a
narrower set than Phase 4 established, and it is the set this experiment touched.

The two bodies of evidence are therefore kept separate. A combined claim across both kernels
would require re-running Phase 4's measurements here, which has not been done.

---

## 5. Measurement corrections

Recorded under methodology rule M6: a correction is recorded, not edited away.

### 5.1 Run 1 reported `refused_after_effect` for the protected write — withdrawn

The first run recorded, for the protected file, that the kernel returned `EPERM` **and the
bytes changed anyway**. Taken at face value this would have been the most significant result
in the experiment: a hook that refuses after the effect cannot support pre-effect adjudication
for `WRITE`, and the `WRITE` analysis would have changed substantially.

It was a harness artefact. The harness held a buffered Python file object. A `BufferedWriter`
does not discard its buffer when a flush fails, and flushes again on `close()`. The arm
disarmed the probe before closing, so the retained buffer was written **after** the measurement
interval, by the cleanup, with nothing armed to refuse it. The measured operation was refused
correctly; the bytes changed afterwards for an unrelated reason.

The hook's own counters were consistent with a correct refusal throughout run 1 — one target
seen, one denial, zero stale entries, and `last_denied` naming the protected file. The
counters and the post-condition disagreed, and the post-condition was wrong.

The correction was to remove Python buffering entirely — raw `os.open` and `os.write` — and to
sample the file content **inside** the armed interval with `os.pread`, so the observation
cannot include cleanup. Run 2 then recorded `bytes_unchanged_in_interval = true`, which
distinguishes the two explanations rather than merely producing a pass. Both readings are kept
in the record.

Run 1's full output is preserved as `results/step4-enforcement-run1.json`.

**What this incident establishes, and the lesson drawn from it.** What is established is
narrow: this harness's buffered cleanup could alter the post-condition after the probe was
disarmed, so a post-condition sampled after cleanup did not measure the operation under test.
The methodological lesson drawn from the incident -- that a measurement apparatus should not
be able to produce the effect whose absence it is measuring -- is a generalisation from this
case and from the earlier negative-test failures, not something this run establishes on its
own. The in-interval sample is what closes the specific gap found here.

### 5.2 Run 1 aborted on the first denied execution

The initial harness used `subprocess.run` for the `EXEC` attempts. A refusal at
`bprm_check_security` means no child process is created, so `posix_spawn` raises rather than
returning a code. The harness treated the expected result as an error and aborted the run on
the first case it was built to measure.

Corrected by recording both channels: a raised `OSError`'s errno, or the child's return code
where one exists. The same run's partial output already showed the refusal working, which is
how the cause was identified.

---

## 6. What this establishes, and what it does not

**Established, within scope:**

> Pre-effect denial was measured for the tested hooks, on kernel `7.1.5+kali-amd64`, in the
> tested configurations, for the tested workloads. In each denied case the operation's effect
> was absent when observed inside the measurement interval.

**Not established:**

- That `EXEC`, `WRITE` and `DELETE` are universally pre-effect events on Linux. One kernel,
  one host, one filesystem, one set of paths.
- That the untested hooks or variants behave the same way.
- Any cost or overhead figure. Nothing here was timed.
- Any claim about behaviour under correlation-map pressure. The map was never filled.

**Explicitly not established — the semantic question:**

```
Measured implementation fact:
    the adopted hooks can refuse the tested operations pre-effect.

Still-open semantic question:
    does the alphabet contain completed occurrences,
    adjudicated attempts,
    or another event meaning?
```

Assumptions A1 and A2 remain occurrence-based and are unchanged. The specification is
unchanged. What this experiment removes is an objection — that pre-effect adjudication might
be unimplementable for three of the four events — and not the question the objection was
about. Whether the alphabet should mean attempts is decided by argument about the formal
model, and that decision has not been taken.

---

## 7. Limitations

- **One kernel, one host.** `7.1.5+kali-amd64`, and not the kernel Phase 4 used.
- **One hook per event.** Alternative hooks for the same event were not compared.
- **No performance measurement.** `file_permission` fired 24 times during a workload of two
  writes; the cost of resolving and deciding on that path remains unmeasured, and it is the
  hook most likely to matter.
- **Synthetic workload.** Single-threaded, one process, files under a dedicated prefix. No
  concurrency, no descriptor inheritance across `fork`, no pressure on the correlation map.
- **`RENAME_EXCHANGE` was refused on the destination side.** Whether an exchange should be a
  `DELETE` at all is a semantic question this experiment does not settle; it was exercised so
  that the behaviour is on record, not to classify it.
- **Control cases are weak evidence of precision.** One permitted operation per arm shows the
  probe is not refusing everything; it does not characterise the false-refusal rate.

---

## 8. Conclusion

The adopted enforcement hooks for `EXEC`, `WRITE` and `DELETE` refused the tested operations
before their effects occurred, on `7.1.5+kali-amd64`. Together with Phase 4's `file_open`
result on `7.0.12`, all four events of the alphabet now have a measured pre-effect denial —
though on two different kernels, which §4 keeps separate rather than merging.

The 5B.0 semantic freeze is unaffected. The trace-meaning question raised in Step 3 remains
open, and the verdict domain identified in Steps 1 and 2 remains undefined.
