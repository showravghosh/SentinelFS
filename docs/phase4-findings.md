# Phase 4 Findings: Synchronous Enforcement Feasibility

**Scope.** This phase asked whether the frozen v1 event alphabet can be implemented as
synchronous kernel enforcement events. It did not modify the specification. Where a hook
does not mean what the specification says, that is recorded as a result.

**Platform.** Kali Linux, kernel `7.0.12+kali-amd64`, x86-64 VM. `CONFIG_BPF_LSM=y`, BTF at
`/sys/kernel/btf/vmlinux`, `bpf` present in the active LSM list, 279 `bpf_lsm_*` hooks
exposed. libbpf 1.7.0, clang 21.1.8.

---

## Summary

| Question | Answer |
|---|---|
| P3 — can BPF LSM prevent an operation synchronously? | **Yes**, demonstrated |
| P1 — `EXEC` | hook available, **argument does not match the specification's** |
| P1 — `OPEN` | `lsm/file_open`, faithful |
| P1 — `WRITE` | `lsm/file_permission` + `MAY_WRITE`, **faithful**, but cannot name its own object |
| P1 — `DELETE` | unlink hooks cover `unlink(2)` only; **two silent gaps** |
| P2 — path availability | constrained; see §3 |
| P4 — state placement | not yet decided; see §6 |

Three findings bear on the specification. One of them, §4.1, breaks policies silently rather
than loudly, and is the most consequential result of this phase.

---

## 1. Synchronous enforcement works (P3)

Experiment 1 attached a program to `lsm/file_open` denying write-opens of one fixed path,
and measured the effect rather than the return code.

| Check | Result |
|---|---|
| baseline write succeeds (test is meaningful) | pass |
| write refused while attached | pass, `EPERM` |
| **file contents unchanged** | pass |
| reads still permitted | pass |
| control file unaffected | pass |
| enforcement stops on detach | pass |

Probe counters: 7 hook calls, 2 write-opens resolved, 1 target seen, 1 denied.

The operation did not occur. This establishes the mechanism; it does not establish that any
particular event can be implemented, which is what the rest of this phase examines.

**Note on what experiment 1 did *not* show.** It denied *opening a file with write intent*,
which is not the event the specification calls `WRITE(path)`. Experiment 1 is retained
unmodified as a demonstration of the mechanism, and its hook choice is not a claim about
event semantics.

---

## 2. `WRITE(path)` is faithfully implementable (P1)

Four cases distinguish "wrote" from "opened for writing". Each case's file is created by the
harness with one write, so the harness contributes exactly 1 to each count and the case's own
writes are the excess.

| Case | Operations | `file_permission` + `MAY_WRITE` | attributable to case |
|---|---|---|---|
| A | open, write once, close | 2 | **1** |
| B | open, close, **no write** | 1 | **0** |
| C | read-only open and read | 1 | **0** |
| D | open, write three times | 4 | **3** |

`lsm/file_permission` filtered on `MAY_WRITE` fires **once per write**, is **silent** when a
file is opened for writing and never written, and is **silent** on read-only access. That is
exactly the specification's `WRITE(p)`.

For comparison, `file_open` with `FMODE_WRITE` on the same files:

| Case | records |
|---|---|
| A (one write) | 2 |
| B (**no write**) | **2** |
| C (read-only) | 1 |
| D (three writes) | **2** |

`file_open` fires when nothing was written and does not scale with the number of writes. It
denotes intent, not the operation, and **cannot implement `WRITE(path)`** without a
specification change. It is not adopted.

Pipe and socket writes produced no record, consistent with A1b: objects with no filesystem
path do not become `WRITE(p)` for any `p`.

---

## 3. Path availability is the binding constraint (P2)

Two kernel restrictions were found, both by verifier rejection rather than by reading
documentation.

### 3.1 `bpf_d_path` requires a trusted pointer

```
call bpf_d_path#147
R1 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_
```

`BPF_CORE_READ(bprm, file)` compiles to `bpf_probe_read_kernel`, whose result the verifier
treats as an untrusted scalar. Path resolution is therefore available only where the object
is reachable by **direct dereference from the hook's own arguments**. Writing
`bpf_d_path(&bprm->file->f_path, ...)` succeeds where reading the field first does not.

### 3.2 `bpf_d_path` is forbidden on the `WRITE` hook

```
call bpf_d_path#147
helper call is not allowed in probe
```

The kernel permits `bpf_d_path` in an LSM program only when the attached hook is in the
sleepable set. `lsm/file_permission`, being on the read/write path, is not. **The one hook
with the correct `WRITE` semantics cannot name its own object.**

### 3.3 Consequence: A1b becomes load-bearing at enforcement time

The only available route is to resolve the path where it is permitted — at `file_open` — and
carry it forward in a map keyed by the `struct file`, releasing entries at
`lsm/file_free_security`. This was implemented and works: 23 `file_permission` records were
emitted with correctly resolved paths.

This is the same fd-correlation used in Phase 2, but its status changes. In observation mode
an unresolvable write was a gap in the data. In enforcement mode the kernel is asking for a
verdict, and a file whose open was never observed **cannot be named in the write hook by any
means available to that hook**.

A1b already states that a `WRITE(p)` event exists only where the descriptor's provenance was
observed. Phase 4 shows this is not merely a property of the chosen instrumentation but a
constraint imposed by the kernel on any BPF LSM implementation. The assumption should be
restated accordingly, and its enforcement-time consequence made explicit.

### 3.4 `DELETE` object identity

| Hook | Context carries | Object identification |
|---|---|---|
| `lsm/path_unlink` | `struct path *dir`, `struct dentry *dentry` | directory path + victim name |
| `lsm/inode_unlink` | `struct inode *dir`, `struct dentry *dentry` | **victim name only** |

`inode_unlink` receives no `struct path`, so there is nothing for `bpf_d_path` to resolve. Of
the two, only `path_unlink` can yield a full path, and only by composing the directory path
with the dentry name. Both hooks fired on every `unlink(2)` in the workload, so `path_unlink`
is available on this kernel despite being gated on `CONFIG_SECURITY_PATH`.

---

## 4. Findings that bear on the specification

### 4.1 The argument of `EXEC` depends on which hook observes it

The specification defines $\Sigma = \mathcal{T} \times \mathcal{S}$ with **structural
equality** on arguments. That presumes each event has one argument. It does not.

| Executed | Phase 2, `sched_process_exec` | Phase 4, `lsm/bprm_check_security` |
|---|---|---|
| `/usr/bin/python3` | `/usr/bin/python3` | **`/usr/bin/python3.13`** |
| `/usr/sbin/ip` | `/usr/sbin/ip` | **`/usr/bin/ip`** |
| `/bin/sh` | — | **`/usr/bin/dash`** |

The tracepoint reports the path as passed to `execve(2)`. The LSM hook, via
`bpf_d_path(&bprm->file->f_path, ...)`, reports the **resolved dentry path**, with symlinks
followed: version symlinks (`python3` to `python3.13`), the usr-merge (`/bin` to `/usr/bin`),
and alternatives (`/bin/sh` to `dash`).

**Consequence.** The repository's own example policy names `/usr/bin/python3` and
`/bin/bash`. Under enforcement, the observed arguments would be `/usr/bin/python3.13` and
`/usr/bin/bash`. Neither matches under structural equality. **The policy would compile, load,
validate, and never fire.**

This is worse than the `SPAWN` finding of Phase 2. `SPAWN` failed loudly: the event could not
be matched and the mismatch was visible. This fails silently: a well-formed policy naming a
real binary protects nothing, and there is no error anywhere to indicate it.

**This requires a specification decision before an adapter is built.** The options, none of
which is free:

1. **Define $\mathcal{S}$ as kernel-resolved paths.** Precise and unambiguous, and it makes
   the two observation mechanisms agree by fiat — Phase 2's tracepoint mapping would have to
   be revised to resolve paths too. The cost is that policies stop being portable: a policy
   naming `/usr/bin/python3.13` is wrong on a host with a different minor version, and
   authors must write paths they did not type and may not know.
2. **Normalise at policy-compile time.** Resolve the policy's literals when the policy is
   compiled, so both sides speak resolved paths. The cost is that compilation becomes
   host-dependent and time-dependent: the same policy compiles to different automata on
   different machines, and a package upgrade silently invalidates a compiled policy. It also
   breaks the property that compilation is a pure function of the policy text, which
   Theorem 2 is stated about.
3. **Match on file identity rather than path.** Compare device and inode number instead of
   a string. This is what the kernel actually means by "the same file", and it is immune to
   symlinks and renaming. The cost is the largest: `\mathcal{S}` is no longer strings,
   Definition 1's structural equality changes meaning, and a policy can no longer name a file
   that does not yet exist.

Option 3 is the most semantically honest and the most disruptive. Option 1 is the smallest
change to the formalism. The decision is deferred to a deliberate specification revision and
is not made here.

### 4.2 `DELETE(path)` does not cover all deletion

Four destructive operations, and which produced an unlink hook record:

| Operation | `path_unlink` | `inode_unlink` | File destroyed? |
|---|---|---|---|
| `unlink(2)` | 1 | 1 | yes |
| **`rename(2)` over an existing file** | **0** | **0** | **yes** |
| `rmdir(2)` | 0 | 0 | directory removed |
| unlink one of two hard links | 1 | 1 | no, a name was removed |

The records observed in the rename case were verified by timestamp to be the harness's own
cleanup `unlink()` (`ts=...073028`, after the rename at `ts=...063344`), not the rename.

Two gaps follow:

- **`rename(2)` over an existing file destroys that file and produces no unlink event.** A
  policy of the form `DENY DELETE("/etc/passwd")` does not prevent an attacker from
  destroying `/etc/passwd` by renaming another file over it. This is an enforcement bypass,
  not merely a monitoring gap.
- **`rmdir(2)` produces no unlink event.** If `DELETE(path)` is intended to cover
  directories, a separate hook is required.

Conversely, unlinking one of several hard links fires the hook although the file's contents
survive. Whether `DELETE(p)` means "the name `p` is removed" or "the file at `p` is
destroyed" is not currently stated, and the two readings differ exactly here.

### 4.3 The two `EXEC` hooks differ on interpreted scripts

| Case | `bprm_check_security` | `bprm_creds_for_exec` |
|---|---|---|
| execute `/usr/bin/python3` and `/bin/bash` | 2 records | 2 records |
| execute a `#!` script | **2 records**: the script and `/usr/bin/dash` | **1 record**: the script only |

The kernel processes an interpreted script as two binprm passes. `bprm_check_security` is
called for both; `bprm_creds_for_exec` once. A policy naming the interpreter fires under one
hook and not the other. The choice between them is a semantic decision about whether
`EXEC(p)` means "the kernel began executing the image `p`" or "the user requested execution
of `p`", and it should be made explicitly rather than by picking whichever hook is
convenient.

---

## 5. Measurement corrections

One correction was made during analysis, and it changed a conclusion.

**Counts included the harness's own setup and ignored the access mask.** The first analysis
counted every record a hook produced inside a case window. Each case calls a helper that
creates its file by writing it, so every case contained one extra open and one extra write
belonging to the harness. With `file_open` showing 2 records in every case and
`file_permission` showing 1 in the no-write case, the first analysis reported that
*both* candidate hooks "fire without a write occurring" and that neither could implement
`WRITE`.

That conclusion was wrong. Filtering `file_permission` by `MAY_WRITE` and subtracting the
harness's single setup write gives A=1, B=0, C=0, D=3 — exactly per-write behaviour.
`file_permission` **is** faithful to `WRITE(path)`; the earlier verdict was an artefact of
the analysis, not a property of the kernel.

The raw records were sufficient to re-derive this without re-running the experiment, because
the access mask and full path were recorded per event. Recording more than the analysis
initially uses is what made the correction possible.

---

## 6. State placement remains open (P4)

No option is selected. What Phase 4 establishes is a constraint that bears on the choice:
path resolution for `WRITE` requires state that spans two hooks — the path resolved at
`file_open` and consulted at `file_permission`. That state lived in a BPF hash map keyed by
`struct file *` and was released at `file_free_security`.

This favours keeping at least the object-identification state kernel-resident, independent of
where the automaton itself lives, because the correlation must be available synchronously
inside a hook that cannot call out to userspace. Whether the automaton can also be kernel-
resident, and what its bounds would be, is not answered here.

---

## 7. Limitations

- **One kernel, one host.** All results are from `7.0.12+kali-amd64`. The installed
  `7.1.5+kali-amd64` has not been booted. Hook availability, and particularly which hooks are
  in the sleepable set, are kernel-version-specific and must be re-established.
- **Enforcement was demonstrated only for `file_open`.** Experiment 2 was observe-only by
  design. That `file_permission`, `path_unlink` and the `bprm` hooks can deny, and at what
  cost, has not been measured.
- **No performance measurement.** `file_permission` fired 1,142 times during a workload of 26
  operations. The overhead of resolving and evaluating on that path is unmeasured, and it is
  the hook most likely to matter.
- **Correlation map bounds untested.** The map held 10,240 entries and was never filled. Its
  behaviour under pressure, and what happens to enforcement when it overflows, is unknown.
- **Symlink findings are distribution-specific.** The usr-merge and Python version symlinks
  are properties of this distribution's layout. The *phenomenon* generalises; the specific
  path pairs do not.

---

## 8. Conclusion

Synchronous enforcement via BPF LSM works, and `WRITE(path)` — the event that appeared most
at risk — is faithfully implementable, at the cost of making A1b load-bearing at enforcement
time.

The phase's more important output is three findings that bear on the frozen specification:

1. **The argument of `EXEC` is not well defined independently of the observation mechanism**
   (§4.1). Two hooks report different strings for the same execution, and the example policy
   in this repository would silently never fire under enforcement. This requires a
   specification decision.
2. **`DELETE(path)` does not cover `rename(2)` over an existing file** (§4.2), which is an
   enforcement bypass rather than a monitoring gap, nor `rmdir(2)`.
3. **The two `EXEC` hooks disagree on interpreted scripts** (§4.3), so the choice between
   them is a semantic decision and not an implementation detail.

None of these is worked around here. Building an adapter before they are settled would embed
whichever answer the hooks happened to make convenient, which is the outcome this phase
existed to prevent.
