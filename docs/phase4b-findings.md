# Phase 4B Findings: Event Identity and Coverage

**Purpose.** Phase 4 left two questions open and recorded one conclusion that turned out to
be wrong. This phase asks what each event means at the enforcement interface, and whether
that meaning is available:

- **EXEC** — can the hook recover the pathname passed to the exec syscall, which is what the
  frozen semantics appear to name, rather than only the resolved object?
- **DELETE** — which mechanisms for destroying an object produce an event?

Observe-only. Same platform as Phase 4: kernel `7.0.12+kali-amd64`, eight hooks attached.

---

## Summary

| Question | Outcome |
|---|---|
| `EXEC` | **A — the specification stands.** The as-passed pathname is recoverable |
| `DELETE` | **A — implementable**, with a specific hook set; the Phase 4 bypass claim was wrong |
| `OPEN` | **C — underspecified.** Only the resolved object is available; there is no as-passed path |
| `WRITE` | inherits `OPEN`'s resolution semantics through the correlation map |

One Phase 4 finding is **retracted** (§4). One new specification question is **raised** (§3).

---

## 1. `EXEC`: the pathname argument is recoverable

`struct linux_binprm` carries `filename`, `interp` and `fdpath` in addition to the resolved
`file`. Capturing all of them on the same execution, against the exact string the workload
passed to `execv`:

| Case | passed to syscall | `bprm->filename` | resolved `d_path` | match |
|---|---|---|---|---|
| absolute | `/bin/true` | `/bin/true` | `/usr/bin/true` | **yes** |
| symlink | `/tmp/…/E2-link-to-true` | `/tmp/…/E2-link-to-true` | `/usr/bin/true` | **yes** |
| versioned | `/usr/bin/python3` | `/usr/bin/python3` | `/usr/bin/python3.13` | **yes** |
| relative | `./E4-relative.sh` | `./E4-relative.sh` | `/tmp/…/E4-relative.sh` | **yes** |
| script | `/tmp/…/E5-script.sh` | `/tmp/…/E5-script.sh` | `/tmp/…/E5-script.sh` | **yes** |
| `execveat` | `E6-execveat.sh` | `/dev/fd/3/E6-execveat.sh` | `/tmp/…/E6-execveat.sh` | no |

**Five of six.** `bprm->filename` is the pathname as handed to the syscall, preserved through
symlinks, version links and the usr-merge — exactly the value the Phase 4 finding said was
unavailable at the enforcement hook. It is available; Phase 4 simply did not read that field.

**The `EXEC` specification therefore stands as written.** No revision is required, and none of
the three compromises sketched in the Phase 4 findings needs to be taken. The adapter must
read `bprm->filename`, not `bpf_d_path(&bprm->file->f_path, …)`.

### 1.1 Three qualifications

**`execveat` with a directory descriptor.** The kernel synthesises `/dev/fd/3/E6-execveat.sh`,
flagged by `interp_flags = 4`. Neither the passed string nor a usable path. A policy naming an
absolute path does not match an `execveat` of the same file. This is a gap in coverage, and
the flag makes it detectable: an adapter can identify these executions even though it cannot
name them.

**Relative pathnames come through relative.** `./E4-relative.sh` is reported verbatim. Under
syscall-argument semantics that is correct — it is what was passed — but a policy naming
`/tmp/…/E4-relative.sh` does not match an execution of `./E4-relative.sh` from that
directory. The same file is reachable under names that do not match the policy.

**Consequently, `EXEC(p)` constrains a name, not a file.** An adversary who can execute a
protected binary under a different name — a relative path, a symlink they create, a hard
link, or `execveat` — is outside what an `EXEC(p)` policy can express. This follows from the
semantics rather than from the implementation, and it belongs in the specification's
expressiveness section rather than being treated as a defect.

### 1.2 Interpreted scripts

Two binprm passes, as Phase 4 observed, but `filename` behaves consistently across them:

| Pass | `filename` | resolved | `interp` |
|---|---|---|---|
| 1 | `/tmp/…/E5-script.sh` | `/tmp/…/E5-script.sh` | `/tmp/…/E5-script.sh` |
| 2 | `/tmp/…/E5-script.sh` | `/usr/bin/dash` | `/bin/sh` |

`filename` names the script in both passes; only the resolved path and `interp` change. An
adapter matching on `filename` sees the script twice rather than seeing the script and then
the interpreter — so `EXEC(script)` fires, and `EXEC(/bin/sh)` does not, which is the
behaviour a policy author naming the script would expect. The duplicate must be suppressed,
which `interp` makes possible.

This also resolves the Phase 4 §4.3 question: with `filename` as the argument, the two `EXEC`
hooks no longer disagree about scripts in a way that affects matching.

---

## 2. `DELETE`: implementable with the right hook set

Nine destruction mechanisms against all six deletion hooks:

| Case | destroys? | hooks that fired | rename detail |
|---|---|---|---|
| `unlink(2)` | yes | `path_unlink`, `inode_unlink` | |
| `unlinkat(2)` | yes | `path_unlink`, `inode_unlink` | |
| `rmdir(2)` | directory | `path_rmdir`, `inode_rmdir` | |
| **`rename(2)` over existing** | **yes** | **`path_rename`, `inode_rename`** | `dest_exists=1, flags=0` |
| `rename(2)`, fresh destination | no | `path_rename`, `inode_rename` | `dest_exists=0` |
| `renameat2` `RENAME_NOREPLACE` | refused by kernel | none | `rc=-1, errno=EEXIST` |
| `renameat2` `RENAME_EXCHANGE` | no (swap) | `path_rename`, `inode_rename` | `dest_exists=1, flags=2` |
| unlink one of two hard links | no (a name) | `path_unlink`, `inode_unlink` | |
| `truncate(2)` to zero | contents only | none of the deletion hooks | |

Every mechanism that destroys an object produces an event, provided the unlink, rmdir **and
rename** hooks are all attached.

### 2.1 Only `path_rename` can distinguish destruction from exchange

`dest_exists` alone is not sufficient. `RENAME_EXCHANGE` also reports `dest_exists=1`, and
destroys nothing: it swaps two files. Destruction is

```
dest_exists == 1  AND  NOT (flags & RENAME_EXCHANGE)
```

`inode_rename`'s signature carries no flags argument, so it reports `flags=0` unconditionally
and **cannot** make this distinction. Only `path_rename` can. Since `path_rename` is gated on
`CONFIG_SECURITY_PATH`, a kernel built without it cannot distinguish a destructive rename
from an exchange through these hooks at all.

### 2.2 What `DELETE(p)` should be taken to mean

The hardlink case makes the ambiguity concrete: unlinking one of two names fires the hook, and
the file survives under the other name. `DELETE(p)` therefore means **"the name `p` is
removed"**, not "the object at `p` is destroyed". The two readings coincide only when `p` is
the last link.

Truncation removes no name and fires no deletion hook, so it is correctly outside `DELETE`.
Whether it should be within `WRITE` is a separate question this phase does not settle.

---

## 3. `OPEN`: only the resolved object is available

Opening a file through a symlink:

| | value |
|---|---|
| passed to syscall | `/tmp/sentinel-p4b/O1-link` |
| dentry name | `O1-real` |
| resolved `d_path` | `/tmp/sentinel-p4b/O1-real` |

**The name the caller opened is not present in the hook.** `lsm/file_open` receives a
`struct file`, which refers to the object after resolution; there is no equivalent of
`bprm->filename` because by the time the hook runs, the pathname has been consumed.

This is an asymmetry in the alphabet that the specification does not currently acknowledge:

| Event | as-passed pathname | resolved object |
|---|---|---|
| `EXEC` | available (`bprm->filename`) | available |
| `OPEN` | **not available** | available |
| `WRITE` | not available | available, via correlation from `OPEN` |
| `DELETE` | dentry name + directory path | composed |

If the specification defines `EXEC` by the syscall argument, as §1 shows it may, then `OPEN`
cannot be defined the same way — no hook offers that value. Either `OPEN(p)` is defined on
the resolved object while `EXEC(p)` is defined on the passed pathname, which makes the two
event types mean structurally different things, or both are defined on the resolved object,
which discards the `EXEC` result of §1 and reinstates the `python3`/`python3.13` mismatch.

**This is a genuine specification question and it is left open.** It is smaller than the
Phase 4 `EXEC` problem — nothing fails silently, because whichever definition is chosen is
implementable — but the alphabet should say which notion each event names, rather than
leaving it to be inferred from whichever hook an implementation chose.

`WRITE` inherits whatever `OPEN` decides, because its path comes from the correlation map
populated at `file_open`.

---

## 4. Retraction: the Phase 4 `DELETE` enforcement bypass

Phase 4 §4.2 stated:

> `rename(2)` over an existing file destroys that file and produces no unlink event. A policy
> of the form `DENY DELETE("/etc/passwd")` does not prevent an attacker from destroying
> `/etc/passwd` by renaming another file over it. **This is an enforcement bypass**, not
> merely a monitoring gap.

**The first sentence is correct; the conclusion is wrong.** No *unlink* event is produced, but
`path_rename` and `inode_rename` both fire, with `dest_exists=1` identifying the destructive
case precisely. Phase 4 attached only the unlink hooks, so it observed the absence of unlink
events and inferred an absence of events. That inference was unsound.

The corrected statement: **`DELETE` requires the rename hooks in addition to the unlink hooks.**
An implementation attaching only unlink hooks does have the bypass Phase 4 described, which
makes this a real constraint on the adapter — but it is a hook-selection requirement, not a
limitation of Linux or of the specification.

The error is recorded rather than quietly amended because it illustrates a methodological
point: an experiment that instruments one mechanism can only report on that mechanism, and
"no event was observed" means "no event was observed **by the attached hooks**". Phase 4's
instrumentation could not have detected rename coverage, so its conclusion exceeded its
evidence.

---

## 5. Limitations

- **One kernel, one host.** `CONFIG_SECURITY_PATH` is enabled here; where it is not, §2.1
  means destructive renames cannot be distinguished from exchanges.
- **Observe-only.** That these hooks can *deny*, and at what cost, remains unmeasured for
  everything except `file_open` (Phase 4, experiment 1).
- **`execveat` coverage is a gap, not a measurement artefact.** It was tested once, with a
  directory descriptor and a relative name. Other forms (`AT_EMPTY_PATH` with an opened file
  descriptor) were not tested and may behave differently.
- **Mount namespaces and bind mounts were not tested.** The same object is reachable at
  multiple paths under bind mounts, and `d_path` is namespace-relative. Both bear on what a
  path-based policy can express and neither was exercised.
- **No performance measurement.** `file_open` fired 438 times and `bprm_check_security` 33
  times during 16 cases; the cost of resolving and evaluating on those paths is unknown.

---

## 6. Conclusion

Both questions Phase 4 left open are answered, and neither requires changing the frozen
semantics:

- **`EXEC` is implementable as specified**, by reading `bprm->filename` rather than resolving
  the executable. The Phase 4 finding that the as-passed pathname was unavailable was a
  consequence of reading the wrong field. Three qualifications (§1.1) belong in the
  expressiveness section: `EXEC(p)` constrains a name rather than a file, and `execveat` and
  relative pathnames fall outside what such a policy matches.
- **`DELETE` is implementable**, provided the rename and rmdir hooks are attached alongside
  the unlink hooks, and provided `path_rename` is available to distinguish a destructive
  rename from an exchange. The Phase 4 bypass claim is retracted (§4).

One new question is raised: **`OPEN` has no as-passed pathname available at any hook** (§3),
so the alphabet cannot define all four events the same way. The specification should state
which notion of identity each event names. That decision is not made here.

The adapter remains unbuilt.
