# Event Identity: Analysis of Candidate Semantics

**Status.** Analysis for a decision, not a decision. The frozen v1 specification is unchanged
by this document. It sets out what each candidate semantics would mean formally, what
security property each yields, and what each costs, so the choice can be made on stated
grounds rather than on which hook proved convenient.

**The question.** Phase 4B established that `EXEC` can be defined on the pathname passed to
the syscall, because `bprm->filename` carries it. It also established that `OPEN` cannot:
`lsm/file_open` receives a `struct file`, by which point the pathname has been consumed. No
hook offers an as-passed pathname for `OPEN`.

The alphabet therefore cannot define all four events the same way by default. Something must
be chosen.

---

## 1. Evidence

### 1.1 Resolution is not a no-op

| Category | Literal | Resolves to |
|---|---|---|
| Security-relevant data files | `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/crontab`, `/boot/grub/grub.cfg` | themselves (5/5) |
| Other config files | `/etc/localtime` | `/usr/share/zoneinfo/Asia/Kolkata` |
| | `/etc/mtab` | `/proc/<pid>/mounts` |
| | `/var/run` | `/run` |
| | `/etc/os-release` | `/usr/lib/os-release` |
| Executables | `/usr/bin/python3` | `/usr/bin/python3.13` |
| | `/bin/bash` | `/usr/bin/bash` |
| | `/bin/sh` | `/usr/bin/dash` |
| | `/usr/bin/curl`, `/usr/bin/wget`, `/usr/sbin/useradd` | themselves |

The files a security policy most often protects happen to resolve to themselves. That is a
convenience, not a guarantee: symlinked configuration files are common, and the sample above
is biased toward files that are deliberately real.

### 1.2 Name-based matching is evadable by an unprivileged user

```
$ ln -s /etc/shadow /tmp/evade-test
$ readlink -f /tmp/evade-test
/etc/shadow
```

Creating a symlink requires no privilege and no write access to the target. Under name-based
matching, `OPEN("/etc/shadow")` does not match `open("/tmp/evade-test")`, and the policy is
bypassed by one command.

Phase 4B measured the corresponding behaviour for `EXEC`: passing a symlink yields
`bprm->filename` = the symlink and resolved path = the real binary. Under as-passed matching,
`EXEC("/usr/bin/python3")` does not match execution through a symlink the attacker created.

**This is the central finding for the decision.** Name-based identity is trivially evadable;
object-based identity is not.

### 1.3 Evasion defeats the whole policy, not one step

A v1 policy is a sequence, and the automaton advances only on exact matches. Evading any one
event prevents the violation state from being reached. A policy

```
ON EXEC("/usr/bin/python3") THEN EXEC("/bin/bash") THEN WRITE("/etc/shadow") DENY
```

is defeated entirely by evading the first `EXEC`. It is not the case that a resolved-identity
`WRITE` rescues a name-identity `EXEC`: the chain never reaches the write.

---

## 2. Candidate A — event-specific identity

$$
\begin{aligned}
\texttt{EXEC}(p) &: \text{the pathname argument to the execution interface is } p \\
\texttt{OPEN}(p) &: \text{the opened object's resolved path is } p \\
\texttt{WRITE}(p) &: \text{the written object's resolved path is } p \\
\texttt{DELETE}(p) &: \text{the name } p \text{ is removed}
\end{aligned}
$$

**Formal impact: none.** $\Sigma = \mathcal{T} \times \mathcal{S}$ is unchanged; arguments
remain strings compared by structural equality. Definition 1, Lemma 1, and Theorems 1–3 are
untouched, because they are statements about an automaton over $\Sigma$ and are indifferent
to what the arguments denote. Only §8, expressiveness, changes.

**Implementability: established.** Every event maps to a measured hook with the required
value available (Phase 4B §1, §2; Phase 4 §2).

**Security property: weak for `EXEC`.** `EXEC(p)` constrains a name. An adversary who can
create a symlink, make a hard link, copy the binary, use a relative path, or use `execveat`
executes the same program without matching the policy. §1.2 shows the first of these costs
one unprivileged command.

**Authoring: natural.** The author writes the path they know, and for `EXEC` it matches what
they wrote. For `OPEN`/`WRITE`/`DELETE` on typical protected files, resolution is a no-op
(§1.1), so the author's literal also matches — but silently fails on a symlinked target such
as `/etc/localtime`.

**Cost not otherwise visible:** the alphabet becomes heterogeneous. Two events written
identically in a policy mean structurally different things, and nothing in the policy text
signals which. A reader of `EXEC("/a/b")` and `OPEN("/a/b")` cannot tell that the first
constrains a name and the second an object.

---

## 3. Candidate B — unified resolved-object identity

$$
\forall t \in \mathcal{T}: \quad t(p) : \text{the resolved path of the object acted upon is } p
$$

**Formal impact: none to the theorems**, for the same reason as A.

**Security property: strong and uniform.** Symlinks, hard links, relative paths and
`execveat` all resolve to the same object, so none of them evades a policy. The evasion in
§1.2 fails.

**Authoring: broken for versioned executables, silently.** The author writes
`EXEC("/usr/bin/python3")`; the system observes `/usr/bin/python3.13`; the policy compiles,
validates, loads, and never fires. This is the failure mode identified in Phase 4 §4.1, and
it is the worst kind: a well-formed policy that protects nothing, with no error anywhere.

**Implementability: established**, and in fact simpler — `bpf_d_path` on the hook's own
object, uniformly, with no need to read `bprm->filename`.

---

## 4. Candidate D — unified resolved identity with validating policy load

Semantics exactly as B. The difference is operational, and deliberately outside the formal
core:

```
policy text  ->  [ validator ]  ->  compiler C  ->  automaton
                      |
                 host filesystem
```

The validator, on the host where the policy will be enforced, checks each literal $p$:

1. **Does `p` exist?** A policy naming a nonexistent path can never match. Report it.
2. **Does `p` resolve to itself?** If not, report the resolution and refuse to load, or
   require an explicit acknowledgement:
   ```
   policy protect_shadow line 4: EXEC("/usr/bin/python3")
     this path resolves to /usr/bin/python3.13 on this host
     under resolved-object semantics the policy as written will not match
     write the resolved path, or re-run with --accept-unresolved
   ```

**Formal impact: none.** The validator is not part of $C$. $C$ remains a pure function of the
policy text, so Theorem 2 is stated about exactly the same object as before. This is the
specific property that compile-time normalisation would have destroyed: normalisation
rewrites the policy and makes the compiled automaton a function of the host, whereas
validation only *reports*, and the author decides.

**Security property:** as B — strong and uniform.

**Authoring:** the silent failure of B becomes a loud one. The policy text becomes
host-specific where resolution is non-trivial, which is visible in the text rather than
hidden in the compiler.

**Residual hazard:** a policy naming `/usr/bin/python3.13` stops matching when the package is
upgraded to `3.14`. Check 1 catches this, but only when the validator is re-run. That makes
re-validation on package change an operational requirement, which should be stated rather
than assumed.

---

## 5. Comparison

| | A: event-specific | B: unified resolved | D: unified resolved + validation |
|---|---|---|---|
| Theorems 1–3, Lemma 1 | unchanged | unchanged | unchanged |
| $C$ remains a pure function of policy text | yes | yes | **yes** |
| `EXEC` evadable by `ln -s` | **yes** | no | no |
| `OPEN`/`WRITE` evadable by `ln -s` | no | no | no |
| Versioned-binary policy fails | no | **yes, silently** | yes, **loudly** |
| Symlinked-target policy fails | yes, silently | no | no |
| All four events mean the same kind of thing | **no** | yes | yes |
| Policy text is host-independent | yes | yes | **no**, where resolution is non-trivial |
| Requires reading `bprm->filename` | yes | no | no |

---

## 6. Assessment

**A is the most comfortable and the least defensible.** It preserves the authoring experience
and requires no tooling, but it leaves `EXEC` — the first event of the canonical policy —
bypassable by a command any user can run, and §1.3 shows that defeats the entire chain. For a
system whose contribution is a formally specified security guarantee, an evasion that cheap
is difficult to justify in the threat model. It would have to be stated as an explicit
non-goal: *SentinelFS `EXEC` policies constrain names and do not constrain execution of the
underlying file.* That is a substantial weakening of what a reader would assume the tool does.

**B has the right security property and an unacceptable failure mode.** A policy that
compiles, validates, loads, and silently protects nothing is worse than a policy that is
rejected, and worse than no policy at all, because it produces false assurance.

**D is B with the failure mode moved from silent to loud**, at the cost of host-specific
policy text and a validation step that must be re-run when the filesystem changes. The
validator is outside the formal core by construction, so nothing proved about $C$ is
affected.

**Recommendation: D**, with the following stated explicitly in the specification:

- $\mathcal{S}$ denotes resolved filesystem paths. Every event type names the object acted
  upon, not the name by which it was reached.
- Policy literals are therefore host-specific where resolution is non-trivial. Validation is
  required at load time and after any change that could alter resolution.
- `execveat` with a directory descriptor remains outside what an `EXEC(p)` policy matches
  (Phase 4B §1.1), regardless of this choice; the synthetic `/dev/fd/N/…` path names no
  object. This is an expressiveness boundary and should be recorded as one.

**If host-specific policy text is unacceptable**, the fallback is A with the `EXEC` weakness
documented as an explicit non-goal. That is a coherent position, but it should be taken
knowingly rather than by default, and the threat model must then exclude an adversary who can
create a symlink — which is nearly every adversary.

---

## 7. What this does not settle

- **Bind mounts and mount namespaces.** The same object is reachable at multiple resolved
  paths, and `bpf_d_path` is namespace-relative. Under any of A, B or D, a resolved path is
  not a unique object identifier across namespaces. Untested, and it bears on all three.
- **Device and inode identity** remains a fourth candidate, not analysed here. It is immune
  to every naming evasion, and it changes $\mathcal{S}$ from strings to identifiers, so
  Definition 1's structural equality changes meaning and a policy cannot name a file that
  does not yet exist. That is a larger revision than the question at hand warrants, but it is
  the only option that is evasion-proof by construction.
- **`TOCTOU` between resolution and use.** Whether the path resolved at the hook is still the
  path acted upon is not established, and matters for enforcement rather than observation.
