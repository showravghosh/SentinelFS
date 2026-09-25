# Phase 4C Findings: Stability of Path Identity

**Purpose.** The event-identity analysis recommended candidate D — defining every event on the
resolved filesystem path — on the strength of one demonstration: a symlink resolves, so an
attacker cannot evade a policy by creating one. This phase tested whether that generalises to
the other routes by which a name and an object can come apart.

**It does not.** The recommendation is withdrawn in the form it was made, and the analysis
document is superseded by §5 below.

Observe-only, root, kernel `7.0.12+kali-amd64`. One object, accessed by six routes.

---

## 1. Result

All accesses below reach or replace the file created as `/tmp/sentinel-p4c/target`, inode
1147. A policy under resolved-path semantics would name `/tmp/sentinel-p4c/target`.

| Route | Reported resolved path | inode | Same object as S1? | Policy matches? |
|---|---|---|---|---|
| S1 ordinary | `/tmp/sentinel-p4c/target` | 1147 | — | yes |
| S2 symlink | `/tmp/sentinel-p4c/target` | 1147 | yes | **yes** |
| S3 hard link | `/tmp/sentinel-p4c/via-hardlink` | 1147 | yes | **no** |
| S4 bind mount | `/tmp/sentinel-p4c-bind/target` | 1147 | yes | **no** |
| S5 rename | `/tmp/sentinel-p4c/renamed-after-load` | 1147 | yes | **no** |
| S6 replacement | `/tmp/sentinel-p4c/target` | **1150** | **no** | **yes** |
| S7 mount namespace | `/tmp/sentinel-p4c-bind/target` | — | — | **no** |

Read as a property of the identity scheme:

**Resolved-path identity is not complete.** The same object was reached under three paths a
policy naming the original would not match: a hard link (S3), a bind mount (S4), and a rename
(S5). In each case the inode confirms it is the same file.

**Resolved-path identity is not sound.** After the object was deleted and a new file created
under the same name (S6), the path a policy names denotes a different object — inode 1150,
not 1147. The policy matches a file it was never written to protect.

**`bpf_d_path` reports the route, not the object.** S3 is the clearest case: the hard link
`via-hardlink` and the original `target` are the same inode with `nlink=2`, and the hook
reports whichever name was used to reach it. There is no canonical path for the kernel to
report, because a file with several hard links has no distinguished name.

**Namespace relativity is real.** S7 resolved to the bind-mount path inside a separate mount
namespace. The same object yields different paths to observers in different namespaces.

---

## 2. Correction to this experiment's own first analysis

The first run of the analysis reported S5 as a *different* object (inode 1150). That was
wrong. Scenario windows were bounded by marker timestamps, and the analysis took the last
record in each window; the S6 setup calls `write_bytes()`, which opens the file, before S6's
marker was recorded. That open therefore fell inside S5's window and displaced S5's own
record.

The corrected value, read from the raw records in time order, is inode **1147** — the same
object under a new name, which is what a rename should produce.

This is the third time in Phase 4 that setup activity inside a measurement window has
displaced the measurement. The pattern is now clear enough to state as a method rule: a
window bounded by markers is only valid if nothing between the markers touches the object
under test, and harness setup for the *next* case violates that. Records should be attributed
by matching the object accessed, not by position within a window.

---

## 3. Consequence for the candidate semantics

Restating the three candidates against the measurements:

| Evasion / hazard | A: name identity | B/D: resolved path | Device + inode |
|---|---|---|---|
| symlink (`ln -s`, unprivileged) | **evades** | resists | resists |
| hard link (`ln`, unprivileged) | **evades** | **evades** | resists |
| bind mount (root, or user namespace) | **evades** | **evades** | resists |
| rename after load | **evades** | **evades** | resists |
| replacement under the same name | false match | **false match** | resists |
| mount namespace | n/a | **path differs** | resists |
| policy names a file that does not exist yet | works | works | **cannot express** |
| policy survives the object being recreated | yes | yes | **no — binding breaks** |
| human-writable policy text | yes | yes | **no** |

**Neither path-based candidate provides object identity.** D is strictly better than A — it
resists symlinks, which A does not, and it is no worse anywhere — but "strictly better than a
scheme evadable by one unprivileged command" is a low bar, and D is evadable by a different
unprivileged command.

**Device and inode is the only scheme that resists every evasion measured**, and it fails
differently: it cannot name a file that does not exist, it cannot be written by a human, and
S6 shows its binding breaks precisely when an attacker deletes and recreates the target —
which is not an exotic attack.

---

## 4. What this means for the security claim

The honest statement of what a path-based policy can guarantee is narrower than the analysis
document assumed:

> A policy naming a path constrains operations that reach the object **by that path**. It does
> not constrain operations that reach the same object by another name, nor does it
> distinguish the object from a different object later given that name.

This is not a defect peculiar to SentinelFS. It is the same limitation AppArmor has, and it
is why SELinux uses labels carried on the inode rather than paths. The distinction matters
for the paper: a path-based mechanism with precisely characterised limits is a defensible
design, whereas a path-based mechanism claiming object-level protection is not.

What Phase 4C adds is that the limits are now *measured* rather than asserted, with the inode
as independent evidence of when two paths denote one object.

---

## 5. Revised recommendation

The recommendation of candidate D **as argued** is withdrawn: its central argument
generalised from the symlink case, and the generalisation is false.

Candidate D **as a choice between available options** still stands, on much weaker grounds:
it is no worse than A anywhere and better on symlinks. It should be adopted only together
with an explicit threat-model statement, not as a claim to object-level protection.

Concretely, the specification should record:

1. **Identity is path-based.** `𝒮` denotes resolved filesystem paths as reported by the
   observation layer, which names the route taken to the object.
2. **Naming evasions are outside the threat model**, enumerated rather than gestured at: hard
   links, bind mounts, renames of a protected object, and access from a different mount
   namespace. An adversary able to perform any of these can reach a protected object without
   matching a policy that names it.
3. **Policies are not rebound when the object changes.** A path that comes to denote a
   different object continues to match; a protected object that is renamed ceases to match.
4. Validation at policy load (the `V_H` function) reports resolution mismatches, as previously
   described. It addresses silent *loading* failures. It does not address anything in §1.

Whether that threat model is acceptable is a judgement about the intended deployment, and it
is not one this phase can make. What it can say is that the alternative — device and inode —
does not rescue the situation: it trades a complete set of naming evasions for a binding that
an attacker breaks by deleting and recreating the target.

**The remaining option worth investigating, and not investigated here, is label-based
identity**: an attribute carried on the object rather than on any name, as SELinux does with
extended attributes. It resists everything in §3's table because it travels with the inode,
and it can be expressed in policy text. It is a substantially larger design than v1
contemplates, and it would require its own feasibility phase. It should be recorded as the
principled answer that v1 does not implement, rather than left out because it is
inconvenient.

---

## 6. Limitations

- **One filesystem.** All scenarios ran on `/tmp`, device 0:42 — a tmpfs. Inode allocation,
  reuse behaviour and `d_path` results may differ on ext4, XFS, or overlayfs, and overlayfs
  is what containers actually use.
- **Inode reuse was not forced.** S6 happened to receive inode 1150. Whether a freed inode
  number can be reallocated to an attacker-controlled file, defeating an inode-based binding,
  was not tested and is the obvious next question if device+inode is pursued.
- **The user-namespace path to bind mounts was not tested.** S4 used root. Whether an
  unprivileged user can achieve the same effect through a user namespace determines whether
  S4 is a privileged or unprivileged evasion, and that materially changes its weight in the
  threat model.
- **Observe-only.** Nothing here measures whether the resolved path at the hook is still the
  path acted upon when the operation completes.
