# Phase 5A-E3 Findings: Correlation Capacity and Degradation

**Question.** A1b makes the `WRITE` correlation part of the enforcement path: Phase 4
established that `bpf_d_path` is rejected on `lsm/file_permission`, so a write's pathname can
come only from an association established at `file_open`. Its capacity is therefore a security
property.

The question is not how many entries fit. It is what happens when they do not, and
specifically whether any failure mode yields a **wrong** pathname rather than **no** pathname.
A missing pathname is what A1b specifies: the event is not a `WRITE(p)` for any $p$. A wrong
one would mean a policy naming one file matching a write to another, which no amount of
capacity would fix.

**Method.** The probe stores the inode alongside the path at `file_open` and compares it
against the file's actual inode at `file_permission`. A hit whose inode disagrees is a stale
entry, counted separately from a correct hit and from a miss, and emitted in full so it can be
examined. Map capacity was set to 64 entries, small enough to exhaust deliberately. All files
were created before the probe attached, per methodology rule M4.

Platform: kernel `7.0.12+kali-amd64`. Observe-only.

---

## 1. Results

| Counter | Value |
|---|---|
| `open_seen` | 1,024 |
| `insert_ok` | 928 |
| `insert_fail` | **96** |
| `write_seen` (writes that found an entry) | 928 |
| `lookup_hit_correct` | 928 |
| **`lookup_hit_stale`** | **0** |
| `lookup_miss` | 478 |
| `free_seen` | 928 |
| `delete_ok` | 928 |
| `delete_miss` | 0 |

Scenarios: 32 files held open (under capacity), 160 held open (over), 400 open/close cycles
alternating two files, 32 opened after release.

### 1.1 The accounting is exact

| Check | |
|---|---|
| workload opens (32 + 160 + 800 + 32) | 1,024 |
| `open_seen` | 1,024 |
| `insert_ok` + `insert_fail` | 1,024 |
| T2 overflow predicted: 160 held open, capacity 64 | 96 |
| `insert_fail` observed | **96** |

Every open was seen, every open either inserted or was refused, and the number refused equals
exactly the predicted overflow. Capacity behaved as a hash map of that size should: the first
64 simultaneous entries were admitted and the remaining 96 refused.

### 1.2 No stale resolution occurred

**`lookup_hit_stale` = 0 across 928 hits**, including 800 open/close cycles specifically
designed to provoke `struct file` pointer reuse.

The reason is visible in the cleanup counters: `free_seen` = `delete_ok` = 928, with
`delete_miss` = 0. Every entry that was inserted was deleted at `file_free_security`, and the
deletion happened before the address could be reused. The hook is load-bearing: without it,
pointer reuse would silently produce entries resolving to a previous file's path.

**Under the tested scenarios, correlation failure degrades to an absent pathname rather than a
wrong one.** That is what A1b requires, and it means A1b describes a degradation mode rather
than papering over an unsound one.

### 1.3 Capacity recovered

`insert_fail` is exactly 96, which is T2's overflow alone. T4 ran after both the overflow and
the reuse scenarios and its 32 opens were all admitted. Releasing descriptors returned capacity.

### 1.4 The miss count is not attributable to the workload

`lookup_miss` = 478, against 96 workload writes that had no entry. The difference is host
activity: the `file_permission` handler cannot filter by pathname, because `bpf_d_path` is
forbidden at that hook, so it counts every write on the system that finds no correlation entry.

This is worth stating because the figure would otherwise look like unexplained loss. Of the
1,024 workload writes, 928 resolved and 96 did not — matching the insertion failures exactly.
The remaining 382 misses belong to unrelated processes.

---

## 2. The security consequence, demonstrated

96 writes produced no `WRITE(p)` event for any $p$, because the descriptors they were issued
through had no correlation entry.

**An adversary who holds enough descriptors open suppresses `WRITE` enforcement entirely,
without triggering any policy.** The writes still occur. No automaton advances. No violation
is recorded, because under A1b nothing happened that is in $\Sigma$.

This is consistent with the specification rather than a defect in it, and that is precisely
the point: A1b is not bookkeeping about instrumentation, it is the statement that makes this
behaviour specified. What the experiment adds is that the threshold is *reachable by design*
rather than only under extreme load — 64 simultaneously open descriptors in this
configuration, and any real deployment must choose a number.

Three properties combine badly:

1. The failure is **silent**. An unresolved write is indistinguishable, in the event stream,
   from a write that did not happen.
2. The failure is **targeted**. An adversary chooses when to exhaust the map.
3. The failure **only affects `WRITE`**. `EXEC`, `OPEN` and `DELETE` resolve their arguments at
   the hook and are unaffected, so a policy's other events continue matching while the write
   step silently never fires — and since the automaton requires every event, the policy never
   reaches its violation state.

**This should be recorded in the threat model.** §7 of v1.2 already excludes an adversary who
can arrange for writes through descriptors the monitor never saw opened; exhausting the
correlation map is a *mechanism* for producing exactly that condition, and it deserves naming
rather than being left implicit in A1b.

---

## 3. What this constrains for the adapter

**Capacity is a security parameter, not a tuning parameter.** It bounds how many descriptors
an adversary must hold to blind `WRITE` enforcement. Sizing it is a threat-model decision.

**Eviction is not available as a remedy.** Evicting a correlation entry makes subsequent writes
through that descriptor unresolvable, which is the same blindness arrived at deliberately. If
capacity pressure is to be handled by eviction, the specification must say which writes are
then outside $\Sigma$ — and that is a change to A1b, not an implementation detail. §8 of v1.2
already forbids an implementation from making such a change on its own.

**Insertion failure must be observable.** The probe counted 96 refusals; an adapter that did
not would have no way to report that its `WRITE` coverage had degraded. Whether the evidence
layer must record correlation failures is a Phase 6 question, but the answer is very likely
yes: a policy that silently stops protecting is worse than one that reports it cannot.

**The release hook is required for soundness, not only for capacity.** §1.2 shows that without
deletion at `file_free_security`, pointer reuse would produce stale resolutions. An adapter
must attach it, and must handle its failure.

---

## 4. Limitations

- **One capacity, one configuration.** 64 entries on one kernel. The absence of stale
  resolutions is evidence about this map type and this cleanup path, not a proof that no
  configuration produces them.
- **Reuse was provoked, not forced.** 800 open/close cycles did not produce an address
  collision that outran the delete. A workload designed adversarially against the allocator,
  or one running under memory pressure, might.
- **`BPF_MAP_TYPE_HASH` only.** Other map types have different eviction and capacity
  behaviour; `BPF_MAP_TYPE_LRU_HASH` in particular evicts silently by design, which §3 argues
  is a semantic change rather than a convenience.
- **No concurrent exhaustion.** The scenarios were single-process. Whether insertion failures
  behave the same when several CPUs contend on a full map is untested.
- **Observe-only.** No enforcement decision was taken on any of these events.
