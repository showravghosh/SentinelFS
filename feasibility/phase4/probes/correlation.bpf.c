// SPDX-License-Identifier: GPL-2.0
//
// Phase 5A-E3: correlation capacity and degradation.
//
// A1b says a WRITE(p) event exists only where the descriptor's opening was
// observed. Phase 4 established that this is not merely a property of the chosen
// instrumentation: bpf_d_path is rejected on lsm/file_permission, so the path must
// come from a correlation established at file_open. That makes the correlation map
// part of the enforcement path, and its capacity a security-relevant property.
//
// The question is not only how many entries fit. It is what happens when they do
// not, and specifically whether the failure can ever produce a WRONG pathname
// rather than no pathname. A missing pathname is consistent with A1b: the event is
// simply not a WRITE(p) for any p. A wrong pathname would be a soundness failure,
// because a policy naming one file would match a write to another.
//
// Two mechanisms could produce a wrong pathname, and both are tested:
//
//   1. Pointer reuse. The map is keyed by struct file *. If an entry outlives its
//      file and the kernel allocates a new struct file at the same address, a
//      lookup returns the previous file's path.
//   2. Exhaustion. If insertion fails silently, a later lookup misses - which is
//      safe - but the surrounding logic must not fall back to a stale or default
//      value.
//
// Detection: the inode number is stored alongside the path at open, and compared
// against the file's actual inode at write. A hit whose inode disagrees is a stale
// entry, and is counted separately from a correct hit and from a miss.
//
// The map is deliberately small so that exhaustion is reachable in a controlled
// test rather than only under production load.
//
// OBSERVE-ONLY.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 128
#define PREFIX "/tmp/sentinel-p6"
#define PREFIX_LEN 16
#define MAY_WRITE 0x2

// Deliberately small. A production adapter would size this to the policy set;
// here it must be exhaustible by a test that does not disturb the host.
#define CORRELATION_CAPACITY 64

struct correlation {
    char path[PATH_LEN];
    __u64 ino;      // identifies the object the path was resolved for
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CORRELATION_CAPACITY);
    __type(key, __u64);            // struct file *
    __type(value, struct correlation);
} correlations SEC(".maps");

enum stat_slot {
    S_OPEN_SEEN = 0,
    S_INSERT_OK,
    S_INSERT_FAIL,
    S_WRITE_SEEN,
    S_LOOKUP_HIT_CORRECT,
    S_LOOKUP_HIT_STALE,     // the soundness failure, if it occurs
    S_LOOKUP_MISS,
    S_FREE_SEEN,
    S_DELETE_OK,
    S_DELETE_MISS,
    S_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, S_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Records every stale hit in full, so a soundness failure can be examined rather
// than only counted.
struct stale_report {
    __u64 stored_ino;
    __u64 actual_ino;
    char stored_path[PATH_LEN];
    char actual_path[PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} stale_events SEC(".maps");

static __always_inline void bump(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &slot);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline int under_prefix(const char *path)
{
    const char prefix[] = PREFIX;

#pragma unroll
    for (int i = 0; i < PREFIX_LEN; i++) {
        if (path[i] != prefix[i])
            return 0;
    }
    return 1;
}

SEC("lsm/file_open")
int BPF_PROG(on_file_open, struct file *file, int prev_ret)
{
    char path[PATH_LEN] = {};
    long len = bpf_d_path(&file->f_path, path, sizeof(path));
    if (len < 0 || !under_prefix(path))
        return prev_ret;

    bump(S_OPEN_SEEN);

    struct correlation c = {};
    bpf_probe_read_kernel_str(c.path, sizeof(c.path), path);
    c.ino = BPF_CORE_READ(file, f_inode, i_ino);

    __u64 key = (__u64)file;
    // BPF_ANY: an existing entry for this address is overwritten. That is the
    // correct behaviour if the address has been reused, and the experiment
    // measures whether stale entries survive long enough to be read.
    long rc = bpf_map_update_elem(&correlations, &key, &c, BPF_ANY);
    bump(rc == 0 ? S_INSERT_OK : S_INSERT_FAIL);

    return prev_ret;
}

SEC("lsm/file_permission")
int BPF_PROG(on_file_permission, struct file *file, int mask, int prev_ret)
{
    if (!(mask & MAY_WRITE))
        return prev_ret;

    __u64 key = (__u64)file;
    struct correlation *c = bpf_map_lookup_elem(&correlations, &key);
    if (!c) {
        // Consistent with A1b: no observed opening, so no WRITE(p) for any p.
        // Counted only for writes to files this experiment created, which is
        // established by the inode check below being unavailable - so instead
        // count all misses and let the analysis bound them by the workload.
        bump(S_LOOKUP_MISS);
        return prev_ret;
    }

    bump(S_WRITE_SEEN);

    __u64 actual = BPF_CORE_READ(file, f_inode, i_ino);
    if (c->ino == actual) {
        bump(S_LOOKUP_HIT_CORRECT);
        return prev_ret;
    }

    // The stored path was resolved for a different object than the one now being
    // written. Any WRITE(p) derived from this entry would name the wrong file.
    bump(S_LOOKUP_HIT_STALE);

    struct stale_report *r = bpf_ringbuf_reserve(&stale_events, sizeof(*r), 0);
    if (r) {
        r->stored_ino = c->ino;
        r->actual_ino = actual;
        bpf_probe_read_kernel_str(r->stored_path, sizeof(r->stored_path), c->path);
        // bpf_d_path is not permitted here, so the actual path cannot be
        // resolved at this hook; the inode is the evidence.
        r->actual_path[0] = '\0';
        bpf_ringbuf_submit(r, 0);
    }

    return prev_ret;
}

SEC("lsm/file_free_security")
int BPF_PROG(on_file_free, struct file *file)
{
    __u64 key = (__u64)file;
    struct correlation *c = bpf_map_lookup_elem(&correlations, &key);
    if (!c)
        return 0;

    bump(S_FREE_SEEN);
    long rc = bpf_map_delete_elem(&correlations, &key);
    bump(rc == 0 ? S_DELETE_OK : S_DELETE_MISS);
    return 0;
}
