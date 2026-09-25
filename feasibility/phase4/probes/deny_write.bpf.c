// SPDX-License-Identifier: GPL-2.0
//
// Phase 5B.0 step 4, arm 2: can the adopted WRITE hook prevent a write?
//
// This arm carries the strongest control requirement of the three, because the
// obvious mistake would produce a convincing but worthless result.
//
// Phase 4 experiment 1 denied lsm/file_open with FMODE_WRITE and observed that
// the file was unchanged. That is evidence about OPEN, not about WRITE: Phase 4
// section 2 established that file_open denotes intent rather than the operation
// and cannot implement WRITE(path). If this arm denied at open time, the file
// would again be unchanged and nothing about write-time enforcement would have
// been measured.
//
// So lsm/file_open here is OBSERVE-ONLY. It records the correlation that A1b
// requires -- struct file * to resolved path -- and never refuses. The open is
// allowed to succeed. Denial happens only at lsm/file_permission with MAY_WRITE,
// which Phase 4 measured as firing once per write, silent when a file is opened
// for writing and never written, and silent on read-only access.
//
// The correlation is necessary rather than convenient: bpf_d_path is forbidden
// on file_permission, so the path cannot be resolved at the point of decision
// and must come from the opening. That is the same structure A1b describes, and
// it means this arm also exercises whether enforcement can act on a path it
// learned earlier rather than one it can see now.
//
// The inode is stored alongside the path and rechecked at write time. A hash
// keyed by struct file * can return a stale entry if the pointer is reused, and
// a stale hit would mean refusing a write to the wrong object. Refusing on a
// mismatched inode would be a soundness failure, so a mismatch does not deny.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 128  // 256 overflows the 512-byte BPF stack alongside struct correlation
#define EPERM 1
#define MAY_WRITE 0x2

#define PROTECTED "/tmp/sentinel-p7/write/protected"
#define PROTECTED_LEN 32

#define WATCH "/tmp/sentinel-p7/write/"
#define WATCH_LEN 23

enum {
    S_OPEN_CALLS = 0,
    S_CORRELATED = 1,
    S_PERM_CALLS = 2,
    S_WRITE_CALLS = 3,
    S_LOOKUP_HIT = 4,
    S_LOOKUP_MISS = 5,
    S_STALE = 6,
    S_TARGET_SEEN = 7,
    S_DENIED = 8,
    S_ARMED_CALLS = 9,
    S_NR = 16,
};

struct correlation {
    char path[PATH_LEN];
    __u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64); // struct file *
    __type(value, struct correlation);
} correlations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, S_NR);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} control SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[PATH_LEN]);
} last_denied SEC(".maps");

static __always_inline void bump(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline int armed(void)
{
    __u32 k = 0;
    __u32 *v = bpf_map_lookup_elem(&control, &k);
    return v && *v;
}

static __always_inline int has_prefix(const char *path, const char *want, int n)
{
#pragma unroll
    for (int i = 0; i < PATH_LEN; i++) {
        if (i >= n)
            return 1;
        if (path[i] != want[i])
            return 0;
    }
    return 1;
}

static __always_inline int is_watched(const char *p)
{
    const char want[] = WATCH;
    return has_prefix(p, want, WATCH_LEN);
}

static __always_inline int is_protected(const char *p)
{
    const char want[] = PROTECTED;
    return has_prefix(p, want, PROTECTED_LEN);
}

// OBSERVE-ONLY. Records provenance and never refuses, so that any refusal
// measured by this arm is attributable to the write and not to the open.
SEC("lsm/file_open")
int BPF_PROG(sentinel_open, struct file *file, int prev_ret)
{
    if (prev_ret != 0)
        return prev_ret;

    bump(S_OPEN_CALLS);

    char path[PATH_LEN] = {};
    long len = bpf_d_path(&file->f_path, path, sizeof(path));
    if (len < 0)
        return 0;

    if (!is_watched(path))
        return 0;

    struct correlation c = {};
    __builtin_memcpy(c.path, path, PATH_LEN);
    c.ino = BPF_CORE_READ(file, f_inode, i_ino);

    __u64 key = (__u64)file;
    if (bpf_map_update_elem(&correlations, &key, &c, BPF_ANY) == 0)
        bump(S_CORRELATED);

    return 0; // never denies
}

SEC("lsm/file_permission")
int BPF_PROG(sentinel_perm, struct file *file, int mask, int prev_ret)
{
    if (prev_ret != 0)
        return prev_ret;

    bump(S_PERM_CALLS);

    if (!(mask & MAY_WRITE))
        return 0;
    bump(S_WRITE_CALLS);

    if (!armed())
        return 0;
    bump(S_ARMED_CALLS);

    __u64 key = (__u64)file;
    struct correlation *c = bpf_map_lookup_elem(&correlations, &key);
    if (!c) {
        // No observed opening: under A1b this is not a WRITE(p) for any p, so
        // there is nothing to decide against. Allow.
        bump(S_LOOKUP_MISS);
        return 0;
    }

    // Guard against pointer reuse returning another file's path. Refusing on a
    // stale entry would deny a write to an object the policy never named.
    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    if (ino != c->ino) {
        bump(S_STALE);
        return 0;
    }
    bump(S_LOOKUP_HIT);

    if (!is_protected(c->path))
        return 0;

    bump(S_TARGET_SEEN);
    bump(S_DENIED);

    __u32 k = 0;
    char *slot = bpf_map_lookup_elem(&last_denied, &k);
    if (slot)
        __builtin_memcpy(slot, c->path, PATH_LEN);

    return -EPERM;
}

SEC("lsm/file_free_security")
int BPF_PROG(sentinel_free, struct file *file)
{
    __u64 key = (__u64)file;
    bpf_map_delete_elem(&correlations, &key);
    return 0;
}
