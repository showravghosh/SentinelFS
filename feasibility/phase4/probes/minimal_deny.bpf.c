// SPDX-License-Identifier: GPL-2.0
//
// Phase 4, experiment 1: the minimal enforcement proof.
//
// Question: can a BPF LSM program prevent an operation, as opposed to observing
// it after the fact? Phase 2 used tracepoints, which fire after the operation has
// happened and therefore cannot enforce anything.
//
// This program attaches to the pre-open security hook and denies opening one
// specific path for writing. It is deliberately the smallest thing that could
// demonstrate enforcement: no automaton, no policy, no state. If this does not
// work, nothing built on top of it can.
//
// Scope: the target path is fixed and compared in full. No other file is affected.
// An LSM program that denies broadly can make a machine unusable, so the
// comparison is exact and the failure mode is to allow.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TARGET_PATH "/tmp/sentinel-test"
#define TARGET_LEN 18 // strlen(TARGET_PATH)
#define PATH_MAX_LEN 256

// vmlinux.h is generated from BTF, which records types but not macros, so kernel
// constants used here are restated. Both are stable parts of the kernel ABI.
#define FMODE_WRITE 0x2 // include/linux/fs.h
#define EPERM 1         // include/uapi/asm-generic/errno-base.h

// Counters, read by the loader so the experiment can distinguish "the hook never
// fired" from "the hook fired and allowed".
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_HOOK_CALLS   0
#define STAT_PATH_RESOLVED 1
#define STAT_TARGET_SEEN  2
#define STAT_DENIED       3

static __always_inline void bump(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &slot);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// Whether the resolved path is exactly the target. Exact comparison, not a
// prefix: a prefix match would also catch /tmp/sentinel-test-other.
static __always_inline int is_target(const char *path)
{
    const char target[] = TARGET_PATH;

#pragma unroll
    for (int i = 0; i < TARGET_LEN; i++) {
        if (path[i] != target[i])
            return 0;
    }
    return path[TARGET_LEN] == '\0';
}

SEC("lsm/file_open")
int BPF_PROG(sentinel_file_open, struct file *file, int prev_ret)
{
    // Another LSM has already decided to deny. Preserve that decision: this
    // program may add denials, never remove them.
    if (prev_ret != 0)
        return prev_ret;

    bump(STAT_HOOK_CALLS);

    // Only writes are of interest for this experiment.
    unsigned int f_mode = BPF_CORE_READ(file, f_mode);
    if (!(f_mode & FMODE_WRITE))
        return 0;

    char path[PATH_MAX_LEN] = {};
    long len = bpf_d_path(&file->f_path, path, sizeof(path));
    if (len < 0)
        return 0; // cannot name the object: allow, and record nothing
    bump(STAT_PATH_RESOLVED);

    if (!is_target(path))
        return 0;

    bump(STAT_TARGET_SEEN);
    bump(STAT_DENIED);

    bpf_printk("sentinelfs: denying write open of %s", path);
    return -EPERM;
}
