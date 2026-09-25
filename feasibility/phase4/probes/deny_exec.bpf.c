// SPDX-License-Identifier: GPL-2.0
//
// Phase 5B.0 step 4, arm 1: can the adopted EXEC hook prevent execution?
//
// Phase 4 demonstrated pre-effect denial for lsm/file_open only. Whether the
// hook adopted for EXEC can refuse an execution before the new image runs was
// never measured, and phase4-findings.md section 7 records that as a limitation
// rather than a result. This arm measures it.
//
// The question is deliberately narrow. It is NOT whether the four execution
// variants produce identical observations -- Phase 4B already established they
// do not, and that finding stands. It is only whether returning a denial from
// this hook prevents the execution from taking effect.
//
// Matching is on the resolved path of the file being executed, taken by direct
// dereference of bprm->file->f_path. BPF_CORE_READ yields an untrusted scalar
// that bpf_d_path rejects; the direct dereference is what Phase 4 established
// works here. Resolution also makes the four variants comparable: a symlinked
// or relatively-named execution resolves to the same protected path, so one
// comparison covers all of them.
//
// The denial is gated on a map flag rather than on attachment. Setup must not
// fall inside the measurement interval (methodology rule M4): an earlier phase
// produced a phantom happens-before violation precisely because setup work was
// captured alongside the measurement. The loader attaches with the arm inert,
// performs setup, arms it, makes one attempt, and disarms it.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 256
#define EPERM 1

// Every execution whose resolved path begins with this prefix is refused while
// the arm is enabled. A control executable placed outside the prefix must
// still run, which distinguishes "denial works" from "everything is broken".
#define PROTECTED "/tmp/sentinel-p7/exec/protected"
#define PROTECTED_LEN 31

enum {
    S_HOOK_CALLS = 0,
    S_PATH_RESOLVED = 1,
    S_TARGET_SEEN = 2,
    S_DENIED = 3,
    S_ARMED_CALLS = 4,
    S_NR = 8,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, S_NR);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Index 0 holds the arm flag. Denial happens only when it is non-zero.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} control SEC(".maps");

// The resolved path of the most recent refusal, so the harness can confirm the
// denial applied to the file it meant to protect rather than to something else.
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

// Prefix comparison, not an exact match: the protected set is a family of names
// under one directory so that the ELF, script, symlink and relative-path cases
// can each have their own file while sharing one comparison.
static __always_inline int is_protected(const char *path)
{
    const char want[] = PROTECTED;

#pragma unroll
    for (int i = 0; i < PROTECTED_LEN; i++) {
        if (path[i] != want[i])
            return 0;
    }
    return 1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(sentinel_bprm, struct linux_binprm *bprm, int prev_ret)
{
    // Another LSM has already refused. Preserve that: this program may add
    // denials, never remove them.
    if (prev_ret != 0)
        return prev_ret;

    bump(S_HOOK_CALLS);

    if (!armed())
        return 0;

    bump(S_ARMED_CALLS);

    char path[PATH_LEN] = {};
    long len = bpf_d_path(&bprm->file->f_path, path, sizeof(path));
    if (len < 0)
        return 0; // cannot name the object: allow, and record nothing
    bump(S_PATH_RESOLVED);

    if (!is_protected(path))
        return 0;

    bump(S_TARGET_SEEN);
    bump(S_DENIED);

    __u32 k = 0;
    char *slot = bpf_map_lookup_elem(&last_denied, &k);
    if (slot)
        __builtin_memcpy(slot, path, PATH_LEN);

    return -EPERM;
}
