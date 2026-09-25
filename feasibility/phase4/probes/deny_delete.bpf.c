// SPDX-License-Identifier: GPL-2.0
//
// Phase 5B.0 step 4, arm 3: can the adopted DELETE hooks prevent a directory
// entry from being removed?
//
// Phase 4 inferred a DELETE enforcement bypass from unlink-only instrumentation
// and was wrong; Phase 4B retracted it after establishing that the rename hooks
// cover the case. That retraction is why all three mechanisms are exercised here
// rather than unlink alone -- an arm that tested only unlink could report
// success while rename-over remained unprotected.
//
// DELETE(p) means "the name p is removed", not "the object at p is destroyed"
// (phase4b-findings.md section 2.2). The post-condition measured is therefore
// the presence of the directory entry, not the survival of the inode.
//
// Path composition: these hooks receive a directory path and a dentry rather
// than a resolved file, so the name is compared in two parts -- bpf_d_path on
// the directory, and the dentry's own name. That is the structure Phase 4B
// recorded for DELETE.
//
// rename is checked on both sides. A rename whose SOURCE is protected removes
// the protected name; a rename whose DESTINATION is protected removes the
// protected name by overwriting it. RENAME_EXCHANGE removes neither name but
// rebinds both, and is recorded separately rather than being assumed to belong
// on one side or the other.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 256
#define NAME_LEN 64
#define EPERM 1

#define WATCH_DIR "/tmp/sentinel-p7/delete"
#define WATCH_DIR_LEN 23

#define PROTECTED_NAME "protected"
#define PROTECTED_NAME_LEN 9

#define RENAME_EXCHANGE 2

enum {
    S_UNLINK_CALLS = 0,
    S_RMDIR_CALLS = 1,
    S_RENAME_CALLS = 2,
    S_DENIED_UNLINK = 3,
    S_DENIED_RMDIR = 4,
    S_DENIED_RENAME_SRC = 5,
    S_DENIED_RENAME_DST = 6,
    S_EXCHANGE_SEEN = 7,
    S_ARMED_CALLS = 8,
    S_NR = 16,
};

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
    __type(value, char[NAME_LEN]);
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

static __always_inline int dir_is_watched(const struct path *dir)
{
    char path[PATH_LEN] = {};
    const char want[] = WATCH_DIR;

    long len = bpf_d_path((struct path *)dir, path, sizeof(path));
    if (len < 0)
        return 0;

#pragma unroll
    for (int i = 0; i < WATCH_DIR_LEN; i++) {
        if (path[i] != want[i])
            return 0;
    }
    // Exact directory, not a prefix: /tmp/sentinel-p7/delete-other must not match.
    return path[WATCH_DIR_LEN] == '\0';
}

static __always_inline int name_is_protected(struct dentry *dentry, char *out)
{
    const char want[] = PROTECTED_NAME;
    const unsigned char *raw = BPF_CORE_READ(dentry, d_name.name);

    if (!raw)
        return 0;
    if (bpf_probe_read_kernel_str(out, NAME_LEN, raw) < 0)
        return 0;

#pragma unroll
    for (int i = 0; i < PROTECTED_NAME_LEN; i++) {
        if (out[i] != want[i])
            return 0;
    }
    return 1;
}

static __always_inline void record(const char *name)
{
    __u32 k = 0;
    char *slot = bpf_map_lookup_elem(&last_denied, &k);
    if (slot)
        __builtin_memcpy(slot, name, NAME_LEN);
}

SEC("lsm/path_unlink")
int BPF_PROG(sentinel_unlink, const struct path *dir, struct dentry *dentry,
             int prev_ret)
{
    if (prev_ret != 0)
        return prev_ret;

    bump(S_UNLINK_CALLS);
    if (!armed())
        return 0;
    bump(S_ARMED_CALLS);

    if (!dir_is_watched(dir))
        return 0;

    char name[NAME_LEN] = {};
    if (!name_is_protected(dentry, name))
        return 0;

    bump(S_DENIED_UNLINK);
    record(name);
    return -EPERM;
}

SEC("lsm/path_rmdir")
int BPF_PROG(sentinel_rmdir, const struct path *dir, struct dentry *dentry,
             int prev_ret)
{
    if (prev_ret != 0)
        return prev_ret;

    bump(S_RMDIR_CALLS);
    if (!armed())
        return 0;
    bump(S_ARMED_CALLS);

    if (!dir_is_watched(dir))
        return 0;

    char name[NAME_LEN] = {};
    if (!name_is_protected(dentry, name))
        return 0;

    bump(S_DENIED_RMDIR);
    record(name);
    return -EPERM;
}

SEC("lsm/path_rename")
int BPF_PROG(sentinel_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags, int prev_ret)
{
    if (prev_ret != 0)
        return prev_ret;

    bump(S_RENAME_CALLS);
    if (!armed())
        return 0;
    bump(S_ARMED_CALLS);

    if (flags & RENAME_EXCHANGE)
        bump(S_EXCHANGE_SEEN);

    char name[NAME_LEN] = {};

    // Source protected: the rename removes the protected name.
    if (dir_is_watched(old_dir) && name_is_protected(old_dentry, name)) {
        bump(S_DENIED_RENAME_SRC);
        record(name);
        return -EPERM;
    }

    // Destination protected: the rename removes the protected name by
    // overwriting it. Phase 4B established this is the case an unlink-only
    // instrumentation misses.
    char dname[NAME_LEN] = {};
    if (dir_is_watched(new_dir) && name_is_protected(new_dentry, dname)) {
        bump(S_DENIED_RENAME_DST);
        record(dname);
        return -EPERM;
    }

    return 0;
}
