// SPDX-License-Identifier: GPL-2.0
//
// Phase 4B: event identity and coverage.
//
// Phase 4 found that lsm/bprm_check_security reports the RESOLVED executable path
// while the Phase 2 tracepoint reported the pathname passed to execve. The two
// disagree, and the specification does not say which one EXEC(p) means.
//
// The question this probe answers is narrower and decidable: can the enforcement
// hook recover the pathname argument itself, rather than only the resolved object?
// struct linux_binprm carries filename, interp and fdpath in addition to the
// resolved file, so all four are captured side by side on the same execution and
// compared, instead of choosing between them in advance.
//
// It also attaches every deletion-related hook the kernel exposes, because Phase 4
// established that unlink hooks miss rename-over-existing and rmdir. Whether
// DELETE(p) is implementable at all depends on what the full set covers.
//
// OBSERVE-ONLY. Every hook returns the incoming verdict unchanged.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 160
#define COMM_LEN 16
#define PREFIX "/tmp/sentinel-p4b"
#define PREFIX_LEN 17

enum hook_id {
    H_BPRM_CHECK   = 1,
    H_FILE_OPEN    = 2,
    H_PATH_UNLINK  = 3,
    H_INODE_UNLINK = 4,
    H_PATH_RMDIR   = 5,
    H_INODE_RMDIR  = 6,
    H_PATH_RENAME  = 7,
    H_INODE_RENAME = 8,
};

// Two path fields, so a hook that exposes more than one notion of the object can
// report both and let the analysis compare them rather than pick one.
struct event {
    __u64 ts_ns;
    __u32 hook;
    __u32 pid;
    __u32 tgid;
    __u32 flags;        // rename flags, or destination-exists for rename
    __u32 dest_exists;  // whether a rename destination was occupied
    char  primary[PATH_LEN];    // as-passed pathname, or the object's name
    char  secondary[PATH_LEN];  // resolved path, or the rename destination
    char  interp[PATH_LEN];     // script interpreter, where applicable
    char  comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} hook_calls SEC(".maps");

static __always_inline void count(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&hook_calls, &slot);
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

static __always_inline struct event *new_event(__u32 hook)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;

    __u64 id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->hook = hook;
    e->pid = (__u32)id;
    e->tgid = (__u32)(id >> 32);
    e->flags = 0;
    e->dest_exists = 0;
    e->primary[0] = '\0';
    e->secondary[0] = '\0';
    e->interp[0] = '\0';
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

// --- EXEC: four notions of the same event, captured together ---------------------

SEC("lsm/bprm_check_security")
int BPF_PROG(on_bprm_check, struct linux_binprm *bprm, int prev_ret)
{
    count(H_BPRM_CHECK);

    // The resolved object path. bpf_d_path needs a trusted pointer, so the context
    // argument is dereferenced directly rather than read through a helper.
    char resolved[PATH_LEN] = {};
    long len = bpf_d_path(&bprm->file->f_path, resolved, sizeof(resolved));

    // The pathname as handed to execve. This is the value the frozen semantics
    // appear to intend, and the whole question is whether it survives to here.
    const char *fname = BPF_CORE_READ(bprm, filename);
    const char *interp = BPF_CORE_READ(bprm, interp);

    struct event *e = new_event(H_BPRM_CHECK);
    if (!e)
        return prev_ret;

    if (fname)
        bpf_probe_read_kernel_str(e->primary, sizeof(e->primary), fname);
    if (len >= 0)
        bpf_probe_read_kernel_str(e->secondary, sizeof(e->secondary), resolved);
    if (interp)
        bpf_probe_read_kernel_str(e->interp, sizeof(e->interp), interp);

    // interp_flags distinguishes the interpreter pass of a #! script from the
    // original request.
    e->flags = BPF_CORE_READ(bprm, interp_flags);

    bpf_ringbuf_submit(e, 0);
    return prev_ret;
}

// --- OPEN: does file_open report the path as opened, or the resolved object? -----

SEC("lsm/file_open")
int BPF_PROG(on_file_open, struct file *file, int prev_ret)
{
    count(H_FILE_OPEN);

    char resolved[PATH_LEN] = {};
    long len = bpf_d_path(&file->f_path, resolved, sizeof(resolved));
    if (len < 0 || !under_prefix(resolved))
        return prev_ret;

    struct event *e = new_event(H_FILE_OPEN);
    if (!e)
        return prev_ret;

    bpf_probe_read_kernel_str(e->secondary, sizeof(e->secondary), resolved);
    // The dentry's own name, for comparison against the resolved path: a symlink
    // and its target differ here.
    const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(e->primary, sizeof(e->primary), name);
    e->flags = (__u32)BPF_CORE_READ(file, f_mode);

    bpf_ringbuf_submit(e, 0);
    return prev_ret;
}

// --- DELETE: every hook by which an object can be removed -------------------------

static __always_inline void emit_dentry(__u32 hook, const struct path *dir,
                                        struct dentry *dentry)
{
    char dirpath[PATH_LEN] = {};
    if (dir) {
        long len = bpf_d_path((struct path *)dir, dirpath, sizeof(dirpath));
        if (len < 0 || !under_prefix(dirpath))
            return;
    }

    struct event *e = new_event(hook);
    if (!e)
        return;

    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(e->primary, sizeof(e->primary), name);
    if (dir)
        bpf_probe_read_kernel_str(e->secondary, sizeof(e->secondary), dirpath);

    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/path_unlink")
int BPF_PROG(on_path_unlink, const struct path *dir, struct dentry *dentry, int prev_ret)
{
    count(H_PATH_UNLINK);
    emit_dentry(H_PATH_UNLINK, dir, dentry);
    return prev_ret;
}

SEC("lsm/inode_unlink")
int BPF_PROG(on_inode_unlink, struct inode *dir, struct dentry *dentry, int prev_ret)
{
    count(H_INODE_UNLINK);
    // No struct path in this context, so no directory to resolve and no filter
    // possible: the object can only be named by its dentry.
    emit_dentry(H_INODE_UNLINK, NULL, dentry);
    return prev_ret;
}

SEC("lsm/path_rmdir")
int BPF_PROG(on_path_rmdir, const struct path *dir, struct dentry *dentry, int prev_ret)
{
    count(H_PATH_RMDIR);
    emit_dentry(H_PATH_RMDIR, dir, dentry);
    return prev_ret;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(on_inode_rmdir, struct inode *dir, struct dentry *dentry, int prev_ret)
{
    count(H_INODE_RMDIR);
    emit_dentry(H_INODE_RMDIR, NULL, dentry);
    return prev_ret;
}

// Rename is the case Phase 4 found uncovered: renaming over an existing file
// destroys it and produces no unlink event. Whether the destination was occupied
// is what distinguishes a destructive rename from a harmless one, so it is
// recorded explicitly.
SEC("lsm/path_rename")
int BPF_PROG(on_path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry,
             unsigned int flags, int prev_ret)
{
    count(H_PATH_RENAME);

    char dirpath[PATH_LEN] = {};
    long len = bpf_d_path((struct path *)new_dir, dirpath, sizeof(dirpath));
    if (len < 0 || !under_prefix(dirpath))
        return prev_ret;

    struct event *e = new_event(H_PATH_RENAME);
    if (!e)
        return prev_ret;

    const unsigned char *oldname = BPF_CORE_READ(old_dentry, d_name.name);
    const unsigned char *newname = BPF_CORE_READ(new_dentry, d_name.name);
    if (oldname)
        bpf_probe_read_kernel_str(e->primary, sizeof(e->primary), oldname);
    if (newname)
        bpf_probe_read_kernel_str(e->secondary, sizeof(e->secondary), newname);

    // A non-NULL inode on the destination dentry means the destination exists and
    // will be replaced: that is the destructive case.
    struct inode *dest = BPF_CORE_READ(new_dentry, d_inode);
    e->dest_exists = dest ? 1 : 0;
    e->flags = flags;

    bpf_ringbuf_submit(e, 0);
    return prev_ret;
}

SEC("lsm/inode_rename")
int BPF_PROG(on_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, int prev_ret)
{
    count(H_INODE_RENAME);

    struct event *e = new_event(H_INODE_RENAME);
    if (!e)
        return prev_ret;

    const unsigned char *oldname = BPF_CORE_READ(old_dentry, d_name.name);
    const unsigned char *newname = BPF_CORE_READ(new_dentry, d_name.name);
    if (oldname)
        bpf_probe_read_kernel_str(e->primary, sizeof(e->primary), oldname);
    if (newname)
        bpf_probe_read_kernel_str(e->secondary, sizeof(e->secondary), newname);

    struct inode *dest = BPF_CORE_READ(new_dentry, d_inode);
    e->dest_exists = dest ? 1 : 0;

    bpf_ringbuf_submit(e, 0);
    return prev_ret;
}
