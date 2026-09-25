// SPDX-License-Identifier: GPL-2.0
//
// Phase 4, experiment 2: do the candidate BPF LSM hooks faithfully implement the
// frozen v1 event alphabet?
//
// Experiment 1 established that a BPF LSM program can prevent an operation. It did
// so using lsm/file_open, which denies opening a file with write intent - and that
// is NOT the event the specification calls WRITE(path). This program exists to
// determine, per event type, which hook (if any) means what the specification says.
//
// It is deliberately OBSERVE-ONLY. Every hook returns the incoming verdict
// unchanged, so attaching it cannot deny anything. Enforcement per hook is tested
// separately, once the semantics are known: testing enforcement before knowing what
// an event means would be measuring the wrong thing.
//
// Multiple candidate hooks are attached per event type, so that their relative
// behaviour can be compared on the same workload rather than across runs.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 192
#define COMM_LEN 16
#define PREFIX "/tmp/sentinel-p4"
#define PREFIX_LEN 16

// Kernel constants. vmlinux.h is generated from BTF, which records types but not
// macros, so these are restated from the kernel headers they belong to.
#define FMODE_WRITE 0x2 // include/linux/fs.h
#define FMODE_READ  0x1
#define MAY_EXEC    0x1 // include/linux/fs.h
#define MAY_WRITE   0x2
#define MAY_READ    0x4
#define MAY_APPEND  0x20

// Which hook produced a record. Named for the hook, not for the SentinelFS event,
// because establishing that correspondence is the point of the experiment.
enum hook_id {
    HOOK_BPRM_CHECK_SECURITY = 1,
    HOOK_BPRM_CREDS_FOR_EXEC = 2,
    HOOK_FILE_OPEN           = 3,
    HOOK_FILE_PERMISSION     = 4,
    HOOK_PATH_UNLINK         = 5,
    HOOK_INODE_UNLINK        = 6,
    HOOK_PATH_TRUNCATE       = 7,
};

struct event {
    __u64 ts_ns;
    __u32 hook;
    __u32 pid;
    __u32 tgid;
    __s32 mask;      // file_permission mask, or file f_mode, where applicable
    __u32 path_ok;   // whether the object could be named
    char  path[PATH_LEN];
    char  comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

// Per-hook call counters, including calls whose object could not be named. The
// ring buffer only carries records that passed the path filter, so without these
// a hook that fires but cannot resolve a path would look like a hook that never
// fires - a distinction that matters for assumption A1b.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} hook_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} hook_unresolved SEC(".maps");

// bpf_d_path is rejected on lsm/file_permission: the kernel allows it only on
// hooks in the sleepable set, and file_permission, being on the read/write path,
// is not one. The only way to name the object in that hook is therefore to resolve
// the path where it IS permitted - at file_open - and carry it forward, keyed by
// the struct file the two hooks share.
//
// This is the same fd-correlation used in Phase 2, and it makes assumption A1b
// load-bearing at enforcement time rather than merely at observation time: a file
// whose open was not seen has no entry here, and cannot be named.
struct path_value {
    char path[PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // struct file *
    __type(value, struct path_value);
} file_paths SEC(".maps");

#define STAT_CORRELATION_HIT  8
#define STAT_CORRELATION_MISS 9

static __always_inline void count(void *map, __u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(map, &slot);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// Whether the path lies under the experiment's directory. Everything else on the
// host is ignored, which keeps the ring buffer bounded and the record free of
// unrelated activity.
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

static __always_inline void emit(__u32 hook, const char *path, __s32 mask, __u32 path_ok)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->hook = hook;
    e->pid = (__u32)id;
    e->tgid = (__u32)(id >> 32);
    e->mask = mask;
    e->path_ok = path_ok;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (path)
        bpf_probe_read_kernel_str(e->path, sizeof(e->path), path);
    else
        e->path[0] = '\0';

    bpf_ringbuf_submit(e, 0);
}

// --- EXEC candidates ----------------------------------------------------------

SEC("lsm/bprm_check_security")
int BPF_PROG(on_bprm_check_security, struct linux_binprm *bprm, int prev_ret)
{
    count(&hook_calls, HOOK_BPRM_CHECK_SECURITY);

    // bpf_d_path requires a trusted pointer. Reading bprm->file through
    // BPF_CORE_READ would compile to bpf_probe_read_kernel, whose result the
    // verifier treats as an untrusted scalar and rejects here. Dereferencing the
    // context argument directly keeps the pointer trusted.
    char path[PATH_LEN] = {};
    long len = bpf_d_path(&bprm->file->f_path, path, sizeof(path));
    if (len < 0) {
        count(&hook_unresolved, HOOK_BPRM_CHECK_SECURITY);
        return prev_ret;
    }

    emit(HOOK_BPRM_CHECK_SECURITY, path, 0, 1);
    return prev_ret;
}

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(on_bprm_creds_for_exec, struct linux_binprm *bprm, int prev_ret)
{
    count(&hook_calls, HOOK_BPRM_CREDS_FOR_EXEC);

    char path[PATH_LEN] = {};
    long len = bpf_d_path(&bprm->file->f_path, path, sizeof(path));
    if (len < 0) {
        count(&hook_unresolved, HOOK_BPRM_CREDS_FOR_EXEC);
        return prev_ret;
    }

    emit(HOOK_BPRM_CREDS_FOR_EXEC, path, 0, 1);
    return prev_ret;
}

// --- OPEN candidate -------------------------------------------------------------

SEC("lsm/file_open")
int BPF_PROG(on_file_open, struct file *file, int prev_ret)
{
    count(&hook_calls, HOOK_FILE_OPEN);

    char path[PATH_LEN] = {};
    long len = bpf_d_path(&file->f_path, path, sizeof(path));
    if (len < 0) {
        count(&hook_unresolved, HOOK_FILE_OPEN);
        return prev_ret;
    }
    if (!under_prefix(path))
        return prev_ret;

    // Carry the resolved path forward for file_permission, which cannot resolve
    // one itself. Only files under the experiment's prefix are recorded; a
    // policy-driven adapter would likewise track only objects its policies name,
    // rather than every file opened on the host.
    struct path_value pv = {};
    bpf_probe_read_kernel_str(pv.path, sizeof(pv.path), path);
    __u64 key = (__u64)file;
    bpf_map_update_elem(&file_paths, &key, &pv, BPF_ANY);

    // f_mode is carried so the analysis can tell an open-for-write from an
    // open-for-read. That distinction is what makes file_open a candidate for
    // WRITE at all, and what the experiment tests.
    __s32 f_mode = (__s32)BPF_CORE_READ(file, f_mode);
    emit(HOOK_FILE_OPEN, path, f_mode, 1);
    return prev_ret;
}

// --- WRITE candidate --------------------------------------------------------------

SEC("lsm/file_permission")
int BPF_PROG(on_file_permission, struct file *file, int mask, int prev_ret)
{
    count(&hook_calls, HOOK_FILE_PERMISSION);

    // bpf_d_path cannot be called here, so the path must come from the
    // correlation map populated at file_open. A miss means the object cannot be
    // named at this hook by any means available to it.
    __u64 key = (__u64)file;
    struct path_value *pv = bpf_map_lookup_elem(&file_paths, &key);
    if (!pv) {
        count(&hook_unresolved, HOOK_FILE_PERMISSION);
        count(&hook_calls, STAT_CORRELATION_MISS);
        return prev_ret;
    }

    count(&hook_calls, STAT_CORRELATION_HIT);
    emit(HOOK_FILE_PERMISSION, pv->path, mask, 1);
    return prev_ret;
}

// Release correlation entries when the kernel releases the file, so the map does
// not grow without bound. A real adapter needs this too.
SEC("lsm/file_free_security")
int BPF_PROG(on_file_free, struct file *file)
{
    __u64 key = (__u64)file;
    bpf_map_delete_elem(&file_paths, &key);
    return 0;
}

// --- DELETE candidates ---------------------------------------------------------------

// path_unlink is gated on CONFIG_SECURITY_PATH. It appears in BTF regardless, so
// whether it is actually invoked is something the experiment has to measure rather
// than infer from the symbol's presence.
SEC("lsm/path_unlink")
int BPF_PROG(on_path_unlink, const struct path *dir, struct dentry *dentry, int prev_ret)
{
    count(&hook_calls, HOOK_PATH_UNLINK);

    char dirpath[PATH_LEN] = {};
    long len = bpf_d_path((struct path *)dir, dirpath, sizeof(dirpath));
    if (len < 0) {
        count(&hook_unresolved, HOOK_PATH_UNLINK);
        return prev_ret;
    }
    if (!under_prefix(dirpath))
        return prev_ret;

    // The victim's own name lives on the dentry; the hook gives the directory, not
    // the full path of the file being removed. Whether that is sufficient to name
    // the object is part of what is being measured.
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return prev_ret;

    __u64 id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->hook = HOOK_PATH_UNLINK;
    e->pid = (__u32)id;
    e->tgid = (__u32)(id >> 32);
    e->mask = 0;
    e->path_ok = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(e->path, sizeof(e->path), name);

    bpf_ringbuf_submit(e, 0);
    return prev_ret;
}

SEC("lsm/inode_unlink")
int BPF_PROG(on_inode_unlink, struct inode *dir, struct dentry *dentry, int prev_ret)
{
    count(&hook_calls, HOOK_INODE_UNLINK);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return prev_ret;

    __u64 id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->hook = HOOK_INODE_UNLINK;
    e->pid = (__u32)id;
    e->tgid = (__u32)(id >> 32);
    e->mask = 0;
    e->path_ok = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // inode_unlink receives no struct path at all, so there is nothing for
    // bpf_d_path to resolve: only the dentry name is available.
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(e->path, sizeof(e->path), name);

    bpf_ringbuf_submit(e, 0);
    return prev_ret;
}

// Truncation empties a file without unlinking it. Whether that is a DELETE, a
// WRITE, or neither under the frozen semantics is a question the findings must
// answer; the hook is observed here so the answer rests on evidence.
SEC("lsm/path_truncate")
int BPF_PROG(on_path_truncate, const struct path *path, int prev_ret)
{
    count(&hook_calls, HOOK_PATH_TRUNCATE);

    char p[PATH_LEN] = {};
    long len = bpf_d_path((struct path *)path, p, sizeof(p));
    if (len < 0) {
        count(&hook_unresolved, HOOK_PATH_TRUNCATE);
        return prev_ret;
    }
    if (!under_prefix(p))
        return prev_ret;

    emit(HOOK_PATH_TRUNCATE, p, 0, 1);
    return prev_ret;
}
