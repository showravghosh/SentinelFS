// SPDX-License-Identifier: GPL-2.0
//
// Phase 4C: is resolved-path identity stable?
//
// The event-identity analysis recommends defining every event on the resolved
// filesystem path. That recommendation rests on resolved paths naming the object
// rather than the route taken to it. Symlinks were shown to resolve; hard links,
// bind mounts and mount namespaces were not tested, and a hard link has no
// canonical path at all.
//
// This probe reports, for every open under the test prefix: the path d_path
// resolves to, the dentry's own name, and the device and inode number of the
// object. The inode is what settles the question - it says whether two paths
// denote the same object, independently of what either path looks like.
//
// OBSERVE-ONLY.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 200
#define COMM_LEN 16
#define PREFIX "/tmp/sentinel-p4c"
#define PREFIX_LEN 17

struct event {
    __u64 ts_ns;
    __u64 ino;        // object identity, independent of any path
    __u32 dev_major;
    __u32 dev_minor;
    __u32 nlink;      // more than one means the object has several names
    __u32 pid;
    char  resolved[PATH_LEN];
    char  dentry_name[PATH_LEN];
    char  comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

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
    char resolved[PATH_LEN] = {};
    long len = bpf_d_path(&file->f_path, resolved, sizeof(resolved));
    if (len < 0 || !under_prefix(resolved))
        return prev_ret;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return prev_ret;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(e->resolved, sizeof(e->resolved), resolved);

    // The dentry's own name: for a hard link this is the link's name, which may
    // differ from any other name the same object carries.
    const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(e->dentry_name, sizeof(e->dentry_name), name);
    else
        e->dentry_name[0] = '\0';

    // Object identity. Two records with the same (dev, ino) refer to the same
    // file however their paths differ; two with different ino are different
    // objects however their paths agree.
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    e->ino = BPF_CORE_READ(inode, i_ino);
    e->nlink = BPF_CORE_READ(inode, i_nlink);
    __u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    e->dev_major = dev >> 20;
    e->dev_minor = dev & 0xfffff;

    bpf_ringbuf_submit(e, 0);
    return prev_ret;
}
