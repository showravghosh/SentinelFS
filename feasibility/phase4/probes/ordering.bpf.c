// SPDX-License-Identifier: GPL-2.0
//
// Phase 5A-E1: concurrent host-wide ordering.
//
// Assumption A2 asserts that events reach the evaluator in the order they
// occurred. Phase 2 tested that with a single-process workload, which cannot
// distinguish "order was preserved" from "there was only one order". The v1.1
// semantics define a single host-wide trace (§1.2), so under concurrency the
// question becomes: what IS the order, when events occur on different CPUs?
//
// Three orderings are captured for every event so they can be compared:
//
//   seq    an atomic counter incremented inside the hook. This is the order in
//          which the kernel actually executed the hook, and it is the order a
//          kernel-resident automaton would apply transitions in.
//   ts_ns  bpf_ktime_get_ns() at the same point.
//   (delivery) the position of the record in the collector's output, which is
//          the order a userspace automaton reading the ring buffer would see.
//
// The three need not agree. Which pairs agree determines which architectures can
// implement the specified semantics, so the measurement is taken before any
// architecture is chosen.
//
// OBSERVE-ONLY.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 128
#define COMM_LEN 16
#define PREFIX "/tmp/sentinel-p5"
#define PREFIX_LEN 16

struct event {
    __u64 seq;       // kernel hook execution order
    __u64 ts_ns;     // timestamp at the same point
    __u32 cpu;
    __u32 pid;
    char  path[PATH_LEN];
    char  comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// A single global counter, deliberately: contention on it is the same contention
// a single host-wide automaton state cell would experience, so the measurement
// exercises the structure the specification implies.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

#define C_SEQ     0
#define C_DROPPED 1

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

    // Claim a sequence number inside the hook. The atomic returns the previous
    // value, so each observed event receives a distinct number in the order the
    // kernel executed the hook, across all CPUs.
    __u32 k = C_SEQ;
    __u64 *ctr = bpf_map_lookup_elem(&counters, &k);
    if (!ctr)
        return prev_ret;
    __u64 seq = __sync_fetch_and_add(ctr, 1);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // The sequence number was already claimed, so a gap in seq identifies a
        // dropped record precisely rather than by inference.
        __u32 d = C_DROPPED;
        __u64 *dc = bpf_map_lookup_elem(&counters, &d);
        if (dc)
            __sync_fetch_and_add(dc, 1);
        return prev_ret;
    }

    e->seq = seq;
    e->ts_ns = bpf_ktime_get_ns();
    e->cpu = bpf_get_smp_processor_id();
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_probe_read_kernel_str(e->path, sizeof(e->path), path);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return prev_ret;
}
