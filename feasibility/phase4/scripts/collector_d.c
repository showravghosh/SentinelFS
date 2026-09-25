// SPDX-License-Identifier: GPL-2.0
//
// Phase 5A-E1 collector. Streams the ordering probe's ring buffer as JSON lines,
// in delivery order. The position of a record in this output IS the measurement:
// it is the order a userspace automaton would apply transitions in, to be
// compared against the `seq` field, which is the order the kernel executed the
// hooks in.
//
// Nothing here sorts or reorders. Doing so would destroy the quantity being
// measured.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PATH_LEN 128
#define COMM_LEN 16

struct event {
    unsigned long long seq;
    unsigned long long ts_ns;
    unsigned int cpu;
    unsigned int pid;
    char path[PATH_LEN];
    char comm[COMM_LEN];
};

static volatile sig_atomic_t stop;
static void on_signal(int sig) { (void)sig; stop = 1; }

static int quiet(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static void escaped(const char *s, size_t max)
{
    for (size_t i = 0; i < max && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        default:
            if (c < 0x20) printf("\\u%04x", c); else putchar(c);
        }
    }
}

static int on_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len < sizeof(struct event))
        return 0;
    const struct event *e = data;

    printf("{\"rec\":\"event\",\"seq\":%llu,\"ts_ns\":%llu,\"cpu\":%u,\"pid\":%u,\"path\":\"",
           e->seq, e->ts_ns, e->cpu, e->pid);
    escaped(e->path, PATH_LEN);
    printf("\",\"comm\":\"");
    escaped(e->comm, COMM_LEN);
    printf("\"}\n");
    return 0;
}

static void dump_counters(struct bpf_object *obj)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "counters");
    if (!map) return;
    int fd = bpf_map__fd(map);
    const char *names[] = { "seq", "dropped" };

    printf("{\"rec\":\"counters\",\"values\":{");
    for (unsigned int k = 0; k < 2; k++) {
        unsigned long long v = 0;
        bpf_map_lookup_elem(fd, &k, &v);
        printf("%s\"%s\":%llu", k ? "," : "", names[k], v);
    }
    printf("}}\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <ordering.bpf.o>\n", argv[0]);
        return 2;
    }

    libbpf_set_print(quiet);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) { fprintf(stderr, "open failed: %s\n", strerror(errno)); return 1; }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog;
    struct bpf_link *links[4];
    int n = 0;
    bpf_object__for_each_program(prog, obj) {
        if (n >= 4) break;
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "attach failed: %s\n", strerror(errno));
            continue;
        }
        links[n++] = link;
    }
    if (n == 0) { bpf_object__close(obj); return 1; }

    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "events");
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map), on_event, NULL, NULL);
    if (!rb) { bpf_object__close(obj); return 1; }

    printf("{\"rec\":\"ready\",\"attached\":%d}\n", n);
    fflush(stdout);

    while (!stop) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) break;
    }

    ring_buffer__consume(rb);
    fflush(stdout);
    dump_counters(obj);

    ring_buffer__free(rb);
    for (int i = 0; i < n; i++) bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return 0;
}
