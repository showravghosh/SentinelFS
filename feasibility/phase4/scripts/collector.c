// SPDX-License-Identifier: GPL-2.0
//
// Phase 4 experiment 2 collector: loads the observe-only mapping probe, attaches
// every hook in it, and streams the ring buffer to stdout as JSON lines.
//
// Per-hook call and unresolved counters are printed on exit. Those matter because
// the ring buffer only carries records that passed the path filter: without the
// counters, a hook that fires but cannot name its object is indistinguishable from
// a hook that never fires.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PATH_LEN 192
#define COMM_LEN 16

struct event {
    unsigned long long ts_ns;
    unsigned int hook;
    unsigned int pid;
    unsigned int tgid;
    int mask;
    unsigned int path_ok;
    char path[PATH_LEN];
    char comm[COMM_LEN];
};

static const char *hook_name(unsigned int id)
{
    switch (id) {
    case 1: return "bprm_check_security";
    case 2: return "bprm_creds_for_exec";
    case 3: return "file_open";
    case 4: return "file_permission";
    case 5: return "path_unlink";
    case 6: return "inode_unlink";
    case 7: return "path_truncate";
    default: return "unknown";
    }
}

static volatile sig_atomic_t stop;

static void on_signal(int sig) { (void)sig; stop = 1; }

static int quiet(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

// JSON string escaping. Paths come from the kernel and are not guaranteed to be
// free of characters that would break the output format.
static void print_escaped(const char *s, size_t max)
{
    for (size_t i = 0; i < max && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (c < 0x20)
                printf("\\u%04x", c);
            else
                putchar(c);
        }
    }
}

static int on_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len < sizeof(struct event))
        return 0;
    const struct event *e = data;

    printf("{\"rec\":\"event\",\"hook\":\"%s\",\"ts_ns\":%llu,\"pid\":%u,\"tgid\":%u,"
           "\"mask\":%d,\"path_ok\":%u,\"comm\":\"",
           hook_name(e->hook), e->ts_ns, e->pid, e->tgid, e->mask, e->path_ok);
    print_escaped(e->comm, COMM_LEN);
    printf("\",\"path\":\"");
    print_escaped(e->path, PATH_LEN);
    printf("\"}\n");
    fflush(stdout);
    return 0;
}

static void dump_counters(struct bpf_object *obj)
{
    const char *maps[] = { "hook_calls", "hook_unresolved" };

    for (int m = 0; m < 2; m++) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj, maps[m]);
        if (!map)
            continue;
        int fd = bpf_map__fd(map);

        printf("{\"rec\":\"counters\",\"map\":\"%s\",\"values\":{", maps[m]);
        int first = 1;
        for (unsigned int k = 1; k <= 7; k++) {
            unsigned long long v = 0;
            if (bpf_map_lookup_elem(fd, &k, &v) != 0)
                continue;
            printf("%s\"%s\":%llu", first ? "" : ",", hook_name(k), v);
            first = 0;
        }
        printf("}}\n");
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <mapping.bpf.o>\n", argv[0]);
        return 2;
    }

    libbpf_set_print(quiet);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "collector: open failed: %s\n", strerror(errno));
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "collector: load failed (verifier?): %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog;
    struct bpf_link *links[16];
    int n = 0;
    bpf_object__for_each_program(prog, obj) {
        if (n >= 16) break;
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            // A hook that cannot be attached is itself a result: it is reported and
            // the run continues, so one unavailable hook does not void the others.
            fprintf(stderr, "collector: could not attach %s: %s\n",
                    bpf_program__name(prog), strerror(errno));
            printf("{\"rec\":\"attach_failed\",\"program\":\"%s\",\"error\":\"%s\"}\n",
                   bpf_program__name(prog), strerror(errno));
            fflush(stdout);
            continue;
        }
        links[n++] = link;
        fprintf(stderr, "collector: attached %s\n", bpf_program__name(prog));
    }

    if (n == 0) {
        fprintf(stderr, "collector: nothing attached\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "events");
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map), on_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "collector: ring buffer failed\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("{\"rec\":\"ready\",\"attached\":%d}\n", n);
    fflush(stdout);

    while (!stop) {
        int err = ring_buffer__poll(rb, 200);
        if (err < 0 && err != -EINTR)
            break;
    }

    ring_buffer__consume(rb);
    dump_counters(obj);

    ring_buffer__free(rb);
    for (int i = 0; i < n; i++)
        bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    fprintf(stderr, "collector: detached\n");
    return 0;
}
