// SPDX-License-Identifier: GPL-2.0
//
// Phase 4B collector: loads the identity probe and streams its ring buffer as
// JSON lines. Each record carries two notions of the object plus an interpreter
// field, so the analysis can compare them rather than being handed one.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PATH_LEN 160
#define COMM_LEN 16

struct event {
    unsigned long long ts_ns;
    unsigned int hook;
    unsigned int pid;
    unsigned int tgid;
    unsigned int flags;
    unsigned int dest_exists;
    char primary[PATH_LEN];
    char secondary[PATH_LEN];
    char interp[PATH_LEN];
    char comm[COMM_LEN];
};

static const char *hook_name(unsigned int id)
{
    switch (id) {
    case 1: return "bprm_check_security";
    case 2: return "file_open";
    case 3: return "path_unlink";
    case 4: return "inode_unlink";
    case 5: return "path_rmdir";
    case 6: return "inode_rmdir";
    case 7: return "path_rename";
    case 8: return "inode_rename";
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

static void escaped(const char *s, size_t max)
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

    printf("{\"rec\":\"event\",\"hook\":\"%s\",\"ts_ns\":%llu,\"pid\":%u,\"tgid\":%u,"
           "\"flags\":%u,\"dest_exists\":%u,\"primary\":\"",
           hook_name(e->hook), e->ts_ns, e->pid, e->tgid, e->flags, e->dest_exists);
    escaped(e->primary, PATH_LEN);
    printf("\",\"secondary\":\"");
    escaped(e->secondary, PATH_LEN);
    printf("\",\"interp\":\"");
    escaped(e->interp, PATH_LEN);
    printf("\",\"comm\":\"");
    escaped(e->comm, COMM_LEN);
    printf("\"}\n");
    fflush(stdout);
    return 0;
}

static void dump_counters(struct bpf_object *obj)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "hook_calls");
    if (!map) return;
    int fd = bpf_map__fd(map);

    printf("{\"rec\":\"counters\",\"values\":{");
    int first = 1;
    for (unsigned int k = 1; k <= 8; k++) {
        unsigned long long v = 0;
        if (bpf_map_lookup_elem(fd, &k, &v) != 0) continue;
        printf("%s\"%s\":%llu", first ? "" : ",", hook_name(k), v);
        first = 0;
    }
    printf("}}\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <identity.bpf.o>\n", argv[0]);
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
    struct bpf_link *links[16];
    int n = 0;
    bpf_object__for_each_program(prog, obj) {
        if (n >= 16) break;
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            // A hook that will not attach is a result in itself, so it is reported
            // and the run continues with the rest.
            printf("{\"rec\":\"attach_failed\",\"program\":\"%s\",\"error\":\"%s\"}\n",
                   bpf_program__name(prog), strerror(errno));
            fflush(stdout);
            continue;
        }
        links[n++] = link;
        fprintf(stderr, "attached %s\n", bpf_program__name(prog));
    }
    if (n == 0) { bpf_object__close(obj); return 1; }

    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "events");
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map), on_event, NULL, NULL);
    if (!rb) { bpf_object__close(obj); return 1; }

    printf("{\"rec\":\"ready\",\"attached\":%d}\n", n);
    fflush(stdout);

    while (!stop) {
        int err = ring_buffer__poll(rb, 200);
        if (err < 0 && err != -EINTR) break;
    }

    ring_buffer__consume(rb);
    dump_counters(obj);

    ring_buffer__free(rb);
    for (int i = 0; i < n; i++) bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return 0;
}
