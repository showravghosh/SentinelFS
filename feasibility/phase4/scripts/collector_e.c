// SPDX-License-Identifier: GPL-2.0
//
// Phase 5A-E3 collector. Streams stale-correlation reports as they occur and
// dumps the counter set on exit.
//
// A stale report is the finding this experiment exists to detect: a write whose
// correlation entry was established for a different object. Each is emitted in
// full rather than only counted, so a soundness failure can be examined.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PATH_LEN 128

struct stale_report {
    unsigned long long stored_ino;
    unsigned long long actual_ino;
    char stored_path[PATH_LEN];
    char actual_path[PATH_LEN];
};

static const char *stat_names[] = {
    "open_seen", "insert_ok", "insert_fail", "write_seen",
    "lookup_hit_correct", "lookup_hit_stale", "lookup_miss",
    "free_seen", "delete_ok", "delete_miss",
};
#define STAT_COUNT ((int)(sizeof(stat_names) / sizeof(stat_names[0])))

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

static int on_stale(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len < sizeof(struct stale_report))
        return 0;
    const struct stale_report *r = data;

    printf("{\"rec\":\"stale\",\"stored_ino\":%llu,\"actual_ino\":%llu,\"stored_path\":\"",
           r->stored_ino, r->actual_ino);
    escaped(r->stored_path, PATH_LEN);
    printf("\",\"actual_path\":\"");
    escaped(r->actual_path, PATH_LEN);
    printf("\"}\n");
    fflush(stdout);
    return 0;
}

static void dump_stats(struct bpf_object *obj)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "stats");
    if (!map) return;
    int fd = bpf_map__fd(map);

    printf("{\"rec\":\"stats\",\"values\":{");
    for (int i = 0; i < STAT_COUNT; i++) {
        unsigned int k = i;
        unsigned long long v = 0;
        bpf_map_lookup_elem(fd, &k, &v);
        printf("%s\"%s\":%llu", i ? "," : "", stat_names[i], v);
    }
    printf("}}\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <correlation.bpf.o>\n", argv[0]);
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
    struct bpf_link *links[8];
    int n = 0;
    bpf_object__for_each_program(prog, obj) {
        if (n >= 8) break;
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "attach failed for %s: %s\n",
                    bpf_program__name(prog), strerror(errno));
            continue;
        }
        links[n++] = link;
        fprintf(stderr, "attached %s\n", bpf_program__name(prog));
    }
    if (n == 0) { bpf_object__close(obj); return 1; }

    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "stale_events");
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map), on_stale, NULL, NULL);
    if (!rb) { bpf_object__close(obj); return 1; }

    printf("{\"rec\":\"ready\",\"attached\":%d}\n", n);
    fflush(stdout);

    while (!stop) {
        int err = ring_buffer__poll(rb, 150);
        if (err < 0 && err != -EINTR) break;
    }

    ring_buffer__consume(rb);
    dump_stats(obj);

    ring_buffer__free(rb);
    for (int i = 0; i < n; i++) bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return 0;
}
