// SPDX-License-Identifier: GPL-2.0
//
// Phase 4C collector: streams the stability probe's ring buffer as JSON lines.
// Each record carries the resolved path, the dentry's own name, and the device,
// inode and link count of the object, so path identity and object identity can be
// compared directly.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PATH_LEN 200
#define COMM_LEN 16

struct event {
    unsigned long long ts_ns;
    unsigned long long ino;
    unsigned int dev_major;
    unsigned int dev_minor;
    unsigned int nlink;
    unsigned int pid;
    char resolved[PATH_LEN];
    char dentry_name[PATH_LEN];
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

    printf("{\"rec\":\"event\",\"ts_ns\":%llu,\"pid\":%u,\"ino\":%llu,"
           "\"dev_major\":%u,\"dev_minor\":%u,\"nlink\":%u,\"resolved\":\"",
           e->ts_ns, e->pid, e->ino, e->dev_major, e->dev_minor, e->nlink);
    escaped(e->resolved, PATH_LEN);
    printf("\",\"dentry_name\":\"");
    escaped(e->dentry_name, PATH_LEN);
    printf("\",\"comm\":\"");
    escaped(e->comm, COMM_LEN);
    printf("\"}\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <stability.bpf.o>\n", argv[0]);
        return 2;
    }

    libbpf_set_print(quiet);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "open failed: %s\n", strerror(errno));
        return 1;
    }
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
            printf("{\"rec\":\"attach_failed\",\"program\":\"%s\",\"error\":\"%s\"}\n",
                   bpf_program__name(prog), strerror(errno));
            fflush(stdout);
            continue;
        }
        links[n++] = link;
        fprintf(stderr, "attached %s\n", bpf_program__name(prog));
    }
    if (n == 0) {
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "events");
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map), on_event, NULL, NULL);
    if (!rb) {
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
    ring_buffer__free(rb);
    for (int i = 0; i < n; i++)
        bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return 0;
}
