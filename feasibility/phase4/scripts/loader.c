// SPDX-License-Identifier: GPL-2.0
//
// Phase 4 probe loader.
//
// Loads a BPF LSM object, attaches its programs, reports readiness on stdout, and
// holds the links open until interrupted. Holding the link is the point: a BPF LSM
// program is only in force while something keeps its link alive, so the harness
// starts this, runs the test operations, and then stops it.
//
// On exit it prints the probe's counters, which lets the experiment distinguish
// "the hook never fired" from "the hook fired and allowed the operation" - a
// distinction that matters, because a test that produces no denial could mean
// either.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static int quiet_libbpf(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static const char *stat_names[] = {
    "hook_calls", "path_resolved", "target_seen", "denied",
};
#define STAT_COUNT ((int)(sizeof(stat_names) / sizeof(stat_names[0])))

static void dump_stats(struct bpf_object *obj)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "stats");
    if (!map) {
        fprintf(stderr, "loader: no stats map\n");
        return;
    }
    int fd = bpf_map__fd(map);

    printf("{\"stats\":{");
    for (int i = 0; i < STAT_COUNT; i++) {
        __u32 key = i;
        __u64 value = 0;
        if (bpf_map_lookup_elem(fd, &key, &value) != 0)
            value = 0;
        printf("%s\"%s\":%llu", i ? "," : "", stat_names[i], (unsigned long long)value);
    }
    printf("}}\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <probe.bpf.o>\n", argv[0]);
        return 2;
    }

    libbpf_set_print(quiet_libbpf);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "loader: failed to open %s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "loader: failed to load (verifier rejected?): %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    // Attach every program in the object and keep the links.
    struct bpf_program *prog;
    struct bpf_link *links[16];
    int n_links = 0;

    bpf_object__for_each_program(prog, obj) {
        if (n_links >= (int)(sizeof(links) / sizeof(links[0]))) {
            fprintf(stderr, "loader: too many programs\n");
            break;
        }
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "loader: failed to attach %s: %s\n",
                    bpf_program__name(prog), strerror(errno));
            for (int i = 0; i < n_links; i++)
                bpf_link__destroy(links[i]);
            bpf_object__close(obj);
            return 1;
        }
        links[n_links++] = link;
        fprintf(stderr, "loader: attached %s (%s)\n",
                bpf_program__name(prog), bpf_program__section_name(prog));
    }

    if (n_links == 0) {
        fprintf(stderr, "loader: no programs attached\n");
        bpf_object__close(obj);
        return 1;
    }

    // Readiness is reported on stdout so the harness can wait for it rather than
    // sleeping and hoping.
    printf("READY\n");
    fflush(stdout);

    while (!stop)
        pause();

    dump_stats(obj);

    for (int i = 0; i < n_links; i++)
        bpf_link__destroy(links[i]);
    bpf_object__close(obj);

    fprintf(stderr, "loader: detached\n");
    return 0;
}
