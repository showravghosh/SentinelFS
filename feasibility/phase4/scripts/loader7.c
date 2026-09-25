// SPDX-License-Identifier: GPL-2.0
//
// Phase 5B.0 step 4 loader.
//
// The Phase 4 loader attaches a probe and holds its links until interrupted,
// which is sufficient when a probe is in force for its whole lifetime. This
// step needs finer control: the probe must be attached while setup happens but
// must not refuse anything until the measurement interval begins.
//
// Methodology rule M4 exists because setup work previously fell inside a
// measurement interval and produced a phantom result. Detaching and reattaching
// around setup would not solve it -- attachment itself perturbs the system, and
// the reattach would sit inside the interval. Instead the probe is attached
// once, inert, and a control map is flipped to arm it.
//
// Commands are read from stdin, one per line:
//
//   arm      set control[0] = 1   (denial active)
//   disarm   set control[0] = 0   (probe attached, refuses nothing)
//   stats    print counters and the last refused name
//   quit     detach and exit
//
// Each command is acknowledged on stdout so the harness can synchronise rather
// than sleep. That matters: a sleep-based harness would either slow the run or
// race the arming, and a race here would silently attribute an unarmed call to
// the measurement interval.

#include <bpf/libbpf.h>
#include <stdarg.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_LINKS 16
#define NAME_MAX_LEN 256

static int quiet_log(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static int set_control(int fd, unsigned int value)
{
    unsigned int key = 0;
    return bpf_map_update_elem(fd, &key, &value, BPF_ANY);
}

static void print_stats(struct bpf_object *obj, int stats_fd, int denied_fd)
{
    // Counter names are carried in the probe's own enum; the loader does not
    // know them, so indices are printed and the harness maps them. Keeping the
    // naming in one place avoids the two drifting apart.
    printf("STATS");
    for (unsigned int k = 0; k < 16; k++) {
        unsigned long long v = 0;
        if (bpf_map_lookup_elem(stats_fd, &k, &v) == 0)
            printf(" %u=%llu", k, v);
    }
    printf("\n");

    if (denied_fd >= 0) {
        char buf[NAME_MAX_LEN] = {};
        unsigned int k = 0;
        if (bpf_map_lookup_elem(denied_fd, &k, buf) == 0) {
            buf[NAME_MAX_LEN - 1] = '\0';
            printf("LAST_DENIED %s\n", buf[0] ? buf : "(none)");
        }
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <object.bpf.o>\n", argv[0]);
        return 2;
    }

    libbpf_set_print(quiet_log);

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

    struct bpf_link *links[MAX_LINKS];
    int nlinks = 0;
    struct bpf_program *prog;

    bpf_object__for_each_program(prog, obj) {
        if (nlinks >= MAX_LINKS)
            break;
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "attach failed for %s: %s\n",
                    bpf_program__name(prog), strerror(errno));
            for (int i = 0; i < nlinks; i++)
                bpf_link__destroy(links[i]);
            bpf_object__close(obj);
            return 1;
        }
        links[nlinks++] = link;
    }

    struct bpf_map *control = bpf_object__find_map_by_name(obj, "control");
    struct bpf_map *stats = bpf_object__find_map_by_name(obj, "stats");
    struct bpf_map *denied = bpf_object__find_map_by_name(obj, "last_denied");

    if (!control || !stats) {
        fprintf(stderr, "required maps not found\n");
        return 1;
    }

    int control_fd = bpf_map__fd(control);
    int stats_fd = bpf_map__fd(stats);
    int denied_fd = denied ? bpf_map__fd(denied) : -1;

    // Attached but inert. Nothing is refused until the harness says so.
    if (set_control(control_fd, 0)) {
        fprintf(stderr, "could not initialise control map\n");
        return 1;
    }

    printf("READY %d\n", nlinks);
    fflush(stdout);

    char line[64];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = '\0';

        if (!strcmp(line, "arm")) {
            printf(set_control(control_fd, 1) ? "ERROR arm\n" : "ARMED\n");
        } else if (!strcmp(line, "disarm")) {
            printf(set_control(control_fd, 0) ? "ERROR disarm\n" : "DISARMED\n");
        } else if (!strcmp(line, "stats")) {
            print_stats(obj, stats_fd, denied_fd);
            continue;
        } else if (!strcmp(line, "quit")) {
            break;
        } else {
            printf("ERROR unknown\n");
        }
        fflush(stdout);
    }

    set_control(control_fd, 0);
    for (int i = 0; i < nlinks; i++)
        bpf_link__destroy(links[i]);
    bpf_object__close(obj);

    printf("BYE\n");
    fflush(stdout);
    return 0;
}
