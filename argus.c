#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "argus.skel.h"
#include "argus.h"
#include "output.h"

static volatile int running = 1;
static uint64_t last_drops = 0;

static void check_drops(int map_fd)
{
    uint32_t key  = 0;
    uint64_t drops = 0;
    if (bpf_map_lookup_elem(map_fd, &key, &drops))
        return;
    if (drops > last_drops) {
        print_drops(drops - last_drops);
        last_drops = drops;
    }
}

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  --pid  <pid>   Only show events from this PID\n"
        "  --comm <name>  Only show events from processes matching this name\n"
        "  --path <str>   Only show file events whose path contains this string\n"
        "  --json         Emit newline-delimited JSON instead of text\n"
        "  --help         Show this message\n",
        prog);
}

/*
 * Populate the BPF filter maps from the parsed CLI filter.
 * Must be called after argus_bpf__open_and_load() and before
 * argus_bpf__attach() so the maps are ready before any events fire.
 *
 * pid and comm filters are enforced in-kernel; path is still userspace-only
 * (prefix/substring matching in BPF requires a trie which is a future step).
 */
static void setup_bpf_filters(struct argus_bpf *skel, const filter_t *f)
{
    argus_config_t cfg = {};
    uint32_t zero = 0;

    if (f->pid != 0) {
        uint32_t pid = (uint32_t)f->pid;
        uint8_t  val = 1;
        bpf_map_update_elem(bpf_map__fd(skel->maps.filter_pids),
                            &pid, &val, BPF_ANY);
        cfg.filter_pid_active = 1;
    }

    if (f->comm[0] != '\0') {
        char key[16] = {};
        strncpy(key, f->comm, sizeof(key) - 1);
        uint8_t val = 1;
        bpf_map_update_elem(bpf_map__fd(skel->maps.filter_comms),
                            key, &val, BPF_ANY);
        cfg.filter_comm_active = 1;
    }

    if (cfg.filter_pid_active || cfg.filter_comm_active)
        bpf_map_update_elem(bpf_map__fd(skel->maps.config_map),
                            &zero, &cfg, BPF_ANY);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;
    const event_t *e = data;
    if (event_matches(e))
        print_event(e);
    return 0;
}

int main(int argc, char **argv)
{
    filter_t      filter  = {0};
    output_fmt_t  fmt     = OUTPUT_TEXT;

    static const struct option long_opts[] = {
        {"pid",  required_argument, 0, 'p'},
        {"comm", required_argument, 0, 'c'},
        {"path", required_argument, 0, 'P'},
        {"json", no_argument,       0, 'j'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:c:P:jh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': filter.pid = atoi(optarg);                                break;
        case 'c': strncpy(filter.comm, optarg, sizeof(filter.comm) - 1);   break;
        case 'P': strncpy(filter.path, optarg, sizeof(filter.path) - 1);   break;
        case 'j': fmt = OUTPUT_JSON;                                        break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    output_init(fmt, &filter);

    struct argus_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_print(NULL);

    skel = argus_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "error: failed to open/load BPF skeleton\n");
        return 1;
    }

    setup_bpf_filters(skel, &filter);

    err = argus_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "error: failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "error: failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    print_header("eBPF");

    int drop_fd = bpf_map__fd(skel->maps.dropped);

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "error: ring buffer poll failed: %d\n", err);
            break;
        }
        check_drops(drop_fd);
    }

    /* Final check — catch any drops that landed in the last poll window */
    check_drops(drop_fd);

    ring_buffer__free(rb);
cleanup:
    argus_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
