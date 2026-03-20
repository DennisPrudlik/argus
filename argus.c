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
#include "lineage.h"
#include "config.h"

static volatile int running = 1;
static uint64_t     last_drops = 0;

static void check_drops(int map_fd)
{
    uint32_t key   = 0;
    uint64_t drops = 0;
    if (bpf_map_lookup_elem(map_fd, &key, &drops))
        return;
    uint64_t delta = drops > last_drops ? drops - last_drops : 0;
    if (delta) {
        last_drops = drops;
        print_drops(delta);
    }
}

static void sig_handler(int sig) { (void)sig; running = 0; }

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  --config  <path>  Config file (default: /etc/argus/config.json)\n"
        "  --pid     <pid>   Only trace this PID (kernel-enforced)\n"
        "  --comm    <name>  Only trace this process name (kernel-enforced)\n"
        "  --path    <str>   Only show file events whose path contains <str>\n"
        "  --exclude <pfx>   Exclude OPEN events whose path starts with <pfx>\n"
        "  --events  <list>  Comma-separated event types: EXEC,OPEN,EXIT,CONNECT\n"
        "  --ringbuf <kb>    Ring buffer size in KB (default: 256)\n"
        "  --summary <secs>  Rolling summary every N seconds instead of per-event\n"
        "  --json            Newline-delimited JSON output\n"
        "  --help            Show this message\n",
        prog);
}

/* Parse "EXEC,OPEN,EXIT,CONNECT" into a TRACE_* bitmask */
static int parse_event_list(const char *s)
{
    int mask = 0;
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf)-1] = '\0';
    char *tok = strtok(buf, ",");
    while (tok) {
        while (*tok == ' ') tok++;
        if      (strcmp(tok, "EXEC")    == 0) mask |= TRACE_EXEC;
        else if (strcmp(tok, "OPEN")    == 0) mask |= TRACE_OPEN;
        else if (strcmp(tok, "EXIT")    == 0) mask |= TRACE_EXIT;
        else if (strcmp(tok, "CONNECT") == 0) mask |= TRACE_CONNECT;
        tok = strtok(NULL, ",");
    }
    return mask;
}

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

/* Selectively detach BPF programs for event types not in event_mask */
static void configure_programs(struct argus_bpf *skel, int event_mask)
{
    if (!(event_mask & TRACE_EXEC)) {
        bpf_program__set_autoload(skel->progs.handle_execve_enter, false);
        bpf_program__set_autoload(skel->progs.handle_execve_exit,  false);
    }
    if (!(event_mask & TRACE_OPEN)) {
        bpf_program__set_autoload(skel->progs.handle_openat_enter, false);
        bpf_program__set_autoload(skel->progs.handle_openat_exit,  false);
    }
    if (!(event_mask & TRACE_EXIT))
        bpf_program__set_autoload(skel->progs.handle_process_exit, false);
    if (!(event_mask & TRACE_CONNECT)) {
        bpf_program__set_autoload(skel->progs.handle_connect_enter, false);
        bpf_program__set_autoload(skel->progs.handle_connect_exit,  false);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx; (void)data_sz;
    const event_t *e = data;

    if (event_matches(e))
        print_event(e);

    if (e->type == EVENT_EXEC)
        lineage_update(e->pid, e->ppid, e->comm);
    else if (e->type == EVENT_EXIT)
        lineage_remove(e->pid);

    return 0;
}

int main(int argc, char **argv)
{
    argus_cfg_t   cfg;
    output_fmt_t  fmt     = OUTPUT_TEXT;
    const char   *cfgpath = NULL;

    cfg_defaults(&cfg);

    /* Try default config locations before parsing CLI */
    if (cfg_load("/etc/argus/config.json", &cfg) == -2)
        fprintf(stderr, "warning: error reading /etc/argus/config.json\n");
    {
        const char *home = getenv("HOME");
        if (home) {
            char path[256];
            snprintf(path, sizeof(path), "%s/.config/argus/config.json", home);
            if (cfg_load(path, &cfg) == -2)
                fprintf(stderr, "warning: error reading %s\n", path);
        }
    }

    static const struct option long_opts[] = {
        {"config",  required_argument, 0, 'C'},
        {"pid",     required_argument, 0, 'p'},
        {"comm",    required_argument, 0, 'c'},
        {"path",    required_argument, 0, 'P'},
        {"exclude", required_argument, 0, 'x'},
        {"events",  required_argument, 0, 'e'},
        {"ringbuf", required_argument, 0, 'r'},
        {"summary", required_argument, 0, 's'},
        {"json",    no_argument,       0, 'j'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "C:p:c:P:x:e:r:s:jh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'C':
            cfgpath = optarg;
            if (cfg_load(cfgpath, &cfg) != 0)
                fprintf(stderr, "warning: could not load %s\n", cfgpath);
            break;
        case 'p': cfg.filter.pid = atoi(optarg);                                   break;
        case 'c': strncpy(cfg.filter.comm, optarg, sizeof(cfg.filter.comm) - 1);   break;
        case 'P': strncpy(cfg.filter.path, optarg, sizeof(cfg.filter.path) - 1);   break;
        case 'x':
            if (cfg.filter.exclude_count < 8)
                strncpy(cfg.filter.excludes[cfg.filter.exclude_count++],
                        optarg, 127);
            break;
        case 'e': cfg.filter.event_mask = parse_event_list(optarg);                break;
        case 'r': cfg.ring_buffer_kb    = atoi(optarg);                            break;
        case 's': cfg.summary_interval  = atoi(optarg);                            break;
        case 'j': fmt = OUTPUT_JSON;                                                break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    /* 0 event_mask means "all" — normalise now so configure_programs works */
    if (cfg.filter.event_mask == 0)
        cfg.filter.event_mask = TRACE_ALL;

    output_init(fmt, &cfg.filter);
    if (cfg.summary_interval > 0)
        output_set_summary(cfg.summary_interval);

    struct argus_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    libbpf_set_print(NULL);

    skel = argus_bpf__open();
    if (!skel) {
        fprintf(stderr, "error: failed to open BPF skeleton\n");
        return 1;
    }

    /* Configure ring buffer size before load */
    bpf_map__set_max_entries(skel->maps.rb,
                             (uint32_t)cfg.ring_buffer_kb * 1024);

    /* Disable programs for event types not requested */
    configure_programs(skel, cfg.filter.event_mask);

    err = argus_bpf__load(skel);
    if (err) {
        fprintf(stderr, "error: failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    setup_bpf_filters(skel, &cfg.filter);

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
        uint64_t drops = 0, key = 0;
        bpf_map_lookup_elem(drop_fd, &key, &drops);
        uint64_t delta = drops > last_drops ? drops - last_drops : 0;
        if (delta) last_drops = drops;
        output_summary_tick(delta);
        if (delta && !cfg.summary_interval)
            print_drops(delta);
    }

    check_drops(drop_fd);

    ring_buffer__free(rb);
cleanup:
    argus_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
