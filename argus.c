#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "argus.skel.h"
#include "argus.h"
#include "output.h"
#include "lineage.h"
#include "config.h"

static volatile int running       = 1;
static volatile int reload_config = 0;
static uint64_t     last_drops    = 0;

static void sig_handler(int sig)  { (void)sig; running = 0; }
static void sighup_handler(int sig) { (void)sig; reload_config = 1; }

/* ── drop accounting ────────────────────────────────────────────────────── */

static uint64_t read_drop_delta(int map_fd)
{
    uint32_t key   = 0;
    uint64_t drops = 0;
    if (bpf_map_lookup_elem(map_fd, &key, &drops))
        return 0;
    uint64_t delta = drops > last_drops ? drops - last_drops : 0;
    if (delta)
        last_drops = drops;
    return delta;
}

/* ── privilege drop ─────────────────────────────────────────────────────── */
/*
 * Called after all BPF programs are attached and the ring buffer fd is open.
 * Drops from root to 'nobody' (uid 65534) so the event loop runs with
 * minimal privilege. All open file descriptors remain valid after setuid.
 */
static void drop_privileges(void)
{
    uid_t uid = 65534;
    gid_t gid = 65534;

    struct passwd *pw = getpwnam("nobody");
    if (pw) {
        uid = pw->pw_uid;
        gid = pw->pw_gid;
    }

    if (setgroups(0, NULL) < 0 ||
        setgid(gid)         < 0 ||
        setuid(uid)         < 0) {
        perror("warning: could not drop privileges");
        /* non-fatal — continue as root rather than abort */
    }
}

/* ── CLI helpers ────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  --config      <path>  Config file (default: ~/.config/argus/config.json)\n"
        "  --pid         <pid>   Only trace this PID (kernel-enforced)\n"
        "  --comm        <name>  Only trace this process name (kernel-enforced)\n"
        "  --path        <str>   Only show events whose path contains <str>\n"
        "  --exclude     <pfx>   Exclude OPEN events whose path starts with <pfx>\n"
        "  --events      <list>  Comma-separated types: EXEC,OPEN,EXIT,CONNECT,\n"
        "                         UNLINK,RENAME,CHMOD,BIND,PTRACE\n"
        "  --ringbuf     <kb>    Ring buffer size in KB (default: 256)\n"
        "  --summary     <secs>  Rolling summary every N seconds\n"
        "  --rate-limit  <n>    Drop events after N per second per comm (0=off)\n"
        "  --no-drop-privs       Stay root after attach (not recommended)\n"
        "  --json                Newline-delimited JSON output\n"
        "  --config-check        Validate config file(s) and print active settings, then exit\n"
        "  --version             Print version and exit\n"
        "  --help                Show this message\n",
        prog);
}

static int parse_event_list(const char *s)
{
    int mask = 0;
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *tok = strtok(buf, ",");
    while (tok) {
        while (*tok == ' ') tok++;
        if      (strcmp(tok, "EXEC")    == 0) mask |= TRACE_EXEC;
        else if (strcmp(tok, "OPEN")    == 0) mask |= TRACE_OPEN;
        else if (strcmp(tok, "EXIT")    == 0) mask |= TRACE_EXIT;
        else if (strcmp(tok, "CONNECT") == 0) mask |= TRACE_CONNECT;
        else if (strcmp(tok, "UNLINK")  == 0) mask |= TRACE_UNLINK;
        else if (strcmp(tok, "RENAME")  == 0) mask |= TRACE_RENAME;
        else if (strcmp(tok, "CHMOD")   == 0) mask |= TRACE_CHMOD;
        else if (strcmp(tok, "BIND")    == 0) mask |= TRACE_BIND;
        else if (strcmp(tok, "PTRACE")  == 0) mask |= TRACE_PTRACE;
        tok = strtok(NULL, ",");
    }
    return mask;
}

/* ── BPF setup ──────────────────────────────────────────────────────────── */

static void setup_bpf_filters(struct argus_bpf *skel, const filter_t *f,
                               uint32_t rate_limit_per_comm)
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
    cfg.rate_limit_per_comm = rate_limit_per_comm;
    /* always write config_map — even with no filters, rate_limit may be set */
    bpf_map_update_elem(bpf_map__fd(skel->maps.config_map),
                        &zero, &cfg, BPF_ANY);
}

static void configure_programs(struct argus_bpf *skel, int event_mask)
{
    if (!(event_mask & TRACE_EXEC)) {
        bpf_program__set_autoload(skel->progs.handle_execve_enter,  false);
        bpf_program__set_autoload(skel->progs.handle_execve_exit,   false);
    }
    if (!(event_mask & TRACE_OPEN)) {
        bpf_program__set_autoload(skel->progs.handle_openat_enter,  false);
        bpf_program__set_autoload(skel->progs.handle_openat_exit,   false);
    }
    if (!(event_mask & TRACE_EXIT))
        bpf_program__set_autoload(skel->progs.handle_process_exit,  false);
    if (!(event_mask & TRACE_CONNECT)) {
        bpf_program__set_autoload(skel->progs.handle_connect_enter, false);
        bpf_program__set_autoload(skel->progs.handle_connect_exit,  false);
    }
    if (!(event_mask & TRACE_UNLINK)) {
        bpf_program__set_autoload(skel->progs.handle_unlinkat_enter, false);
        bpf_program__set_autoload(skel->progs.handle_unlinkat_exit,  false);
    }
    if (!(event_mask & TRACE_RENAME)) {
        bpf_program__set_autoload(skel->progs.handle_renameat2_enter, false);
        bpf_program__set_autoload(skel->progs.handle_renameat2_exit,  false);
    }
    if (!(event_mask & TRACE_CHMOD)) {
        bpf_program__set_autoload(skel->progs.handle_fchmodat_enter, false);
        bpf_program__set_autoload(skel->progs.handle_fchmodat_exit,  false);
    }
    if (!(event_mask & TRACE_BIND)) {
        bpf_program__set_autoload(skel->progs.handle_bind_enter, false);
        bpf_program__set_autoload(skel->progs.handle_bind_exit,  false);
    }
    if (!(event_mask & TRACE_PTRACE)) {
        bpf_program__set_autoload(skel->progs.handle_ptrace_enter, false);
        bpf_program__set_autoload(skel->progs.handle_ptrace_exit,  false);
    }
}

/* ── event handler ──────────────────────────────────────────────────────── */

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx; (void)data_sz;
    const event_t *e = data;

    if (event_matches(e))
        print_event(e);

    /* Update lineage regardless of filter so the tree stays consistent */
    if (e->type == EVENT_EXEC)
        lineage_update(e->pid, e->ppid, e->comm);
    else if (e->type == EVENT_EXIT)
        lineage_remove(e->pid);

    return 0;
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    argus_cfg_t  cfg;
    output_fmt_t fmt          = OUTPUT_TEXT;
    int          no_drop_privs = 0;

    cfg_defaults(&cfg);

    /* Load config files — CLI flags override below */
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
        {"config",        required_argument, 0, 'C'},
        {"pid",           required_argument, 0, 'p'},
        {"comm",          required_argument, 0, 'c'},
        {"path",          required_argument, 0, 'P'},
        {"exclude",       required_argument, 0, 'x'},
        {"events",        required_argument, 0, 'e'},
        {"ringbuf",       required_argument, 0, 'r'},
        {"summary",       required_argument, 0, 's'},
        {"rate-limit",    required_argument, 0, 'R'},
        {"no-drop-privs", no_argument,       0, 'n'},
        {"json",          no_argument,       0, 'j'},
        {"config-check",  no_argument,       0, 'K'},
        {"version",       no_argument,       0, 'V'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int config_check = 0;
    int opt;
    while ((opt = getopt_long(argc, argv, "C:p:c:P:x:e:r:s:R:njKVh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'C':
            if (cfg_load(optarg, &cfg) != 0)
                fprintf(stderr, "warning: could not load %s\n", optarg);
            break;
        case 'p': cfg.filter.pid = atoi(optarg);                                  break;
        case 'c': strncpy(cfg.filter.comm, optarg, sizeof(cfg.filter.comm)-1);    break;
        case 'P': strncpy(cfg.filter.path, optarg, sizeof(cfg.filter.path)-1);    break;
        case 'x':
            if (cfg.filter.exclude_count < 8)
                strncpy(cfg.filter.excludes[cfg.filter.exclude_count++],
                        optarg, 127);
            else
                fprintf(stderr, "warning: --exclude limit (8) reached, "
                                "ignoring '%s'\n", optarg);
            break;
        case 'e': cfg.filter.event_mask = parse_event_list(optarg);               break;
        case 'r': {
            int kb = atoi(optarg);
            if (kb < 4 || kb > 65536) {
                fprintf(stderr, "error: --ringbuf must be between 4 and 65536 KB\n");
                return 1;
            }
            cfg.ring_buffer_kb = kb;
            break;
        }
        case 's': cfg.summary_interval      = atoi(optarg);                       break;
        case 'R': cfg.rate_limit_per_comm  = (uint32_t)atoi(optarg);             break;
        case 'n': no_drop_privs            = 1;                                   break;
        case 'j': fmt                   = OUTPUT_JSON;                             break;
        case 'K': config_check          = 1;                                       break;
        case 'V': printf("argus %s\n", ARGUS_VERSION); return 0;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (config_check) {
        static const char *type_names[] = {
            "EXEC","OPEN","EXIT","CONNECT",
            "UNLINK","RENAME","CHMOD","BIND","PTRACE"
        };
        printf("argus %s — active configuration\n\n", ARGUS_VERSION);
        printf("  ring_buffer_kb      : %d\n",  cfg.ring_buffer_kb);
        printf("  summary_interval    : %d\n",  cfg.summary_interval);
        printf("  rate_limit_per_comm : %u\n",  cfg.rate_limit_per_comm);
        printf("  filter.pid          : %d\n",  cfg.filter.pid);
        printf("  filter.comm         : %s\n",  cfg.filter.comm[0] ? cfg.filter.comm : "(none)");
        printf("  filter.path         : %s\n",  cfg.filter.path[0] ? cfg.filter.path : "(none)");
        printf("  filter.event_mask   : ");
        int any = 0;
        for (int i = 0; i < EVENT_TYPE_MAX; i++)
            if (cfg.filter.event_mask & (1 << i)) {
                printf("%s%s", any ? "," : "", type_names[i]);
                any = 1;
            }
        if (!any) printf("ALL");
        printf("\n");
        printf("  exclude_paths     :");
        if (cfg.filter.exclude_count == 0) printf(" (none)");
        for (int i = 0; i < cfg.filter.exclude_count; i++)
            printf(" %s", cfg.filter.excludes[i]);
        printf("\n");
        return 0;
    }

    if (cfg.filter.event_mask == 0)
        cfg.filter.event_mask = TRACE_ALL;

    output_init(fmt, &cfg.filter);
    if (cfg.summary_interval > 0)
        output_set_summary(cfg.summary_interval);

    /* Ignore SIGPIPE so piped consumers (jq, etc.) can exit without crashing us */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP,  sighup_handler);
    libbpf_set_print(NULL);

    /* Pre-populate lineage cache from /proc before attaching BPF programs */
    lineage_scan_proc();

    struct argus_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    skel = argus_bpf__open();
    if (!skel) {
        fprintf(stderr, "error: failed to open BPF skeleton\n");
        return 1;
    }

    bpf_map__set_max_entries(skel->maps.rb,
                             (uint32_t)cfg.ring_buffer_kb * 1024);
    configure_programs(skel, cfg.filter.event_mask);

    err = argus_bpf__load(skel);
    if (err) {
        fprintf(stderr, "error: failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    setup_bpf_filters(skel, &cfg.filter, cfg.rate_limit_per_comm);

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

    /* Drop root privileges — all BPF fds are already open */
    if (!no_drop_privs)
        drop_privileges();

    print_header("eBPF");

    int drop_fd = bpf_map__fd(skel->maps.dropped);

    /* Save config file paths for SIGHUP reload */
    char cfg_home_path[256] = {};
    {
        const char *home = getenv("HOME");
        if (home)
            snprintf(cfg_home_path, sizeof(cfg_home_path),
                     "%s/.config/argus/config.json", home);
    }

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "error: ring buffer poll failed: %d\n", err);
            break;
        }

        /* ── SIGHUP: reload config files and update BPF filter maps ── */
        if (reload_config) {
            reload_config = 0;
            argus_cfg_t new_cfg;
            cfg_defaults(&new_cfg);
            cfg_load("/etc/argus/config.json", &new_cfg);
            if (cfg_home_path[0])
                cfg_load(cfg_home_path, &new_cfg);
            /* Update BPF maps with new filter/rate settings */
            setup_bpf_filters(skel, &new_cfg.filter, new_cfg.rate_limit_per_comm);
            /* Update userspace filter (path, excludes, event_mask) */
            output_update_filter(&new_cfg.filter);
            /* Propagate to the live cfg (keep ring_buffer_kb/summary fixed) */
            cfg.filter              = new_cfg.filter;
            cfg.rate_limit_per_comm = new_cfg.rate_limit_per_comm;
            fprintf(stderr, "info: configuration reloaded (SIGHUP)\n");
        }

        uint64_t delta = read_drop_delta(drop_fd);
        output_summary_tick(delta);
        if (delta && !cfg.summary_interval)
            print_drops(delta);
    }

    /* Final drop check before exit */
    uint64_t delta = read_drop_delta(drop_fd);
    if (delta)
        print_drops(delta);

    ring_buffer__free(rb);
cleanup:
    argus_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
