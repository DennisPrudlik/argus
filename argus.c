#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "argus.skel.h"
#include "argus.h"

static volatile int running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;
    const event_t *e = data;

    printf("%-7d  %-7d  %-16s  %-10llu  %-4s  %s\n",
           e->pid,
           e->ppid,
           e->comm,
           (unsigned long long)e->duration_ns,
           e->success ? "OK" : "FAIL",
           e->filename);
    return 0;
}

int main(void)
{
    struct argus_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* Silence libbpf debug output */
    libbpf_set_print(NULL);

    skel = argus_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "error: failed to open/load BPF skeleton\n");
        return 1;
    }

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

    printf("Tracing execve... Hit Ctrl-C to stop.\n\n");
    printf("%-7s  %-7s  %-16s  %-10s  %-4s  %s\n",
           "PID", "PPID", "COMM", "DURATION_NS", "STATUS", "FILENAME");
    printf("%-7s  %-7s  %-16s  %-10s  %-4s  %s\n",
           "-------", "-------", "----------------", "----------", "----",
           "--------");

    while (running) {
        err = ring_buffer__poll(rb, 100 /* ms timeout */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "error: ring buffer poll failed: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
cleanup:
    argus_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
