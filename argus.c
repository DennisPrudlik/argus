#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "argus.skel.h"
#include "argus.h"

static volatile int running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void print_header(void)
{
    printf("Tracing (EXEC, OPEN, EXIT, CONNECT)... Hit Ctrl-C to stop.\n\n");
    printf("%-5s  %-6s  %-6s  %-4s  %-4s  %-16s  %s\n",
           "TYPE", "PID", "PPID", "UID", "GID", "COMM", "DETAIL");
    printf("%-5s  %-6s  %-6s  %-4s  %-4s  %-16s  %s\n",
           "-----", "------", "------", "----", "----",
           "----------------", "------");
}

static void print_event(const event_t *e)
{
    /* common prefix */
    printf("%-5s  %-6d  %-6d  %-4u  %-4u  %-16s  ",
           e->type == EVENT_EXEC    ? "EXEC"  :
           e->type == EVENT_OPEN    ? "OPEN"  :
           e->type == EVENT_EXIT    ? "EXIT"  :
           e->type == EVENT_CONNECT ? "CONN"  : "?",
           e->pid, e->ppid, e->uid, e->gid, e->comm);

    switch (e->type) {
    case EVENT_EXEC:
        printf("%s %s", e->filename, e->args);
        break;
    case EVENT_OPEN:
        printf("[%s] %s",
               e->success ? "OK" : "FAIL",
               e->filename);
        break;
    case EVENT_EXIT:
        printf("exit_code=%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        char addr[INET6_ADDRSTRLEN] = {};
        if (e->family == AF_INET)
            inet_ntop(AF_INET,  e->daddr, addr, sizeof(addr));
        else
            inet_ntop(AF_INET6, e->daddr, addr, sizeof(addr));
        printf("[%s] %s:%u",
               e->success ? "OK" : "FAIL",
               addr, e->dport);
        break;
    }
    }
    putchar('\n');
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;
    print_event((const event_t *)data);
    return 0;
}

int main(void)
{
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

    print_header();

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
