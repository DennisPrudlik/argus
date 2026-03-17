/*
 * argus_esf.c — macOS Endpoint Security Framework backend
 *
 * Event coverage:
 *   EVENT_EXEC — ES_EVENT_TYPE_NOTIFY_EXEC  (macOS 10.15+)
 *   EVENT_OPEN — ES_EVENT_TYPE_NOTIFY_OPEN  (macOS 10.15+)
 *   EVENT_EXIT — ES_EVENT_TYPE_NOTIFY_EXIT  (macOS 10.15+)
 *
 * NOTE: EVENT_CONNECT is not available via ESF. Network monitoring on macOS
 * requires the Network Extension framework (NEFilterDataProvider /
 * NEAppProxyProvider), which is a separate implementation.
 *
 * Requirements:
 *   - Binary signed with com.apple.developer.endpoint-security.client
 *   - Must run as root
 *
 * Build:
 *   clang -g -Wall -o argus_esf argus_esf.c \
 *         -framework EndpointSecurity -lbsm
 *
 * NOTE: duration_ns is always 0 for all events — NOTIFY_* fires after the
 * fact. AUTH_* variants allow timing but require responding allow/deny.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <bsm/libbsm.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include "argus.h"

/* ── helpers ────────────────────────────────────────────────────────────── */

static void fill_common(event_t *e, const es_process_t *proc,
                         event_type_t type)
{
    e->type        = type;
    e->pid         = audit_token_to_pid(proc->audit_token);
    e->ppid        = proc->ppid;
    e->uid         = audit_token_to_euid(proc->audit_token);
    e->gid         = audit_token_to_egid(proc->audit_token);
    e->duration_ns = 0;
    e->success     = true;

    const char *path = proc->executable->path.data;
    const char *base = strrchr(path, '/');
    strncpy(e->comm, base ? base + 1 : path, sizeof(e->comm) - 1);
}

/* ── event handlers ─────────────────────────────────────────────────────── */

static void handle_exec(const es_message_t *msg)
{
    event_t e = {};
    const es_process_t *proc = msg->event.exec.target;
    fill_common(&e, proc, EVENT_EXEC);

    strncpy(e.filename, proc->executable->path.data,
            sizeof(e.filename) - 1);

    /* argv[1..N] → space-separated args (requires macOS 11.0+) */
    uint32_t argc = es_exec_arg_count(&msg->event.exec);
    int off = 0;
    for (uint32_t i = 1; i < argc; i++) {
        es_string_token_t arg = es_exec_arg(&msg->event.exec, i);
        int rem = (int)sizeof(e.args) - off - 1;
        if (rem <= 0)
            break;
        int n = snprintf(e.args + off, rem, "%.*s",
                         (int)arg.length, arg.data);
        if (n <= 0)
            break;
        off += n;
        if (off < (int)sizeof(e.args) - 1 && i + 1 < argc)
            e.args[off++] = ' ';
    }

    print_event(&e);
}

static void handle_open(const es_message_t *msg)
{
    event_t e = {};
    fill_common(&e, msg->process, EVENT_OPEN);

    strncpy(e.filename, msg->event.open.file->path.data,
            sizeof(e.filename) - 1);

    print_event(&e);
}

static void handle_exit(const es_message_t *msg)
{
    event_t e = {};
    fill_common(&e, msg->process, EVENT_EXIT);

    int stat = msg->event.exit.stat;
    if (WIFEXITED(stat))
        e.exit_code = WEXITSTATUS(stat);
    else if (WIFSIGNALED(stat))
        e.exit_code = -WTERMSIG(stat); /* negative = killed by signal */

    print_event(&e);
}

/* ── printer ────────────────────────────────────────────────────────────── */

void print_event(const event_t *e)
{
    /* common prefix */
    printf("%-5s  %-6d  %-6d  %-4u  %-4u  %-16s  ",
           e->type == EVENT_EXEC    ? "EXEC"    :
           e->type == EVENT_OPEN    ? "OPEN"    :
           e->type == EVENT_EXIT    ? "EXIT"    :
           e->type == EVENT_CONNECT ? "CONN"    : "?",
           e->pid, e->ppid, e->uid, e->gid, e->comm);

    switch (e->type) {
    case EVENT_EXEC:
        printf("%s %s", e->filename, e->args);
        break;
    case EVENT_OPEN:
        printf("%s", e->filename);
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
        printf("%s:%u", addr, e->dport);
        break;
    }
    }
    putchar('\n');
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void)
{
    es_client_t *client = NULL;

    es_new_client_result_t res = es_new_client(&client,
        ^(es_client_t *c, const es_message_t *msg) {
            (void)c;
            switch (msg->event_type) {
            case ES_EVENT_TYPE_NOTIFY_EXEC: handle_exec(msg); break;
            case ES_EVENT_TYPE_NOTIFY_OPEN: handle_open(msg); break;
            case ES_EVENT_TYPE_NOTIFY_EXIT: handle_exit(msg); break;
            default: break;
            }
        });

    switch (res) {
    case ES_NEW_CLIENT_RESULT_SUCCESS:
        break;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        fprintf(stderr, "error: binary must be signed with "
                        "com.apple.developer.endpoint-security.client\n");
        return 1;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        fprintf(stderr, "error: must run as root\n");
        return 1;
    default:
        fprintf(stderr, "error: es_new_client failed: %d\n", res);
        return 1;
    }

    es_event_type_t subs[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_OPEN,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    };
    if (es_subscribe(client, subs, 3) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "error: es_subscribe failed\n");
        es_delete_client(client);
        return 1;
    }

    signal(SIGINT,  SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    void (^shutdown)(void) = ^{
        es_unsubscribe_all(client);
        es_delete_client(client);
        printf("\nDone.\n");
        exit(0);
    };

    dispatch_source_t src_int =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0,
                               dispatch_get_main_queue());
    dispatch_source_set_event_handler(src_int, shutdown);
    dispatch_resume(src_int);

    dispatch_source_t src_term =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0,
                               dispatch_get_main_queue());
    dispatch_source_set_event_handler(src_term, shutdown);
    dispatch_resume(src_term);

    printf("Tracing via ESF (EXEC, OPEN, EXIT)... Ctrl-C to stop.\n\n");
    printf("  NOTE: CONNECT not available via ESF — use Network Extension for network telemetry.\n\n");
    printf("%-5s  %-6s  %-6s  %-4s  %-4s  %-16s  %s\n",
           "TYPE", "PID", "PPID", "UID", "GID", "COMM", "DETAIL");
    printf("%-5s  %-6s  %-6s  %-4s  %-4s  %-16s  %s\n",
           "-----", "------", "------", "----", "----",
           "----------------", "------");

    dispatch_main();
    return 0;
}
