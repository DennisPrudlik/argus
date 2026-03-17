/*
 * argus_esf.c — macOS Endpoint Security Framework backend
 *
 * Captures ES_EVENT_TYPE_NOTIFY_EXEC events and emits them as event_t
 * structs, matching the same output format as the Linux eBPF backend.
 *
 * Requirements:
 *   - macOS 10.15+
 *   - Binary must be signed with the entitlement:
 *       com.apple.developer.endpoint-security.client
 *   - Must run as root (or have TCC Full Disk Access)
 *
 * Build:
 *   clang -g -Wall -o argus_esf argus_esf.c \
 *         -framework EndpointSecurity -lbsm
 *
 * Code-sign (after obtaining entitlement from Apple):
 *   codesign --entitlements argus.entitlements -s "Developer ID" argus_esf
 *
 * NOTE: duration_ns is always 0 on macOS — NOTIFY_EXEC fires after exec
 * has already completed; AUTH_EXEC would allow timing but requires
 * responding to every event (allow/deny), which is out of scope here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <bsm/libbsm.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include "argus.h"

static void print_header(void)
{
    printf("Tracing execve via ESF... Hit Ctrl-C to stop.\n\n");
    printf("%-7s  %-7s  %-16s  %-10s  %-4s  %s\n",
           "PID", "PPID", "COMM", "DURATION_NS", "STATUS", "FILENAME");
    printf("%-7s  %-7s  %-16s  %-10s  %-4s  %s\n",
           "-------", "-------", "----------------", "----------",
           "----", "--------");
}

static void print_event(const event_t *e)
{
    printf("%-7d  %-7d  %-16s  %-10llu  %-4s  %s\n",
           e->pid,
           e->ppid,
           e->comm,
           (unsigned long long)e->duration_ns,
           e->success ? "OK" : "FAIL",
           e->filename);
}

static void handle_exec(const es_message_t *msg)
{
    const es_process_t *proc = msg->event.exec.target;
    event_t e = {};

    e.pid        = audit_token_to_pid(proc->audit_token);
    e.ppid       = proc->ppid;
    e.duration_ns = 0;   /* not available for NOTIFY events */
    e.success    = true; /* NOTIFY_EXEC only fires on success */

    /* Executable path -> filename */
    const char *path = proc->executable->path.data;
    strncpy(e.filename, path, sizeof(e.filename) - 1);

    /* Derive comm from basename of path */
    const char *base = strrchr(path, '/');
    strncpy(e.comm, base ? base + 1 : path, sizeof(e.comm) - 1);

    print_event(&e);
}

int main(void)
{
    es_client_t *client = NULL;

    es_new_client_result_t res = es_new_client(&client,
        ^(es_client_t *c, const es_message_t *msg) {
            (void)c;
            if (msg->event_type == ES_EVENT_TYPE_NOTIFY_EXEC)
                handle_exec(msg);
        });

    switch (res) {
    case ES_NEW_CLIENT_RESULT_SUCCESS:
        break;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        fprintf(stderr, "error: not permitted — binary must be signed with "
                        "com.apple.developer.endpoint-security.client\n");
        return 1;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        fprintf(stderr, "error: must run as root\n");
        return 1;
    default:
        fprintf(stderr, "error: es_new_client failed: %d\n", res);
        return 1;
    }

    es_event_type_t subs[] = { ES_EVENT_TYPE_NOTIFY_EXEC };
    if (es_subscribe(client, subs, 1) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "error: es_subscribe failed\n");
        es_delete_client(client);
        return 1;
    }

    /* Use dispatch sources for clean Ctrl-C / SIGTERM shutdown */
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

    print_header();
    dispatch_main(); /* blocks; ESF callbacks delivered on internal queue */
    return 0;
}
