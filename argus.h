#ifndef __ARGUS_H
#define __ARGUS_H

#define ARGUS_VERSION "0.1.0"

/* vmlinux.h (BPF context) already provides these types */
#ifndef __VMLINUX_H__
#include <stdint.h>
#include <stdbool.h>
#endif

typedef enum {
    EVENT_EXEC    = 0,
    EVENT_OPEN    = 1,
    EVENT_EXIT    = 2,
    EVENT_CONNECT = 3,
    EVENT_UNLINK  = 4,
    EVENT_RENAME  = 5,
    EVENT_CHMOD   = 6,
    EVENT_BIND    = 7,
    EVENT_PTRACE  = 8,
} event_type_t;

#define EVENT_TYPE_MAX 9   /* highest event_type_t value + 1 */

/* Bitmask values for filter_t.event_mask / argus_cfg_t event selection */
#define TRACE_EXEC    (1 << EVENT_EXEC)
#define TRACE_OPEN    (1 << EVENT_OPEN)
#define TRACE_EXIT    (1 << EVENT_EXIT)
#define TRACE_CONNECT (1 << EVENT_CONNECT)
#define TRACE_UNLINK  (1 << EVENT_UNLINK)
#define TRACE_RENAME  (1 << EVENT_RENAME)
#define TRACE_CHMOD   (1 << EVENT_CHMOD)
#define TRACE_BIND    (1 << EVENT_BIND)
#define TRACE_PTRACE  (1 << EVENT_PTRACE)
#define TRACE_ALL     (TRACE_EXEC | TRACE_OPEN | TRACE_EXIT | TRACE_CONNECT | \
                       TRACE_UNLINK | TRACE_RENAME | TRACE_CHMOD | \
                       TRACE_BIND | TRACE_PTRACE)

typedef struct event {
    /* ── common fields ─────────────────────────────────── */
    uint64_t     duration_ns;
    event_type_t type;
    int          pid;
    int          ppid;
    uint32_t     uid;
    uint32_t     gid;
    bool         success;
    char         comm[16];

    /* ── EVENT_EXEC / EVENT_OPEN ────────────────────────── */
    char         filename[128];

    /* ── EVENT_EXEC only ────────────────────────────────── */
    char         args[256];   /* space-separated argv[1..N] */

    /* ── EVENT_EXIT only ────────────────────────────────── */
    int          exit_code;   /* raw kernel exit_code >> 8  */

    /* ── EVENT_CONNECT / EVENT_BIND ─────────────────────────── */
    uint8_t      family;      /* AF_INET (2) or AF_INET6 (10)              */
    uint16_t     dport;       /* dest port (CONNECT) or local port (BIND)  */
    uint8_t      daddr[16];   /* dest/local addr; IPv4 in first 4 bytes    */

    /* ── EVENT_CHMOD ─────────────────────────────────────────── */
    uint32_t     mode;        /* new permission bits                        */

    /* ── EVENT_PTRACE ───────────────────────────────────────── */
    int          ptrace_req;  /* ptrace request number                      */
    int          target_pid;  /* PID being traced                           */

    /* ── container / cgroup ─────────────────────────────────── */
    char         cgroup[64];  /* leaf cgroup name; empty string on host     */
} event_t;

/*
 * BPF filter configuration — written by userspace into config_map[0],
 * read by every BPF handler via should_drop().
 */
typedef struct argus_config {
    uint8_t  filter_pid_active;    /* 1 = only pass PIDs in filter_pids   */
    uint8_t  filter_comm_active;   /* 1 = only pass comms in filter_comms */
    uint8_t  filter_follow_active; /* 1 = pass PIDs in follow_pids tree   */
    uint8_t  pad[1];
    uint32_t rate_limit_per_comm;  /* 0 = disabled; N = max events/sec/comm */
} argus_config_t;

#endif /* __ARGUS_H */
