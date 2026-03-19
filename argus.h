#ifndef __ARGUS_H
#define __ARGUS_H

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
} event_type_t;

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

    /* ── EVENT_CONNECT only ─────────────────────────────── */
    uint8_t      family;      /* AF_INET (2) or AF_INET6 (10) */
    uint16_t     dport;       /* destination port, host byte order */
    uint8_t      daddr[16];   /* IPv4 in first 4 bytes, IPv6 uses all 16 */
} event_t;

/*
 * BPF filter configuration — written by userspace into config_map[0],
 * read by every BPF handler via should_drop().
 */
typedef struct argus_config {
    uint8_t filter_pid_active;   /* 1 = only pass PIDs in filter_pids  */
    uint8_t filter_comm_active;  /* 1 = only pass comms in filter_comms */
} argus_config_t;

#endif /* __ARGUS_H */
