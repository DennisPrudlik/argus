#ifndef __CONFIG_H
#define __CONFIG_H

#include "output.h"

/*
 * Full runtime configuration for argus.
 * Populated from the config file first, then overridden by CLI flags.
 * filter_t holds the event-matching rules; the rest are operational settings.
 */
typedef struct {
    filter_t filter;
    int      ring_buffer_kb;        /* ring buffer size; default 256           */
    int      summary_interval;      /* 0 = per-event output, N = N-second roll */
    uint32_t rate_limit_per_comm;   /* 0 = disabled; N = max events/sec/comm   */
    int      use_syslog;            /* 1 = emit to syslog(LOG_DAEMON)          */
    int      follow_pid;            /* 0 = off; N = trace PID + descendants    */
    char     output_path[256];      /* "" = stdout; else write events to file  */
    char     rules_path[256];       /* "" = no rules; else load rules JSON     */
    char     forward_addr[256];     /* "" = off; else "host:port" to forward   */
    int      forward_tls;           /* 1 = TLS with cert verification           */
    int      forward_tls_noverify;  /* 1 = TLS without cert verification        */
    char     baseline_path[256];    /* "" = off; else load profile for anomaly */
    char     baseline_out[256];     /* "" = off; else write learnt profile     */
    int      baseline_learn_secs;   /* 0 = detect; >0 = learn for N seconds   */
} argus_cfg_t;

/* Fill cfg with safe defaults (no filters, 256KB ring buffer, no summary) */
void cfg_defaults(argus_cfg_t *cfg);

/*
 * Load a JSON config file into cfg.
 * Config file values are merged in — only keys present in the file are set.
 * CLI flags should be applied after this call to override file values.
 *
 * Returns:
 *   0   success
 *  -1   file not found (not an error — just use defaults)
 *  -2   file read / parse error (logged to stderr)
 */
int cfg_load(const char *path, argus_cfg_t *cfg);

#endif /* __CONFIG_H */
