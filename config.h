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
    int      ring_buffer_kb;    /* ring buffer size; default 256           */
    int      summary_interval;  /* 0 = per-event output, N = N-second roll */
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
