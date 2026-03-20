#ifndef __OUTPUT_H
#define __OUTPUT_H

#include <stdint.h>
#include "argus.h"

typedef enum {
    OUTPUT_TEXT = 0,
    OUTPUT_JSON = 1,
} output_fmt_t;

typedef struct {
    int  pid;                  /* 0   = no filter                          */
    char comm[16];             /* ""  = no filter                          */
    char path[128];            /* ""  = include filter (substring match)   */
    char excludes[8][128];     /* path prefixes excluded from OPEN events  */
    int  exclude_count;
    int  event_mask;           /* TRACE_* bitmask; 0 treated as TRACE_ALL  */
} filter_t;

/* Call once at startup before any print_event / event_matches calls */
void output_init(output_fmt_t fmt, const filter_t *filter);

/* Hot-swap the active filter (used on SIGHUP config reload) */
void output_update_filter(const filter_t *filter);

/* Print column headers (text mode only; no-op in JSON and summary modes) */
void print_header(const char *backend);

/* Returns 1 if the event passes all active filters, 0 to drop it */
int  event_matches(const event_t *e);

/* Emit one event (or accumulate it in summary mode) */
void print_event(const event_t *e);

/*
 * Report dropped events.
 * Text: warning to stderr. JSON: {"type":"DROP",...} inline.
 * Summary mode: accumulates the count and shows it in the next flush.
 */
void print_drops(uint64_t count);

/*
 * Enable summary mode. interval_secs > 0 activates rolling summaries;
 * 0 disables. Must be called after output_init().
 */
void output_set_summary(int interval_secs);

/*
 * Call after each ring_buffer__poll() tick.
 * In summary mode, flushes the summary when the interval has elapsed.
 * drop_delta is new drops since the last check (pass 0 if not applicable).
 */
void output_summary_tick(uint64_t drop_delta);

#endif /* __OUTPUT_H */
