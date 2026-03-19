#ifndef __OUTPUT_H
#define __OUTPUT_H

#include "argus.h"

typedef enum {
    OUTPUT_TEXT = 0,
    OUTPUT_JSON = 1,
} output_fmt_t;

typedef struct {
    int  pid;        /* 0   = no filter */
    char comm[16];   /* ""  = no filter */
    char path[128];  /* ""  = no filter */
} filter_t;

/* Call once at startup before any print_event / event_matches calls */
void output_init(output_fmt_t fmt, const filter_t *filter);

/* Print column headers (text mode only; no-op for JSON) */
void print_header(const char *backend);

/* Returns 1 if the event passes all active filters, 0 to drop it */
int  event_matches(const event_t *e);

/* Emit one event in the configured format */
void print_event(const event_t *e);

/*
 * Report that 'count' events were dropped by the kernel ring buffer.
 * Text mode: warning to stderr.
 * JSON mode: {"type":"DROP","count":<n>} to stdout so consumers see it inline.
 */
void print_drops(uint64_t count);

#endif /* __OUTPUT_H */
