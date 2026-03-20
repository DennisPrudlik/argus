#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "config.h"
#include "argus.h"

/* ── defaults ───────────────────────────────────────────────────────────── */

void cfg_defaults(argus_cfg_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->filter.event_mask  = TRACE_ALL;
    cfg->ring_buffer_kb     = 256;
    cfg->summary_interval   = 0;
}

/* ── minimal JSON parser ────────────────────────────────────────────────── */
/*
 * Only handles the flat schema written by argus — no nesting beyond one-level
 * arrays. Ignores unknown keys. Errors leave the field at its current value.
 */

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Parse a JSON string starting at the opening '"'. Returns ptr after '"'. */
static const char *parse_str(const char *p, char *out, size_t max)
{
    p = skip_ws(p);
    if (*p != '"') return p;
    p++;
    size_t i = 0;
    while (*p && *p != '"') {
        if (*p == '\\') { p++; if (!*p) break; }
        if (i < max - 1) out[i++] = *p;
        p++;
    }
    out[i] = '\0';
    return *p == '"' ? p + 1 : p;
}

/* Parse a JSON integer (no leading minus yet — all our ints are >= 0). */
static const char *parse_int(const char *p, int *out)
{
    p = skip_ws(p);
    if (*p < '0' || *p > '9') return p;
    *out = 0;
    while (*p >= '0' && *p <= '9') { *out = *out * 10 + (*p - '0'); p++; }
    return p;
}

/* Parse true/false into *out (1/0). */
static const char *parse_bool(const char *p, int *out)
{
    p = skip_ws(p);
    if (strncmp(p, "true",  4) == 0) { *out = 1; return p + 4; }
    if (strncmp(p, "false", 5) == 0) { *out = 0; return p + 5; }
    return p;
}

/* Advance past ':' and optional whitespace. */
static const char *past_colon(const char *p)
{
    p = skip_ws(p);
    if (*p == ':') p++;
    return skip_ws(p);
}

/* ── event_types array parser ───────────────────────────────────────────── */

static int parse_event_types(const char *p, int *mask)
{
    *mask = 0;
    p = skip_ws(p);
    if (*p != '[') return 0;
    p++;
    while (*p && *p != ']') {
        char tok[16] = {};
        p = parse_str(p, tok, sizeof(tok));
        if      (strcmp(tok, "EXEC")    == 0) *mask |= TRACE_EXEC;
        else if (strcmp(tok, "OPEN")    == 0) *mask |= TRACE_OPEN;
        else if (strcmp(tok, "EXIT")    == 0) *mask |= TRACE_EXIT;
        else if (strcmp(tok, "CONNECT") == 0) *mask |= TRACE_CONNECT;
        p = skip_ws(p);
        if (*p == ',') p++;
        p = skip_ws(p);
    }
    return 1;
}

/* ── exclude_paths array parser ─────────────────────────────────────────── */

static void parse_exclude_paths(const char *p, filter_t *f)
{
    p = skip_ws(p);
    if (*p != '[') return;
    p++;
    while (*p && *p != ']') {
        if (f->exclude_count >= 8) break;
        p = parse_str(p, f->excludes[f->exclude_count], 128);
        if (f->excludes[f->exclude_count][0])
            f->exclude_count++;
        p = skip_ws(p);
        if (*p == ',') p++;
        p = skip_ws(p);
    }
}

/* ── cfg_load ───────────────────────────────────────────────────────────── */

int cfg_load(const char *path, argus_cfg_t *cfg)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    /* Read entire file */
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 65536) { fclose(f); return -2; }

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return -2; }
    if (fread(buf, 1, sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -2;
    }
    buf[sz] = '\0';
    fclose(f);

    /* Scan for known keys */
    const char *p = buf;
    while (*p) {
        p = skip_ws(p);
        if (*p != '"') { p++; continue; }

        char key[64] = {};
        p = parse_str(p, key, sizeof(key));
        p = past_colon(p);

        if      (strcmp(key, "pid")  == 0)
            p = parse_int(p, &cfg->filter.pid);
        else if (strcmp(key, "comm") == 0)
            p = parse_str(p, cfg->filter.comm, sizeof(cfg->filter.comm));
        else if (strcmp(key, "path") == 0)
            p = parse_str(p, cfg->filter.path, sizeof(cfg->filter.path));
        else if (strcmp(key, "json") == 0) {
            int v = 0;
            p = parse_bool(p, &v);
            /* stored separately by caller — mark via ring_buffer_kb sentinel? */
            (void)v; /* caller reads this via the fmt field; skip for now */
        }
        else if (strcmp(key, "ring_buffer_kb") == 0)
            p = parse_int(p, &cfg->ring_buffer_kb);
        else if (strcmp(key, "summary_interval") == 0)
            p = parse_int(p, &cfg->summary_interval);
        else if (strcmp(key, "event_types") == 0)
            parse_event_types(p, &cfg->filter.event_mask);
        else if (strcmp(key, "exclude_paths") == 0)
            parse_exclude_paths(p, &cfg->filter);

        /* advance past current value to next key */
        while (*p && *p != ',' && *p != '}') p++;
        if (*p == ',') p++;
    }

    free(buf);
    return 0;
}
