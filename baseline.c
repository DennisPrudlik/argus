#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <syslog.h>
#include "baseline.h"
#include "output.h"
#include "argus.h"

#define BL_MAX_COMMS    64
#define BL_MAX_ENTRIES  256   /* max strings per set per comm */
#define BL_MAX_STR      128

/* ── string set ──────────────────────────────────────────────────────────── */

typedef struct {
    char   s[BL_MAX_ENTRIES][BL_MAX_STR];
    int    count;
} str_set_t;

static int set_contains(const str_set_t *ss, const char *val)
{
    for (int i = 0; i < ss->count; i++)
        if (strncmp(ss->s[i], val, BL_MAX_STR - 1) == 0)
            return 1;
    return 0;
}

static void set_add(str_set_t *ss, const char *val)
{
    if (!val || !val[0] || ss->count >= BL_MAX_ENTRIES)
        return;
    if (set_contains(ss, val))
        return;
    strncpy(ss->s[ss->count], val, BL_MAX_STR - 1);
    ss->s[ss->count][BL_MAX_STR - 1] = '\0';
    ss->count++;
}

/* ── per-comm profile ────────────────────────────────────────────────────── */

typedef struct {
    char      comm[16];
    str_set_t exec_targets;   /* filenames seen in EXEC events   */
    str_set_t connect_dests;  /* "addr:port" seen in CONNECT     */
    str_set_t open_paths;     /* filenames seen in OPEN events   */
} comm_profile_t;

/* ── module state ────────────────────────────────────────────────────────── */

static comm_profile_t g_profiles[BL_MAX_COMMS];
static int            g_profile_count = 0;

static int    g_learning  = 0;       /* 1 while in active learning window   */
static time_t g_learn_end = 0;       /* epoch when learning window closes   */
static char   g_out_path[256] = {};  /* file to write the learnt profile to */

static int    g_detecting = 0;       /* 1 when a profile has been loaded    */

/* ── helpers ─────────────────────────────────────────────────────────────── */

static comm_profile_t *find_or_create(const char *comm)
{
    for (int i = 0; i < g_profile_count; i++)
        if (strncmp(g_profiles[i].comm, comm, 15) == 0)
            return &g_profiles[i];
    if (g_profile_count >= BL_MAX_COMMS)
        return NULL;
    comm_profile_t *cp = &g_profiles[g_profile_count++];
    memset(cp, 0, sizeof(*cp));
    strncpy(cp->comm, comm, 15);
    cp->comm[15] = '\0';
    return cp;
}

static comm_profile_t *find_profile(const char *comm)
{
    for (int i = 0; i < g_profile_count; i++)
        if (strncmp(g_profiles[i].comm, comm, 15) == 0)
            return &g_profiles[i];
    return NULL;
}

/* ── alert emission ──────────────────────────────────────────────────────── */

static void emit_anomaly(const event_t *e, const char *what, const char *value)
{
    output_fmt_t fmt = output_get_fmt();
    if (fmt == OUTPUT_JSON) {
        FILE *out = output_stream();
        fprintf(out,
                "{\"type\":\"ANOMALY\",\"severity\":\"HIGH\","
                "\"comm\":\"%s\",\"pid\":%d,\"what\":\"%s\",\"value\":\"%s\"}\n",
                e->comm, e->pid, what, value);
    } else if (fmt == OUTPUT_SYSLOG) {
        syslog(LOG_WARNING,
               "ANOMALY comm=%s pid=%d what=%s value=%s",
               e->comm, e->pid, what, value);
    } else {
        fprintf(stderr,
                "[ANOMALY] comm=%-16s pid=%-6d  %s: %s\n",
                e->comm, e->pid, what, value);
    }
}

/* ── public API ─────────────────────────────────────────────────────────── */

int baseline_learn_init(const char *out_path, int secs)
{
    if (!out_path || secs <= 0)
        return -1;
    memset(g_profiles, 0, sizeof(g_profiles));
    g_profile_count = 0;
    strncpy(g_out_path, out_path, sizeof(g_out_path) - 1);
    g_learn_end = time(NULL) + secs;
    g_learning  = 1;
    g_detecting = 0;
    return 0;
}

void baseline_learn(const event_t *e)
{
    if (!g_learning)
        return;

    /* Window expired — flush automatically */
    if (time(NULL) >= g_learn_end) {
        baseline_flush();
        return;
    }

    comm_profile_t *cp = find_or_create(e->comm);
    if (!cp)
        return;

    switch (e->type) {
    case EVENT_EXEC:
        set_add(&cp->exec_targets, e->filename);
        break;
    case EVENT_OPEN:
        if (e->success)
            set_add(&cp->open_paths, e->filename);
        break;
    case EVENT_CONNECT: {
        char key[64] = {};
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(e->family == 2 ? AF_INET : AF_INET6, e->daddr, ip, sizeof(ip));
        snprintf(key, sizeof(key), "%s:%u", ip, e->dport);
        set_add(&cp->connect_dests, key);
        break;
    }
    default:
        break;
    }
}

int baseline_learning(void)
{
    if (!g_learning)
        return 0;
    if (time(NULL) >= g_learn_end) {
        baseline_flush();
        return 0;
    }
    return 1;
}

/* ── JSON serialiser ─────────────────────────────────────────────────────── */

static void write_str_set(FILE *f, const str_set_t *ss)
{
    fputc('[', f);
    for (int i = 0; i < ss->count; i++) {
        /* Basic JSON string escaping */
        fputc('"', f);
        for (const char *p = ss->s[i]; *p; p++) {
            if (*p == '"' || *p == '\\')
                fputc('\\', f);
            fputc(*p, f);
        }
        fputc('"', f);
        if (i + 1 < ss->count)
            fputc(',', f);
    }
    fputc(']', f);
}

void baseline_flush(void)
{
    if (!g_learning || !g_out_path[0])
        return;
    g_learning = 0;

    FILE *f = fopen(g_out_path, "w");
    if (!f) {
        perror("baseline: could not write profile");
        return;
    }

    fputs("{\"version\":1,\"comms\":{", f);
    for (int i = 0; i < g_profile_count; i++) {
        comm_profile_t *cp = &g_profiles[i];
        if (i > 0) fputc(',', f);
        fprintf(f, "\"%s\":{", cp->comm);
        fputs("\"exec_targets\":",  f); write_str_set(f, &cp->exec_targets);
        fputs(",\"connect_dests\":", f); write_str_set(f, &cp->connect_dests);
        fputs(",\"open_paths\":",   f); write_str_set(f, &cp->open_paths);
        fputc('}', f);
    }
    fputs("}}\n", f);
    fclose(f);

    fprintf(stderr, "info: baseline profile written to %s (%d comm(s))\n",
            g_out_path, g_profile_count);
}

/* ── minimal JSON loader ─────────────────────────────────────────────────── */
/*
 * Parses the profile format written by baseline_flush().
 * Only handles the specific schema above — not a general JSON parser.
 */

static const char *bl_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static const char *bl_parse_str(const char *p, char *out, size_t max)
{
    p = bl_skip_ws(p);
    if (*p != '"') return p;
    p++;
    size_t i = 0;
    while (*p && *p != '"') {
        if (*p == '\\') { p++; if (!*p) break; }
        if (i < max - 1) out[i++] = *p;
        p++;
    }
    out[i] = '\0';
    return (*p == '"') ? p + 1 : p;
}

/* Parse ["str1","str2",...] into a str_set_t */
static const char *bl_parse_str_array(const char *p, str_set_t *ss)
{
    p = bl_skip_ws(p);
    if (*p != '[') return p;
    p++;
    while (*p && *p != ']') {
        char tok[BL_MAX_STR] = {};
        p = bl_parse_str(p, tok, sizeof(tok));
        if (tok[0]) set_add(ss, tok);
        p = bl_skip_ws(p);
        if (*p == ',') p++;
        p = bl_skip_ws(p);
    }
    return (*p == ']') ? p + 1 : p;
}

int baseline_load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 1048576) { fclose(f); return -1; }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -1;
    }
    buf[sz] = '\0';
    fclose(f);

    memset(g_profiles, 0, sizeof(g_profiles));
    g_profile_count = 0;
    g_learning  = 0;
    g_detecting = 0;

    /*
     * Simple scan: find each comm key inside "comms":{...},
     * then parse its exec_targets, connect_dests, open_paths arrays.
     */
    const char *p = buf;
    while (*p) {
        p = bl_skip_ws(p);
        if (*p != '"') { p++; continue; }

        char key[64] = {};
        p = bl_parse_str(p, key, sizeof(key));
        p = bl_skip_ws(p);
        if (*p == ':') p++;
        p = bl_skip_ws(p);

        /* Skip top-level keys ("version", "comms") */
        if (strcmp(key, "version") == 0 || strcmp(key, "comms") == 0) {
            continue;
        }

        /* Assume any other string key is a comm name inside "comms" */
        if (*p == '{') {
            comm_profile_t *cp = find_or_create(key);
            p++;  /* skip '{' */
            while (*p && *p != '}') {
                p = bl_skip_ws(p);
                if (*p != '"') { p++; continue; }
                char field[64] = {};
                p = bl_parse_str(p, field, sizeof(field));
                p = bl_skip_ws(p);
                if (*p == ':') p++;
                if (cp) {
                    if (strcmp(field, "exec_targets") == 0)
                        p = bl_parse_str_array(p, &cp->exec_targets);
                    else if (strcmp(field, "connect_dests") == 0)
                        p = bl_parse_str_array(p, &cp->connect_dests);
                    else if (strcmp(field, "open_paths") == 0)
                        p = bl_parse_str_array(p, &cp->open_paths);
                }
                p = bl_skip_ws(p);
                if (*p == ',') p++;
            }
        }

        while (*p && *p != ',' && *p != '}' && *p != '{') p++;
        if (*p == ',' ) p++;
    }

    free(buf);
    g_detecting = (g_profile_count > 0) ? 1 : 0;
    return g_profile_count;
}

int baseline_check(const event_t *e)
{
    if (!g_detecting)
        return 0;

    comm_profile_t *cp = find_profile(e->comm);
    if (!cp)
        return 0;   /* comm not in profile — no opinion */

    switch (e->type) {
    case EVENT_EXEC:
        if (cp->exec_targets.count > 0 &&
            !set_contains(&cp->exec_targets, e->filename)) {
            emit_anomaly(e, "new_exec_target", e->filename);
            return 1;
        }
        break;
    case EVENT_OPEN:
        if (e->success && cp->open_paths.count > 0 &&
            !set_contains(&cp->open_paths, e->filename)) {
            emit_anomaly(e, "new_open_path", e->filename);
            return 1;
        }
        break;
    case EVENT_CONNECT: {
        if (cp->connect_dests.count > 0) {
            char key[64] = {};
            char ip[INET6_ADDRSTRLEN] = {};
            inet_ntop(e->family == 2 ? AF_INET : AF_INET6,
                      e->daddr, ip, sizeof(ip));
            snprintf(key, sizeof(key), "%s:%u", ip, e->dport);
            if (!set_contains(&cp->connect_dests, key)) {
                emit_anomaly(e, "new_connect_dest", key);
                return 1;
            }
        }
        break;
    }
    default:
        break;
    }
    return 0;
}

void baseline_free(void)
{
    memset(g_profiles, 0, sizeof(g_profiles));
    g_profile_count = 0;
    g_learning  = 0;
    g_detecting = 0;
    g_learn_end = 0;
    g_out_path[0] = '\0';
}
