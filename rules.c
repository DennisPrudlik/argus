#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include "rules.h"
#include "output.h"
#include "argus.h"

#define RULES_MAX 64

typedef enum {
    SEV_INFO     = 0,
    SEV_LOW      = 1,
    SEV_MEDIUM   = 2,
    SEV_HIGH     = 3,
    SEV_CRITICAL = 4,
} severity_t;

static const char *sev_names[] = {
    [SEV_INFO]     = "info",
    [SEV_LOW]      = "low",
    [SEV_MEDIUM]   = "medium",
    [SEV_HIGH]     = "high",
    [SEV_CRITICAL] = "critical",
};

/* syslog priorities indexed by severity_t */
static const int sev_priority[] = {
    LOG_INFO, LOG_NOTICE, LOG_WARNING, LOG_WARNING, LOG_CRIT,
};

typedef struct {
    char       name[64];
    char       message[256];
    severity_t severity;
    int        event_type;        /* -1 = any; otherwise EVENT_* value */
    char       comm[16];          /* "" = any */
    int        uid;               /* -1 = any */
    char       path_contains[128];/* "" = any */
    uint32_t   mode_mask;         /* 0 = skip; flag if (mode & mask) != 0 */
} rule_t;

static rule_t g_rules[RULES_MAX];
static int    g_rule_count = 0;

int rules_count(void) { return g_rule_count; }

void rules_free(void)
{
    g_rule_count = 0;
    memset(g_rules, 0, sizeof(g_rules));
}

/* ── minimal JSON parser ─────────────────────────────────────────────────── */

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

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

static const char *parse_int(const char *p, int *out)
{
    p = skip_ws(p);
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    if (*p < '0' || *p > '9') return p;
    *out = 0;
    while (*p >= '0' && *p <= '9') { *out = *out * 10 + (*p - '0'); p++; }
    if (neg) *out = -*out;
    return p;
}

static const char *past_colon(const char *p)
{
    p = skip_ws(p);
    if (*p == ':') p++;
    return skip_ws(p);
}

static severity_t parse_severity(const char *s)
{
    if (strcmp(s, "low")      == 0) return SEV_LOW;
    if (strcmp(s, "medium")   == 0) return SEV_MEDIUM;
    if (strcmp(s, "high")     == 0) return SEV_HIGH;
    if (strcmp(s, "critical") == 0) return SEV_CRITICAL;
    return SEV_INFO;
}

static int parse_event_type_str(const char *s)
{
    if (strcmp(s, "EXEC")    == 0) return EVENT_EXEC;
    if (strcmp(s, "OPEN")    == 0) return EVENT_OPEN;
    if (strcmp(s, "EXIT")    == 0) return EVENT_EXIT;
    if (strcmp(s, "CONNECT") == 0) return EVENT_CONNECT;
    if (strcmp(s, "UNLINK")  == 0) return EVENT_UNLINK;
    if (strcmp(s, "RENAME")  == 0) return EVENT_RENAME;
    if (strcmp(s, "CHMOD")   == 0) return EVENT_CHMOD;
    if (strcmp(s, "BIND")    == 0) return EVENT_BIND;
    if (strcmp(s, "PTRACE")  == 0) return EVENT_PTRACE;
    return -1;
}

/* ── rules_load ──────────────────────────────────────────────────────────── */

int rules_load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "warning: rules file not found: %s\n", path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 1048576) { fclose(f); return -2; }

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return -2; }
    if (fread(buf, 1, sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -2;
    }
    buf[sz] = '\0';
    fclose(f);

    const char *p = skip_ws(buf);
    if (*p != '[') { free(buf); return -2; }
    p++;

    while (*p && *p != ']' && g_rule_count < RULES_MAX) {
        p = skip_ws(p);
        if (*p != '{') { p++; continue; }
        p++;

        rule_t *r = &g_rules[g_rule_count];
        r->event_type = -1;
        r->uid        = -1;

        while (*p && *p != '}') {
            p = skip_ws(p);
            if (*p != '"') { p++; continue; }

            char key[64] = {};
            p = parse_str(p, key, sizeof(key));
            p = past_colon(p);

            if (strcmp(key, "name") == 0)
                p = parse_str(p, r->name, sizeof(r->name));
            else if (strcmp(key, "message") == 0)
                p = parse_str(p, r->message, sizeof(r->message));
            else if (strcmp(key, "severity") == 0) {
                char sv[16] = {};
                p = parse_str(p, sv, sizeof(sv));
                r->severity = parse_severity(sv);
            }
            else if (strcmp(key, "type") == 0) {
                char tv[16] = {};
                p = parse_str(p, tv, sizeof(tv));
                r->event_type = parse_event_type_str(tv);
            }
            else if (strcmp(key, "comm") == 0)
                p = parse_str(p, r->comm, sizeof(r->comm));
            else if (strcmp(key, "path_contains") == 0)
                p = parse_str(p, r->path_contains, sizeof(r->path_contains));
            else if (strcmp(key, "uid") == 0)
                p = parse_int(p, &r->uid);
            else if (strcmp(key, "mode_mask") == 0) {
                int v = 0;
                p = parse_int(p, &v);
                r->mode_mask = (uint32_t)v;
            }

            p = skip_ws(p);
            if (*p == ',') p++;
        }
        if (*p == '}') p++;

        if (r->name[0])
            g_rule_count++;

        p = skip_ws(p);
        if (*p == ',') p++;
    }

    free(buf);
    return g_rule_count;
}

/* ── message template expansion ─────────────────────────────────────────── */

static void expand_message(const rule_t *r, const event_t *e,
                           char *out, size_t outsize)
{
    const char *src = r->message;
    size_t pos = 0;

    while (*src && pos + 1 < outsize) {
        if (*src != '{') {
            out[pos++] = *src++;
            continue;
        }
        const char *end = src + 1;
        while (*end && *end != '}') end++;
        if (!*end) { out[pos++] = *src++; continue; }

        size_t varlen = (size_t)(end - src - 1);
        char var[32] = {};
        if (varlen < sizeof(var))
            memcpy(var, src + 1, varlen);

        char val[128] = {};
        if      (strcmp(var, "comm")       == 0) snprintf(val, sizeof(val), "%s",  e->comm);
        else if (strcmp(var, "pid")        == 0) snprintf(val, sizeof(val), "%d",  e->pid);
        else if (strcmp(var, "ppid")       == 0) snprintf(val, sizeof(val), "%d",  e->ppid);
        else if (strcmp(var, "uid")        == 0) snprintf(val, sizeof(val), "%u",  e->uid);
        else if (strcmp(var, "gid")        == 0) snprintf(val, sizeof(val), "%u",  e->gid);
        else if (strcmp(var, "cgroup")     == 0) snprintf(val, sizeof(val), "%s",  e->cgroup[0] ? e->cgroup : "-");
        else if (strcmp(var, "filename")   == 0) snprintf(val, sizeof(val), "%s",  e->filename);
        else if (strcmp(var, "args")       == 0) snprintf(val, sizeof(val), "%s",  e->args);
        else if (strcmp(var, "new_path")   == 0) snprintf(val, sizeof(val), "%s",  e->args);
        else if (strcmp(var, "mode")       == 0) snprintf(val, sizeof(val), "%o",  e->mode);
        else if (strcmp(var, "target_pid") == 0) snprintf(val, sizeof(val), "%d",  e->target_pid);
        else if (strcmp(var, "ptrace_req") == 0) snprintf(val, sizeof(val), "%d",  e->ptrace_req);
        else if (strcmp(var, "dport")      == 0) snprintf(val, sizeof(val), "%u",  e->dport);
        else if (strcmp(var, "lport")      == 0) snprintf(val, sizeof(val), "%u",  e->dport);
        else if (strcmp(var, "daddr") == 0 || strcmp(var, "laddr") == 0)
            inet_ntop(e->family == 2 ? AF_INET : AF_INET6, e->daddr, val, sizeof(val));
        else
            snprintf(val, sizeof(val), "{%s}", var);  /* unknown: keep literal */

        size_t vl = strlen(val);
        if (pos + vl >= outsize) vl = outsize - pos - 1;
        memcpy(out + pos, val, vl);
        pos += vl;
        src = end + 1;
    }
    out[pos] = '\0';
}

/* ── rule matching ───────────────────────────────────────────────────────── */

static int rule_matches(const rule_t *r, const event_t *e)
{
    if (r->event_type >= 0 && (int)e->type != r->event_type)
        return 0;
    if (r->comm[0] && strncmp(e->comm, r->comm, sizeof(r->comm)) != 0)
        return 0;
    if (r->uid >= 0 && (int)e->uid != r->uid)
        return 0;
    if (r->path_contains[0] && strstr(e->filename, r->path_contains) == NULL)
        return 0;
    if (r->mode_mask && e->type == EVENT_CHMOD &&
        (e->mode & r->mode_mask) == 0)
        return 0;
    return 1;
}

/* ── JSON string escape (writes to FILE) ─────────────────────────────────── */

static void write_json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  fprintf(f, "\\\""); break;
        case '\\': fprintf(f, "\\\\"); break;
        case '\n': fprintf(f, "\\n");  break;
        case '\r': fprintf(f, "\\r");  break;
        case '\t': fprintf(f, "\\t");  break;
        default:
            if (*p < 0x20) fprintf(f, "\\u%04x", *p);
            else fputc(*p, f);
            break;
        }
    }
    fputc('"', f);
}

/* ── alert emission ──────────────────────────────────────────────────────── */

static void emit_alert(const rule_t *r, const event_t *e)
{
    char msg[512];
    expand_message(r, e, msg, sizeof(msg));
    const char *sev = sev_names[r->severity];
    output_fmt_t fmt = output_get_fmt();

    if (fmt == OUTPUT_JSON) {
        FILE *out = output_stream();
        fprintf(out, "{\"type\":\"ALERT\",\"severity\":");
        write_json_str(out, sev);
        fprintf(out, ",\"rule\":");
        write_json_str(out, r->name);
        fprintf(out, ",\"pid\":%d,\"ppid\":%d,\"uid\":%u,\"comm\":",
                e->pid, e->ppid, e->uid);
        write_json_str(out, e->comm);
        fprintf(out, ",\"message\":");
        write_json_str(out, msg);
        fputs("}\n", out);
    } else if (fmt == OUTPUT_SYSLOG) {
        syslog(sev_priority[r->severity],
               "ALERT:%s rule=%s pid=%d comm=%s %s",
               sev, r->name, e->pid, e->comm, msg);
    } else {
        fprintf(stderr, "[ALERT:%s] %s: %s\n", sev, r->name, msg);
    }
}

/* ── public API ──────────────────────────────────────────────────────────── */

void rules_check(const event_t *e)
{
    for (int i = 0; i < g_rule_count; i++)
        if (rule_matches(&g_rules[i], e))
            emit_alert(&g_rules[i], e);
}
