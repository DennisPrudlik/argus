#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <syslog.h>
#include "output.h"
#include "lineage.h"
#include "argus.h"
#include "dns.h"

#define LINEAGE_BUF 256

static output_fmt_t g_fmt    = OUTPUT_TEXT;
static filter_t     g_filter = {0};
static FILE        *g_out    = NULL;   /* NULL = use stdout */

#define OUT (g_out ? g_out : stdout)

void output_init(output_fmt_t fmt, const filter_t *filter)
{
    g_fmt = fmt;
    if (filter)
        g_filter = *filter;
    if (fmt == OUTPUT_SYSLOG)
        openlog("argus", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

void output_update_filter(const filter_t *filter)
{
    if (filter)
        g_filter = *filter;
}

void output_set_file(FILE *f)
{
    g_out = f;
}

FILE *output_stream(void)
{
    return g_out ? g_out : stdout;
}

output_fmt_t output_get_fmt(void)
{
    return g_fmt;
}

void output_fini(void)
{
    if (g_fmt == OUTPUT_SYSLOG)
        closelog();
}

/* ── filtering ──────────────────────────────────────────────────────────── */

int event_matches(const event_t *e)
{
    /* event type mask (0 == TRACE_ALL) */
    if (g_filter.event_mask) {
        int bit = 1 << (int)e->type;
        if (!(g_filter.event_mask & bit))
            return 0;
    }

    if (g_filter.pid != 0 && e->pid != g_filter.pid)
        return 0;

    if (g_filter.comm[0] != '\0' &&
        strncmp(e->comm, g_filter.comm, sizeof(g_filter.comm)) != 0)
        return 0;

    if (g_filter.path[0] != '\0' &&
        strstr(e->filename, g_filter.path) == NULL)
        return 0;

    /* exclude paths — applied to all file events */
    if ((e->type == EVENT_OPEN   || e->type == EVENT_UNLINK ||
         e->type == EVENT_RENAME || e->type == EVENT_CHMOD) &&
        g_filter.exclude_count > 0) {
        for (int i = 0; i < g_filter.exclude_count; i++) {
            if (g_filter.excludes[i][0] &&
                strncmp(e->filename, g_filter.excludes[i],
                        strlen(g_filter.excludes[i])) == 0)
                return 0;
        }
    }

    return 1;
}

/* ── text output ────────────────────────────────────────────────────────── */

void print_header(const char *backend)
{
    if (g_fmt != OUTPUT_TEXT)
        return;

    static const struct { int bit; const char *name; } type_map[] = {
        { TRACE_EXEC,    "EXEC"    }, { TRACE_OPEN,   "OPEN"   },
        { TRACE_EXIT,    "EXIT"    }, { TRACE_CONNECT,"CONNECT"},
        { TRACE_UNLINK,  "UNLINK"  }, { TRACE_RENAME, "RENAME" },
        { TRACE_CHMOD,   "CHMOD"   }, { TRACE_BIND,   "BIND"   },
        { TRACE_PTRACE,  "PTRACE"  },
    };
    int mask = g_filter.event_mask ? g_filter.event_mask : TRACE_ALL;
    fprintf(OUT, "Tracing via %s (", backend);
    int first = 1;
    for (int i = 0; i < 9; i++) {
        if (mask & type_map[i].bit) {
            fprintf(OUT, "%s%s", first ? "" : ",", type_map[i].name);
            first = 0;
        }
    }
    fprintf(OUT, ")... Ctrl-C to stop.\n");

    if (g_filter.pid)
        fprintf(OUT, "  filter: pid=%d\n", g_filter.pid);
    if (g_filter.comm[0])
        fprintf(OUT, "  filter: comm=%s\n", g_filter.comm);
    if (g_filter.path[0])
        fprintf(OUT, "  filter: path=%s\n", g_filter.path);
    for (int i = 0; i < g_filter.exclude_count; i++)
        fprintf(OUT, "  exclude: %s\n", g_filter.excludes[i]);

    if (g_filter.pid || g_filter.comm[0] || g_filter.path[0] ||
        g_filter.exclude_count)
        fputc('\n', OUT);

    fprintf(OUT, "\n%-5s  %-6s  %-6s  %-4s  %-4s  %-16s  %-24s  %-32s  %s\n",
           "TYPE", "PID", "PPID", "UID", "GID", "COMM",
           "CGROUP", "LINEAGE", "DETAIL");
    fprintf(OUT, "%-5s  %-6s  %-6s  %-4s  %-4s  %-16s  %-24s  %-32s  %s\n",
           "-----", "------", "------", "----", "----",
           "----------------", "------------------------",
           "--------------------------------", "------");
}

static void text_event(const event_t *e)
{
    char chain[LINEAGE_BUF];
    lineage_str(e->ppid, chain, sizeof(chain));

    static const char *type_names[] = {
        [EVENT_EXEC]    = "EXEC",  [EVENT_OPEN]    = "OPEN",
        [EVENT_EXIT]    = "EXIT",  [EVENT_CONNECT] = "CONN",
        [EVENT_UNLINK]  = "UNLNK",[EVENT_RENAME]  = "RENM",
        [EVENT_CHMOD]   = "CMOD", [EVENT_BIND]    = "BIND",
        [EVENT_PTRACE]  = "PTRC",
    };
    const char *tname = (e->type < EVENT_TYPE_MAX) ? type_names[e->type] : "?";

    fprintf(OUT, "%-5s  %-6d  %-6d  %-4u  %-4u  %-16s  %-24s  %-32s  ",
           tname, e->pid, e->ppid, e->uid, e->gid, e->comm,
           e->cgroup[0] ? e->cgroup : "-", chain);

    switch (e->type) {
    case EVENT_EXEC:
        fprintf(OUT, "%s %s", e->filename, e->args);
        break;
    case EVENT_OPEN:
        fprintf(OUT, "[%s] %s", e->success ? "OK" : "FAIL", e->filename);
        break;
    case EVENT_EXIT:
        fprintf(OUT, "exit_code=%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        if (strcmp(host, ip) != 0)
            fprintf(OUT, "[%s] %s (%s):%u",
                    e->success ? "OK" : "FAIL", host, ip, e->dport);
        else
            fprintf(OUT, "[%s] %s:%u",
                    e->success ? "OK" : "FAIL", ip, e->dport);
        break;
    }
    case EVENT_UNLINK:
        fprintf(OUT, "[%s] %s", e->success ? "OK" : "FAIL", e->filename);
        break;
    case EVENT_RENAME:
        fprintf(OUT, "[%s] %s -> %s", e->success ? "OK" : "FAIL",
               e->filename, e->args);
        break;
    case EVENT_CHMOD:
        fprintf(OUT, "[%s] %s mode=0%o", e->success ? "OK" : "FAIL",
               e->filename, e->mode);
        break;
    case EVENT_BIND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        if (strcmp(host, ip) != 0)
            fprintf(OUT, "[%s] %s (%s):%u",
                    e->success ? "OK" : "FAIL", host, ip, e->dport);
        else
            fprintf(OUT, "[%s] %s:%u",
                    e->success ? "OK" : "FAIL", ip, e->dport);
        break;
    }
    case EVENT_PTRACE:
        fprintf(OUT, "[%s] req=%d target_pid=%d",
               e->success ? "OK" : "FAIL", e->ptrace_req, e->target_pid);
        break;
    }
    fputc('\n', OUT);
}

/* ── JSON output ────────────────────────────────────────────────────────── */

static void json_str(const char *s)
{
    fputc('"', OUT);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  fprintf(OUT, "\\\""); break;
        case '\\': fprintf(OUT, "\\\\"); break;
        case '\n': fprintf(OUT, "\\n");  break;
        case '\r': fprintf(OUT, "\\r");  break;
        case '\t': fprintf(OUT, "\\t");  break;
        default:
            if (*p < 0x20)
                fprintf(OUT, "\\u%04x", *p);
            else
                fputc(*p, OUT);
            break;
        }
    }
    fputc('"', OUT);
}

static void json_event(const event_t *e)
{
    static const char *type_str[] = {
        [EVENT_EXEC]    = "EXEC",
        [EVENT_OPEN]    = "OPEN",
        [EVENT_EXIT]    = "EXIT",
        [EVENT_CONNECT] = "CONNECT",
        [EVENT_UNLINK]  = "UNLINK",
        [EVENT_RENAME]  = "RENAME",
        [EVENT_CHMOD]   = "CHMOD",
        [EVENT_BIND]    = "BIND",
        [EVENT_PTRACE]  = "PTRACE",
    };

    char chain[LINEAGE_BUF];
    lineage_str(e->ppid, chain, sizeof(chain));

    const char *ts = (e->type < EVENT_TYPE_MAX) ? type_str[e->type] : "UNKNOWN";
    fprintf(OUT, "{\"type\":\"%s\","
           "\"pid\":%d,\"ppid\":%d,"
           "\"uid\":%u,\"gid\":%u,"
           "\"comm\":",
           ts, e->pid, e->ppid, e->uid, e->gid);
    json_str(e->comm);
    fprintf(OUT, ",\"cgroup\":");
    json_str(e->cgroup);
    fprintf(OUT, ",\"lineage\":");
    json_str(chain);

    fprintf(OUT, ",\"duration_ns\":%llu,\"success\":%s",
           (unsigned long long)e->duration_ns,
           e->success ? "true" : "false");

    switch (e->type) {
    case EVENT_EXEC:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        fprintf(OUT, ",\"args\":");     json_str(e->args);
        break;
    case EVENT_OPEN:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        break;
    case EVENT_EXIT:
        fprintf(OUT, ",\"exit_code\":%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        fprintf(OUT, ",\"family\":%u,\"daddr\":\"%s\",\"hostname\":",
                e->family, ip);
        json_str(host);
        fprintf(OUT, ",\"dport\":%u", e->dport);
        break;
    }
    case EVENT_UNLINK:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        break;
    case EVENT_RENAME:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        fprintf(OUT, ",\"new_path\":"); json_str(e->args);
        break;
    case EVENT_CHMOD:
        fprintf(OUT, ",\"filename\":"); json_str(e->filename);
        fprintf(OUT, ",\"mode\":%u", e->mode);
        break;
    case EVENT_BIND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        fprintf(OUT, ",\"family\":%u,\"laddr\":\"%s\",\"hostname\":",
                e->family, ip);
        json_str(host);
        fprintf(OUT, ",\"lport\":%u", e->dport);
        break;
    }
    case EVENT_PTRACE:
        fprintf(OUT, ",\"ptrace_req\":%d,\"target_pid\":%d",
               e->ptrace_req, e->target_pid);
        break;
    }
    fputs("}\n", OUT);
}

/* ── syslog output ──────────────────────────────────────────────────────── */

static void syslog_event(const event_t *e)
{
    static const char *type_str[] = {
        [EVENT_EXEC]    = "EXEC",    [EVENT_OPEN]    = "OPEN",
        [EVENT_EXIT]    = "EXIT",    [EVENT_CONNECT] = "CONNECT",
        [EVENT_UNLINK]  = "UNLINK",  [EVENT_RENAME]  = "RENAME",
        [EVENT_CHMOD]   = "CHMOD",   [EVENT_BIND]    = "BIND",
        [EVENT_PTRACE]  = "PTRACE",
    };

    char chain[LINEAGE_BUF];
    lineage_str(e->ppid, chain, sizeof(chain));

    const char *ts = (e->type < EVENT_TYPE_MAX) ? type_str[e->type] : "UNKNOWN";
    char detail[256] = {};

    switch (e->type) {
    case EVENT_EXEC:
        snprintf(detail, sizeof(detail), "%s %s", e->filename, e->args);
        break;
    case EVENT_OPEN:
        snprintf(detail, sizeof(detail), "[%s] %s",
                 e->success ? "OK" : "FAIL", e->filename);
        break;
    case EVENT_EXIT:
        snprintf(detail, sizeof(detail), "exit_code=%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        if (strcmp(host, ip) != 0)
            snprintf(detail, sizeof(detail), "[%s] %s (%s):%u",
                     e->success ? "OK" : "FAIL", host, ip, e->dport);
        else
            snprintf(detail, sizeof(detail), "[%s] %s:%u",
                     e->success ? "OK" : "FAIL", ip, e->dport);
        break;
    }
    case EVENT_UNLINK:
        snprintf(detail, sizeof(detail), "[%s] %s",
                 e->success ? "OK" : "FAIL", e->filename);
        break;
    case EVENT_RENAME:
        snprintf(detail, sizeof(detail), "[%s] %s -> %s",
                 e->success ? "OK" : "FAIL", e->filename, e->args);
        break;
    case EVENT_CHMOD:
        snprintf(detail, sizeof(detail), "[%s] %s mode=0%o",
                 e->success ? "OK" : "FAIL", e->filename, e->mode);
        break;
    case EVENT_BIND: {
        int  af = (e->family == 2) ? AF_INET : AF_INET6;
        char ip[INET6_ADDRSTRLEN] = {};
        char host[256] = {};
        inet_ntop(af, e->daddr, ip, sizeof(ip));
        dns_lookup(e->daddr, af, host, sizeof(host));
        if (strcmp(host, ip) != 0)
            snprintf(detail, sizeof(detail), "[%s] %s (%s):%u",
                     e->success ? "OK" : "FAIL", host, ip, e->dport);
        else
            snprintf(detail, sizeof(detail), "[%s] %s:%u",
                     e->success ? "OK" : "FAIL", ip, e->dport);
        break;
    }
    case EVENT_PTRACE:
        snprintf(detail, sizeof(detail), "[%s] req=%d target_pid=%d",
                 e->success ? "OK" : "FAIL", e->ptrace_req, e->target_pid);
        break;
    }

    syslog(LOG_INFO,
           "type=%s pid=%d ppid=%d uid=%u comm=%s cgroup=%s lineage=%s %s",
           ts, e->pid, e->ppid, e->uid, e->comm,
           e->cgroup[0] ? e->cgroup : "-", chain, detail);
}

/* ── summary mode ───────────────────────────────────────────────────────── */

#define SUMMARY_MAX_COMMS 64

typedef struct {
    char     comm[16];
    uint64_t counts[EVENT_TYPE_MAX];   /* indexed by event_type_t */
} comm_stat_t;

static int         g_summary_interval = 0;
static uint64_t    g_totals[EVENT_TYPE_MAX];
static uint64_t    g_summary_drops;
static comm_stat_t g_comm_stats[SUMMARY_MAX_COMMS];
static int         g_comm_count;
static time_t      g_last_flush;

void output_set_summary(int interval_secs)
{
    g_summary_interval = interval_secs;
    g_last_flush       = time(NULL);
    memset(g_totals,     0, sizeof(g_totals));
    memset(g_comm_stats, 0, sizeof(g_comm_stats));
    g_comm_count   = 0;
    g_summary_drops = 0;
}

static void summary_record(const event_t *e)
{
    if (e->type < EVENT_TYPE_MAX)
        g_totals[e->type]++;

    comm_stat_t *slot = NULL;
    for (int i = 0; i < g_comm_count; i++) {
        if (strncmp(g_comm_stats[i].comm, e->comm, 16) == 0) {
            slot = &g_comm_stats[i];
            break;
        }
    }
    if (!slot && g_comm_count < SUMMARY_MAX_COMMS) {
        slot = &g_comm_stats[g_comm_count++];
        strncpy(slot->comm, e->comm, 15);
        slot->comm[15] = '\0';
        memset(slot->counts, 0, sizeof(slot->counts));
    }
    if (slot && e->type < EVENT_TYPE_MAX)
        slot->counts[e->type]++;
}

static void print_top_comms(int type, int top)
{
    int order[SUMMARY_MAX_COMMS];
    for (int i = 0; i < g_comm_count; i++) order[i] = i;
    for (int i = 0; i < g_comm_count && i < top; i++) {
        int best = i;
        for (int j = i + 1; j < g_comm_count; j++)
            if (g_comm_stats[order[j]].counts[type] >
                g_comm_stats[order[best]].counts[type])
                best = j;
        int tmp = order[i]; order[i] = order[best]; order[best] = tmp;
    }
    for (int i = 0; i < g_comm_count && i < top; i++) {
        uint64_t c = g_comm_stats[order[i]].counts[type];
        if (c == 0) break;
        fprintf(OUT, "  %s(%llu)", g_comm_stats[order[i]].comm,
               (unsigned long long)c);
    }
}

static void summary_flush(void)
{
    static const char *line =
        "════════════════════════════════════════════════════════";
    fprintf(OUT, "\n%s\n", line);
    fprintf(OUT, " %lus summary\n", (unsigned long)g_summary_interval);
    static const struct { event_type_t t; const char *label; } rows[] = {
        { EVENT_EXEC,    "EXEC   " }, { EVENT_OPEN,   "OPEN   " },
        { EVENT_CONNECT, "CONNECT" }, { EVENT_EXIT,   "EXIT   " },
        { EVENT_UNLINK,  "UNLINK " }, { EVENT_RENAME, "RENAME " },
        { EVENT_CHMOD,   "CHMOD  " }, { EVENT_BIND,   "BIND   " },
        { EVENT_PTRACE,  "PTRACE " },
    };
    for (int r = 0; r < 9; r++) {
        uint64_t n = g_totals[rows[r].t];
        if (n == 0 && rows[r].t != EVENT_EXEC && rows[r].t != EVENT_OPEN)
            continue;
        fprintf(OUT, "  %s %6llu", rows[r].label, (unsigned long long)n);
        if (rows[r].t != EVENT_EXIT)
            print_top_comms(rows[r].t, 5);
        fputc('\n', OUT);
    }
    if (g_summary_drops)
        fprintf(OUT, "  DROPS   %6llu\n", (unsigned long long)g_summary_drops);
    fprintf(OUT, "%s\n\n", line);
    fflush(OUT);

    memset(g_totals,     0, sizeof(g_totals));
    memset(g_comm_stats, 0, sizeof(g_comm_stats));
    g_comm_count    = 0;
    g_summary_drops = 0;
    g_last_flush    = time(NULL);
}

void output_summary_tick(uint64_t drop_delta)
{
    if (!g_summary_interval)
        return;
    g_summary_drops += drop_delta;
    if (time(NULL) - g_last_flush >= g_summary_interval)
        summary_flush();
}

/* ── event_to_json ──────────────────────────────────────────────────────── */
/*
 * Serialise one event to a caller-supplied buffer as JSON (no newline).
 * Uses open_memstream so we can reuse the existing json_event formatter.
 * The g_out swap is safe because argus is single-threaded.
 */
size_t event_to_json(const event_t *e, char *buf, size_t bufsz)
{
    if (!buf || bufsz < 2) return 0;

    char  *ptr = NULL;
    size_t sz  = 0;
    FILE  *mem = open_memstream(&ptr, &sz);
    if (!mem) return 0;

    FILE *saved = g_out;
    g_out = mem;
    json_event(e);      /* writes JSON + '\n' into mem via OUT macro */
    g_out = saved;

    fclose(mem);        /* finalises ptr and sz */

    /* strip trailing newline written by json_event */
    size_t copy = sz;
    if (copy > 0 && ptr[copy - 1] == '\n') copy--;
    if (copy >= bufsz) copy = bufsz - 1;
    memcpy(buf, ptr, copy);
    buf[copy] = '\0';
    free(ptr);
    return copy;
}

/* ── dispatcher ─────────────────────────────────────────────────────────── */

void print_event(const event_t *e)
{
    if (g_summary_interval) {
        summary_record(e);
        return;
    }
    if (g_fmt == OUTPUT_JSON)
        json_event(e);
    else if (g_fmt == OUTPUT_SYSLOG)
        syslog_event(e);
    else
        text_event(e);
}

void print_drops(uint64_t count)
{
    if (g_summary_interval) {
        g_summary_drops += count;
        return;
    }
    if (g_fmt == OUTPUT_JSON)
        fprintf(OUT, "{\"type\":\"DROP\",\"count\":%llu}\n",
               (unsigned long long)count);
    else if (g_fmt == OUTPUT_SYSLOG)
        syslog(LOG_WARNING, "dropped %llu event(s) — ring buffer full",
               (unsigned long long)count);
    else
        fprintf(stderr, "[WARNING: %llu event(s) dropped — ring buffer full]\n",
                (unsigned long long)count);
}
