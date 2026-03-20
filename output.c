#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "output.h"
#include "lineage.h"
#include "argus.h"

#define LINEAGE_BUF 256

static output_fmt_t g_fmt    = OUTPUT_TEXT;
static filter_t     g_filter = {0};

void output_init(output_fmt_t fmt, const filter_t *filter)
{
    g_fmt = fmt;
    if (filter)
        g_filter = *filter;
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

    /* exclude paths — only applied to OPEN events */
    if (e->type == EVENT_OPEN && g_filter.exclude_count > 0) {
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
    if (g_fmt == OUTPUT_JSON)
        return;

    printf("Tracing via %s (EXEC, OPEN, EXIT, CONNECT)... Ctrl-C to stop.\n",
           backend);

    if (g_filter.pid)
        printf("  filter: pid=%d\n", g_filter.pid);
    if (g_filter.comm[0])
        printf("  filter: comm=%s\n", g_filter.comm);
    if (g_filter.path[0])
        printf("  filter: path=%s\n", g_filter.path);
    for (int i = 0; i < g_filter.exclude_count; i++)
        printf("  exclude: %s\n", g_filter.excludes[i]);

    if (g_filter.pid || g_filter.comm[0] || g_filter.path[0] ||
        g_filter.exclude_count)
        putchar('\n');

    printf("\n%-5s  %-6s  %-6s  %-4s  %-4s  %-16s  %-32s  %s\n",
           "TYPE", "PID", "PPID", "UID", "GID", "COMM", "LINEAGE", "DETAIL");
    printf("%-5s  %-6s  %-6s  %-4s  %-4s  %-16s  %-32s  %s\n",
           "-----", "------", "------", "----", "----",
           "----------------", "--------------------------------", "------");
}

static void text_event(const event_t *e)
{
    char chain[LINEAGE_BUF];
    lineage_str(e->ppid, chain, sizeof(chain));

    printf("%-5s  %-6d  %-6d  %-4u  %-4u  %-16s  %-32s  ",
           e->type == EVENT_EXEC    ? "EXEC"  :
           e->type == EVENT_OPEN    ? "OPEN"  :
           e->type == EVENT_EXIT    ? "EXIT"  :
           e->type == EVENT_CONNECT ? "CONN"  : "?",
           e->pid, e->ppid, e->uid, e->gid, e->comm, chain);

    switch (e->type) {
    case EVENT_EXEC:
        printf("%s %s", e->filename, e->args);
        break;
    case EVENT_OPEN:
        printf("[%s] %s", e->success ? "OK" : "FAIL", e->filename);
        break;
    case EVENT_EXIT:
        printf("exit_code=%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        char addr[INET6_ADDRSTRLEN] = {};
        inet_ntop(e->family == 2 ? AF_INET : AF_INET6,
                  e->daddr, addr, sizeof(addr));
        printf("[%s] %s:%u", e->success ? "OK" : "FAIL", addr, e->dport);
        break;
    }
    }
    putchar('\n');
}

/* ── JSON output ────────────────────────────────────────────────────────── */

static void json_str(const char *s)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  printf("\\\""); break;
        case '\\': printf("\\\\"); break;
        case '\n': printf("\\n");  break;
        case '\r': printf("\\r");  break;
        case '\t': printf("\\t");  break;
        default:
            if (*p < 0x20)
                printf("\\u%04x", *p);   /* escape control characters */
            else
                putchar(*p);
            break;
        }
    }
    putchar('"');
}

static void json_event(const event_t *e)
{
    static const char *type_str[] = {
        [EVENT_EXEC]    = "EXEC",
        [EVENT_OPEN]    = "OPEN",
        [EVENT_EXIT]    = "EXIT",
        [EVENT_CONNECT] = "CONNECT",
    };

    char chain[LINEAGE_BUF];
    lineage_str(e->ppid, chain, sizeof(chain));

    printf("{\"type\":\"%s\","
           "\"pid\":%d,\"ppid\":%d,"
           "\"uid\":%u,\"gid\":%u,"
           "\"comm\":",
           type_str[e->type], e->pid, e->ppid, e->uid, e->gid);
    json_str(e->comm);
    printf(",\"lineage\":");
    json_str(chain);

    printf(",\"duration_ns\":%llu,\"success\":%s",
           (unsigned long long)e->duration_ns,
           e->success ? "true" : "false");

    switch (e->type) {
    case EVENT_EXEC:
        printf(",\"filename\":"); json_str(e->filename);
        printf(",\"args\":");     json_str(e->args);
        break;
    case EVENT_OPEN:
        printf(",\"filename\":"); json_str(e->filename);
        break;
    case EVENT_EXIT:
        printf(",\"exit_code\":%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        char addr[INET6_ADDRSTRLEN] = {};
        inet_ntop(e->family == 2 ? AF_INET : AF_INET6,
                  e->daddr, addr, sizeof(addr));
        printf(",\"family\":%u,\"daddr\":\"%s\",\"dport\":%u",
               e->family, addr, e->dport);
        break;
    }
    }
    puts("}");
}

/* ── summary mode ───────────────────────────────────────────────────────── */

#define SUMMARY_MAX_COMMS 64

typedef struct {
    char     comm[16];
    uint64_t counts[4];   /* indexed by event_type_t */
} comm_stat_t;

static int         g_summary_interval = 0;
static uint64_t    g_totals[4];
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
    if (e->type < 4)
        g_totals[e->type]++;

    /* find or create comm slot */
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
    if (slot && e->type < 4)
        slot->counts[e->type]++;
}

/* Print top-N comms for a given event type, sorted by count descending */
static void print_top_comms(int type, int top)
{
    /* selection sort — good enough for SUMMARY_MAX_COMMS entries */
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
        printf("  %s(%llu)", g_comm_stats[order[i]].comm,
               (unsigned long long)c);
    }
}

static void summary_flush(void)
{
    static const char *line =
        "════════════════════════════════════════════════════════";
    printf("\n%s\n", line);
    printf(" %lus summary\n", (unsigned long)g_summary_interval);
    printf("  EXEC    %6llu", (unsigned long long)g_totals[EVENT_EXEC]);
    print_top_comms(EVENT_EXEC, 5);    putchar('\n');
    printf("  OPEN    %6llu", (unsigned long long)g_totals[EVENT_OPEN]);
    print_top_comms(EVENT_OPEN, 5);    putchar('\n');
    printf("  CONNECT %6llu", (unsigned long long)g_totals[EVENT_CONNECT]);
    print_top_comms(EVENT_CONNECT, 5); putchar('\n');
    printf("  EXIT    %6llu\n", (unsigned long long)g_totals[EVENT_EXIT]);
    if (g_summary_drops)
        printf("  DROPS   %6llu\n", (unsigned long long)g_summary_drops);
    printf("%s\n\n", line);
    fflush(stdout);

    /* reset */
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

/* ── dispatcher ─────────────────────────────────────────────────────────── */

void print_event(const event_t *e)
{
    if (g_summary_interval) {
        summary_record(e);
        return;
    }
    if (g_fmt == OUTPUT_JSON)
        json_event(e);
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
        printf("{\"type\":\"DROP\",\"count\":%llu}\n",
               (unsigned long long)count);
    else
        fprintf(stderr, "[WARNING: %llu event(s) dropped — ring buffer full]\n",
                (unsigned long long)count);
}
