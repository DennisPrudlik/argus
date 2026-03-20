#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "output.h"
#include "lineage.h"

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
    if (g_filter.pid != 0 && e->pid != g_filter.pid)
        return 0;

    if (g_filter.comm[0] != '\0' &&
        strncmp(e->comm, g_filter.comm, sizeof(g_filter.comm)) != 0)
        return 0;

    if (g_filter.path[0] != '\0' &&
        strstr(e->filename, g_filter.path) == NULL)
        return 0;

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

    if (g_filter.pid || g_filter.comm[0] || g_filter.path[0])
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
        inet_ntop(e->family == 2 /* AF_INET */ ? AF_INET : AF_INET6,
                  e->daddr, addr, sizeof(addr));
        printf("[%s] %s:%u", e->success ? "OK" : "FAIL", addr, e->dport);
        break;
    }
    }
    putchar('\n');
}

/* ── JSON output ────────────────────────────────────────────────────────── */

/* Emit a JSON-safe quoted string */
static void json_str(const char *s)
{
    putchar('"');
    for (; *s; s++) {
        switch (*s) {
        case '"':  printf("\\\""); break;
        case '\\': printf("\\\\"); break;
        case '\n': printf("\\n");  break;
        case '\r': printf("\\r");  break;
        case '\t': printf("\\t");  break;
        default:   putchar(*s);    break;
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
           type_str[e->type],
           e->pid, e->ppid,
           e->uid, e->gid);
    json_str(e->comm);
    printf(",\"lineage\":");
    json_str(chain);

    printf(",\"duration_ns\":%llu,\"success\":%s",
           (unsigned long long)e->duration_ns,
           e->success ? "true" : "false");

    switch (e->type) {
    case EVENT_EXEC:
        printf(",\"filename\":");
        json_str(e->filename);
        printf(",\"args\":");
        json_str(e->args);
        break;
    case EVENT_OPEN:
        printf(",\"filename\":");
        json_str(e->filename);
        break;
    case EVENT_EXIT:
        printf(",\"exit_code\":%d", e->exit_code);
        break;
    case EVENT_CONNECT: {
        char addr[INET6_ADDRSTRLEN] = {};
        inet_ntop(e->family == 2 /* AF_INET */ ? AF_INET : AF_INET6,
                  e->daddr, addr, sizeof(addr));
        printf(",\"family\":%u,\"daddr\":\"%s\",\"dport\":%u",
               e->family, addr, e->dport);
        break;
    }
    }

    puts("}");
}

/* ── dispatcher ─────────────────────────────────────────────────────────── */

void print_event(const event_t *e)
{
    if (g_fmt == OUTPUT_JSON)
        json_event(e);
    else
        text_event(e);
}

void print_drops(uint64_t count)
{
    if (g_fmt == OUTPUT_JSON)
        printf("{\"type\":\"DROP\",\"count\":%llu}\n",
               (unsigned long long)count);
    else
        fprintf(stderr, "[WARNING: %llu event(s) dropped — ring buffer full]\n",
                (unsigned long long)count);
}
