#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "forward.h"
#include "output.h"
#include "argus.h"

#define RECONNECT_MIN_S   1
#define RECONNECT_MAX_S  30

static char    g_host[256] = {};
static int     g_port      = 0;
static int     g_sock      = -1;

static time_t  g_next_reconnect  = 0;
static int     g_reconnect_delay = RECONNECT_MIN_S;
static uint64_t g_dropped_fwd   = 0;   /* events dropped while disconnected / buffer full */

/* ── helpers ─────────────────────────────────────────────────────────────── */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int try_connect(void)
{
    struct addrinfo hints = {}, *res = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", g_port);

    if (getaddrinfo(g_host, port_str, &hints, &res) != 0 || !res)
        return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    /* TCP keepalive so we detect half-open connections */
    int one = 1;
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE, &one, sizeof(one));
#ifdef TCP_KEEPIDLE
    int idle = 10;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &idle, sizeof(idle));
#endif
    /* TCP_NODELAY: flush small writes immediately */
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    set_nonblocking(fd);

    int r = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (r < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Write buf to the socket with MSG_DONTWAIT.  On full buffer: drop+count.
 * On error: close socket and schedule reconnect. */
static void do_send(const char *buf, size_t len)
{
    if (g_sock < 0 || len == 0) return;

    ssize_t n = send(g_sock, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            g_dropped_fwd++;
        } else {
            fprintf(stderr,
                    "warning: forward: lost connection to %s:%d (%s), "
                    "reconnecting in %ds\n",
                    g_host, g_port, strerror(errno), g_reconnect_delay);
            close(g_sock);
            g_sock = -1;
            g_next_reconnect  = time(NULL) + g_reconnect_delay;
            g_reconnect_delay = g_reconnect_delay < RECONNECT_MAX_S
                                ? g_reconnect_delay * 2 : RECONNECT_MAX_S;
            g_dropped_fwd++;
        }
    }
}

/* ── public API ──────────────────────────────────────────────────────────── */

int forward_parse_addr(const char *s, char *host_out, size_t hostsz,
                       int *port_out)
{
    if (!s || !host_out || !port_out) return -1;

    if (s[0] == '[') {
        /* IPv6 bracketed form: [::1]:9000 */
        const char *end_bracket = strchr(s, ']');
        if (!end_bracket || end_bracket[1] != ':') return -1;
        size_t len = (size_t)(end_bracket - s - 1);
        if (len == 0 || len >= hostsz) return -1;
        memcpy(host_out, s + 1, len);
        host_out[len] = '\0';
        *port_out = atoi(end_bracket + 2);
    } else {
        /* host:port or ip:port — split at last ':' */
        const char *colon = strrchr(s, ':');
        if (!colon) return -1;
        size_t len = (size_t)(colon - s);
        if (len == 0 || len >= hostsz) return -1;
        memcpy(host_out, s, len);
        host_out[len] = '\0';
        *port_out = atoi(colon + 1);
    }

    if (*port_out <= 0 || *port_out > 65535) return -1;
    return 0;
}

int forward_init(const char *host, int port)
{
    if (!host || !*host || port <= 0 || port > 65535) return -1;

    strncpy(g_host, host, sizeof(g_host) - 1);
    g_port = port;

    g_sock = try_connect();
    if (g_sock < 0) {
        fprintf(stderr,
                "warning: forward: cannot connect to %s:%d, "
                "will retry (backoff %ds)\n",
                g_host, g_port, g_reconnect_delay);
        g_next_reconnect = time(NULL) + g_reconnect_delay;
    } else {
        fprintf(stderr, "info: forward: connected to %s:%d\n",
                g_host, g_port);
        g_reconnect_delay = RECONNECT_MIN_S;
    }
    return 0;
}

void forward_event(const event_t *e)
{
    if (g_sock < 0) { g_dropped_fwd++; return; }

    char buf[2048];
    size_t len = event_to_json(e, buf, sizeof(buf) - 2);
    if (len == 0) return;

    /* append newline for NDJSON framing */
    buf[len]     = '\n';
    buf[len + 1] = '\0';
    do_send(buf, len + 1);
}

void forward_drops(uint64_t count)
{
    if (g_sock < 0 || count == 0) return;
    char buf[64];
    int n = snprintf(buf, sizeof(buf),
                     "{\"type\":\"DROP\",\"count\":%llu}\n",
                     (unsigned long long)count);
    if (n > 0) do_send(buf, (size_t)n);
}

void forward_tick(void)
{
    if (g_sock >= 0) return;                    /* already connected */
    if (time(NULL) < g_next_reconnect) return;  /* still in backoff */

    g_sock = try_connect();
    if (g_sock >= 0) {
        fprintf(stderr, "info: forward: reconnected to %s:%d\n",
                g_host, g_port);
        g_reconnect_delay = RECONNECT_MIN_S;
        if (g_dropped_fwd) {
            forward_drops(g_dropped_fwd);
            g_dropped_fwd = 0;
        }
    } else {
        g_next_reconnect  = time(NULL) + g_reconnect_delay;
        g_reconnect_delay = g_reconnect_delay < RECONNECT_MAX_S
                            ? g_reconnect_delay * 2 : RECONNECT_MAX_S;
    }
}

int forward_connected(void) { return g_sock >= 0; }

void forward_fini(void)
{
    if (g_sock < 0) return;
    if (g_dropped_fwd)
        forward_drops(g_dropped_fwd);
    shutdown(g_sock, SHUT_RDWR);
    close(g_sock);
    g_sock = -1;
}
