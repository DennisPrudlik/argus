#ifndef __FORWARD_H
#define __FORWARD_H

#include <stdint.h>
#include "argus.h"

/*
 * TCP event forwarding.
 *
 * Connects to a remote host:port and streams events as newline-delimited JSON,
 * identical in format to --json output.  Designed for feeding SIEMs, log
 * aggregators (Loki, Elasticsearch, Vector, Logstash), or a custom receiver.
 *
 * Behaviour under failure:
 *   - Connection attempt is non-blocking; if the remote is unreachable at
 *     startup, forwarding silently defers and retries with exponential backoff
 *     (1 s → 2 s → 4 s … capped at 30 s).
 *   - Sends use MSG_DONTWAIT — if the kernel send buffer is full the event is
 *     dropped and counted.  Accumulated drops are reported as
 *     {"type":"DROP","count":N} on the next successful send after reconnect.
 *   - A lost connection triggers the same backoff/reconnect cycle.
 *
 * Usage:
 *   forward_init("192.168.1.10", 9000);      // once, before event loop
 *   ...
 *   forward_event(e);                         // in handle_event callback
 *   forward_drops(delta);                     // after each poll tick if drops
 *   forward_tick();                           // once per poll tick
 *   forward_fini();                           // at exit
 */

/*
 * Parse "host:port" or "[ipv6addr]:port" into separate host and port.
 * Writes host into *host_out (up to hostsz bytes) and port into *port_out.
 * Returns 0 on success, -1 on malformed input.
 */
int forward_parse_addr(const char *s, char *host_out, size_t hostsz,
                       int *port_out);

/*
 * Initialise forwarding to host:port.
 * Attempts an immediate connection; failure is non-fatal (will retry).
 * Returns 0 if arguments are valid, -1 if host/port are malformed.
 */
int  forward_init(const char *host, int port);

/*
 * Format event as JSON and send to the forward socket.
 * Non-blocking — drops silently if the connection is down or the buffer full.
 */
void forward_event(const event_t *e);

/* Send {"type":"DROP","count":N} to the forward target. */
void forward_drops(uint64_t count);

/*
 * Call once per poll loop tick (~100 ms).
 * Drives reconnect attempts after connection loss.
 */
void forward_tick(void);

/* Returns 1 if currently connected to the forward target, 0 otherwise. */
int  forward_connected(void);

/* Flush pending drop report and close the socket. */
void forward_fini(void);

#endif /* __FORWARD_H */
