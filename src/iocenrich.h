#ifndef __IOCENRICH_H
#define __IOCENRICH_H

#include "argus.h"

/*
 * iocenrich — IOC threat-intelligence enrichment
 *
 * Requires HAVE_OPENSSL at compile time (needs HTTPS for API calls).
 *
 * iocenrich_init()   — register API keys; NULL disables that source.
 * iocenrich_check()  — enrich EVENT_CONNECT (IP), EVENT_DNS (domain), and
 *                      EVENT_EXEC (hash, if exechash integration present).
 *                      Returns immediately; all network I/O is done on a
 *                      background worker thread.
 * iocenrich_destroy() — flush request queue, join worker thread.
 *
 * Alerts are written to stderr and syslog when a VirusTotal or AlienVault
 * OTX hit is returned.
 *
 * Without HAVE_OPENSSL all functions compile to no-ops.
 */

#ifdef HAVE_OPENSSL

void iocenrich_init(const char *vt_api_key, const char *otx_api_key);
void iocenrich_check(const event_t *ev);
void iocenrich_destroy(void);

#else /* !HAVE_OPENSSL */

static inline void iocenrich_init(const char *vt, const char *otx)
{
    (void)vt; (void)otx;
}
static inline void iocenrich_check(const event_t *ev)  { (void)ev; }
static inline void iocenrich_destroy(void)              {}

#endif /* HAVE_OPENSSL */

#endif /* __IOCENRICH_H */
