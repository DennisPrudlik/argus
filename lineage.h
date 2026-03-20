#ifndef __LINEAGE_H
#define __LINEAGE_H

#include <stdint.h>

/*
 * Userspace process ancestry cache.
 *
 * Maintains a pid→{ppid,comm} hash table updated on every EXEC/EXIT event.
 * lineage_str() walks the parent chain and returns a human-readable string
 * like "systemd→sshd→bash" representing the ancestry of a process.
 *
 * The cache is best-effort: processes that were already running when argus
 * started won't be in the table until they exec again. lineage_str() emits
 * as much of the chain as it can and stops when a parent isn't found.
 */

/* Register a new process (call on EVENT_EXEC, before printing the event) */
void lineage_update(uint32_t pid, uint32_t ppid, const char *comm);

/* Remove a process from the cache (call on EVENT_EXIT, after printing) */
void lineage_remove(uint32_t pid);

/*
 * Build the ancestry string for a process whose parent is 'ppid'.
 * Writes "ancestor→...→parent" into buf (NUL-terminated, never overflows).
 * Returns buf so it can be used inline in printf calls.
 */
char *lineage_str(uint32_t ppid, char *buf, size_t len);

#endif /* __LINEAGE_H */
