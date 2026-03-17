#ifndef __ARGUS_H
#define __ARGUS_H

/* vmlinux.h (BPF context) already provides these types */
#ifndef __VMLINUX_H__
#include <stdint.h>
#include <stdbool.h>
#endif

// Task communication structure
typedef struct event {
    int pid;
    int ppid;
    uint64_t duration_ns;
    char comm[16];
    char filename[128];
    bool success;
} event_t;

#endif /* __ARGUS_H */