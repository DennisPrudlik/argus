#include "vmlinux.h"
/* __user is a sparse annotation — not always defined by older vmlinux.h */
#ifndef __user
#define __user
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "argus.h"

/* ── Ring buffer: kernel → userspace ───────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ── Drop counter ───────────────────────────────────────────────────────── */

/*
 * Incremented every time bpf_ringbuf_reserve fails (ring buffer full).
 * Userspace reads this after each poll() interval and reports the delta.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint64_t);
} dropped SEC(".maps");

static __always_inline void note_drop(void)
{
    uint32_t zero = 0;
    uint64_t *cnt = bpf_map_lookup_elem(&dropped, &zero);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

/* ── Kernel-side filter maps ────────────────────────────────────────────── */

/*
 * config_map[0] holds active filter flags set by userspace at startup.
 * Checked in should_drop() before any ring buffer reservation.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, argus_config_t);
} config_map SEC(".maps");

/* Allowlist of PIDs to trace (only consulted when filter_pid_active=1) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, uint32_t);    /* pid  */
    __type(value, uint8_t);   /* 1    */
} filter_pids SEC(".maps");

/* Allowlist of comm strings to trace (only consulted when filter_comm_active=1) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);    /* null-padded comm */
    __type(value, uint8_t);   /* 1                */
} filter_comms SEC(".maps");

/*
 * should_drop_pid — called in ENTER handlers (before comm is available).
 * Returns 1 if the event should be silently discarded, 0 to keep it.
 */
static __always_inline int should_drop_pid(uint32_t pid)
{
    uint32_t zero = 0;
    argus_config_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return 0;
    if (cfg->filter_pid_active && !bpf_map_lookup_elem(&filter_pids, &pid))
        return 1;
    return 0;
}

/*
 * should_drop — called in EXIT handlers once comm is known.
 * Checks both pid and comm allowlists.
 */
static __always_inline int should_drop(uint32_t pid, char comm[16])
{
    uint32_t zero = 0;
    argus_config_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return 0;
    if (cfg->filter_pid_active && !bpf_map_lookup_elem(&filter_pids, &pid))
        return 1;
    if (cfg->filter_comm_active && !bpf_map_lookup_elem(&filter_comms, comm))
        return 1;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_EXEC — tracepoint/syscalls/sys_{enter,exit}_execve
 * ══════════════════════════════════════════════════════════════════════════ */

struct exec_start {
    uint64_t ts;
    char     filename[128];
    char     args[256];
};

/*
 * Per-CPU scratch buffer for exec_start — the struct is too large
 * (filename + args = 384 bytes) to fit on the 512-byte BPF stack.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct exec_start);
} exec_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uint32_t);           /* pid */
    __type(value, struct exec_start);
} execs SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t zero = 0;
    struct exec_start *es = bpf_map_lookup_elem(&exec_scratch, &zero);
    if (!es)
        return 0;

    __builtin_memset(es, 0, sizeof(*es));
    es->ts = bpf_ktime_get_ns();

    /* argv[0] = executable filename */
    bpf_probe_read_user_str(es->filename, sizeof(es->filename),
                            (const char *)ctx->args[0]);

    /*
     * argv[1..8] → args buffer, 8 fixed 31-char slots separated by spaces.
     * Layout: [arg1:31][ ][arg2:31][ ] ... (8 × 32 = 256 bytes)
     *
     * Fixed slot offsets let the BPF verifier statically prove all map-value
     * accesses are in-bounds, avoiding verifier rejection on kernels ≤ 5.15
     * that cannot track dynamic offset arithmetic through loops.
     */
    const char *const *argv = (const char *const *)ctx->args[1];

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        const char *argp = NULL;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i + 1]) || !argp)
            break;
        bpf_probe_read_user_str(es->args + i * 32, 31, argp);
        if (i < 7)
            es->args[i * 32 + 31] = ' ';
    }

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    if (should_drop_pid(pid))
        return 0;
    bpf_map_update_elem(&execs, &pid, es, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct exec_start *es = bpf_map_lookup_elem(&execs, &pid);
    if (!es)
        goto cleanup;

    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_drop(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_EXEC;
    e->pid         = pid;
    e->duration_ns = bpf_ktime_get_ns() - es->ts;
    e->success     = (ctx->ret == 0);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    uint64_t uid_gid = bpf_get_current_uid_gid();
    e->uid = (uint32_t)(uid_gid);
    e->gid = (uint32_t)(uid_gid >> 32);

    __builtin_memcpy(e->comm, comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, es->filename, sizeof(e->filename));
    __builtin_memcpy(e->args,     es->args,     sizeof(e->args));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&execs, &pid);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_OPEN — tracepoint/syscalls/sys_{enter,exit}_openat
 * ══════════════════════════════════════════════════════════════════════════ */

struct open_start {
    uint64_t ts;
    char     filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uint64_t);           /* pid_tgid — threads can openat concurrently */
    __type(value, struct open_start);
} opens SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct open_start os = {};
    os.ts = bpf_ktime_get_ns();

    /* openat: args[0]=dirfd, args[1]=filename */
    bpf_probe_read_user_str(os.filename, sizeof(os.filename),
                            (const char *)ctx->args[1]);

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&opens, &id, &os, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct open_start *os = bpf_map_lookup_elem(&opens, &id);
    if (!os)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_drop(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_OPEN;
    e->pid         = pid;
    e->duration_ns = bpf_ktime_get_ns() - os->ts;
    e->success     = (ctx->ret >= 0);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    uint64_t uid_gid = bpf_get_current_uid_gid();
    e->uid = (uint32_t)(uid_gid);
    e->gid = (uint32_t)(uid_gid >> 32);

    __builtin_memcpy(e->comm, comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, os->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&opens, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_EXIT — tracepoint/sched/sched_process_exit
 * ══════════════════════════════════════════════════════════════════════════ */

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_drop(pid, comm))
        return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        return 0;
    }

    e->type    = EVENT_EXIT;
    e->pid     = pid;
    e->success = true;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    uint64_t uid_gid = bpf_get_current_uid_gid();
    e->uid = (uint32_t)(uid_gid);
    e->gid = (uint32_t)(uid_gid >> 32);

    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_CONNECT — tracepoint/syscalls/sys_{enter,exit}_connect
 * ══════════════════════════════════════════════════════════════════════════ */

#define AF_INET  2
#define AF_INET6 10

struct connect_start {
    uint64_t ts;
    uint8_t  family;
    uint16_t dport;
    uint8_t  daddr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uint64_t);              /* pid_tgid */
    __type(value, struct connect_start);
} connects SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* args[1] = const struct sockaddr *uservaddr */
    struct sockaddr_in  sin  = {};
    struct sockaddr_in6 sin6 = {};
    uint16_t family = 0;

    bpf_probe_read_user(&family, sizeof(family), (void *)ctx->args[1]);

    struct connect_start cs = {};
    cs.ts     = bpf_ktime_get_ns();
    cs.family = (uint8_t)family;

    if (family == AF_INET) {
        bpf_probe_read_user(&sin, sizeof(sin), (void *)ctx->args[1]);
        cs.dport = bpf_ntohs(sin.sin_port);
        __builtin_memcpy(cs.daddr, &sin.sin_addr.s_addr, 4);
    } else if (family == AF_INET6) {
        bpf_probe_read_user(&sin6, sizeof(sin6), (void *)ctx->args[1]);
        cs.dport = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(cs.daddr, &sin6.sin6_addr.in6_u.u6_addr8, 16);
    } else {
        /* Ignore UNIX sockets and other families */
        return 0;
    }

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&connects, &id, &cs, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int handle_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct connect_start *cs = bpf_map_lookup_elem(&connects, &id);
    if (!cs)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_drop(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_CONNECT;
    e->pid         = pid;
    e->duration_ns = bpf_ktime_get_ns() - cs->ts;
    /* connect returns 0 on success, or -EINPROGRESS for non-blocking */
    e->success     = (ctx->ret == 0 || ctx->ret == -115 /* EINPROGRESS */);
    e->family      = cs->family;
    e->dport       = cs->dport;
    __builtin_memcpy(e->daddr, cs->daddr, sizeof(e->daddr));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    uint64_t uid_gid = bpf_get_current_uid_gid();
    e->uid = (uint32_t)(uid_gid);
    e->gid = (uint32_t)(uid_gid >> 32);

    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&connects, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
