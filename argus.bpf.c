#include "vmlinux.h"
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

    /* argv[1..15] → space-separated args buffer */
    const char __user *const __user *argv =
        (const char *const *)ctx->args[1];
    int off = 0;

    for (int i = 1; i < 16; i++) {
        const char __user *argp = NULL;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]))
            break;
        if (!argp)
            break;

        int rem = (int)sizeof(es->args) - off - 1;
        if (rem <= 0)
            break;

        int safe_off = off & (sizeof(es->args) - 1);
        int n = bpf_probe_read_user_str(es->args + safe_off, rem, argp);
        if (n <= 0)
            break;

        off += n;
        if (off > 0 && off < (int)sizeof(es->args)) {
            int sep = (off - 1) & (sizeof(es->args) - 1);
            es->args[sep] = ' ';
        }
    }

    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
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

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e)
        goto cleanup;

    e->type        = EVENT_EXEC;
    e->pid         = pid;
    e->duration_ns = bpf_ktime_get_ns() - es->ts;
    e->success     = (ctx->ret == 0);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    uint64_t uid_gid = bpf_get_current_uid_gid();
    e->uid = (uint32_t)(uid_gid);
    e->gid = (uint32_t)(uid_gid >> 32);

    bpf_get_current_comm(e->comm, sizeof(e->comm));
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

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e)
        goto cleanup;

    e->type        = EVENT_OPEN;
    e->pid         = (uint32_t)(id >> 32);
    e->duration_ns = bpf_ktime_get_ns() - os->ts;
    e->success     = (ctx->ret >= 0);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    uint64_t uid_gid = bpf_get_current_uid_gid();
    e->uid = (uint32_t)(uid_gid);
    e->gid = (uint32_t)(uid_gid >> 32);

    bpf_get_current_comm(e->comm, sizeof(e->comm));
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
    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e)
        return 0;

    e->type    = EVENT_EXIT;
    e->pid     = bpf_get_current_pid_tgid() >> 32;
    e->success = true;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    uint64_t uid_gid = bpf_get_current_uid_gid();
    e->uid = (uint32_t)(uid_gid);
    e->gid = (uint32_t)(uid_gid >> 32);

    bpf_get_current_comm(e->comm, sizeof(e->comm));

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

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e)
        goto cleanup;

    e->type        = EVENT_CONNECT;
    e->pid         = (uint32_t)(id >> 32);
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

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&connects, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
