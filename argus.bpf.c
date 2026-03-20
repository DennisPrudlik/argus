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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, argus_config_t);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, uint32_t);
    __type(value, uint8_t);
} filter_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, uint8_t);
} filter_comms SEC(".maps");

/* ── Per-comm rate limiting ─────────────────────────────────────────────── */

struct rate_slot {
    uint64_t window_ns;   /* ktime_ns when current window started */
    uint32_t count;       /* events emitted in this window        */
    uint32_t pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, struct rate_slot);
} rate_limit_map SEC(".maps");

/* ── Filter helpers ─────────────────────────────────────────────────────── */

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
 * should_filter_out — exit-handler gate combining pid/comm allowlist and
 * per-comm rate limiting into one config_map lookup.
 */
static __always_inline int should_filter_out(uint32_t pid, char comm[16])
{
    uint32_t zero = 0;
    argus_config_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return 0;

    if (cfg->filter_pid_active && !bpf_map_lookup_elem(&filter_pids, &pid))
        return 1;
    if (cfg->filter_comm_active && !bpf_map_lookup_elem(&filter_comms, comm))
        return 1;

    if (cfg->rate_limit_per_comm > 0) {
        uint64_t now = bpf_ktime_get_ns();
        struct rate_slot *slot = bpf_map_lookup_elem(&rate_limit_map, comm);
        if (!slot) {
            struct rate_slot ns = { .window_ns = now, .count = 1, .pad = 0 };
            bpf_map_update_elem(&rate_limit_map, comm, &ns, BPF_ANY);
        } else if (now - slot->window_ns > 1000000000ULL) {
            slot->window_ns = now;
            slot->count = 1;
        } else if (slot->count >= cfg->rate_limit_per_comm) {
            return 1;
        } else {
            slot->count++;
        }
    }

    return 0;
}

/* ── Cgroup helper ──────────────────────────────────────────────────────── */

/*
 * Read the leaf cgroup name from the current task.
 * Uses BPF CO-RE: task_struct → css_set → cgroup → kernfs_node → name.
 * On host processes the name is typically "/" or the slice name.
 * On Docker/k8s containers it is the container ID or scope name.
 */
static __always_inline void fill_cgroup(event_t *e)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const char *name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
    if (name)
        bpf_probe_read_kernel_str(e->cgroup, sizeof(e->cgroup), name);
}

/* ── Common event header fill ───────────────────────────────────────────── */

static __always_inline void fill_common(event_t *e, uint32_t pid,
                                        char comm[16])
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->pid  = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    uint64_t uid_gid = bpf_get_current_uid_gid();
    e->uid = (uint32_t)(uid_gid);
    e->gid = (uint32_t)(uid_gid >> 32);

    __builtin_memcpy(e->comm, comm, 16);
    fill_cgroup(e);
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_EXEC — tracepoint/syscalls/sys_{enter,exit}_execve
 * ══════════════════════════════════════════════════════════════════════════ */

struct exec_start {
    uint64_t ts;
    char     filename[128];
    char     args[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct exec_start);
} exec_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uint32_t);
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

    bpf_probe_read_user_str(es->filename, sizeof(es->filename),
                            (const char *)ctx->args[0]);

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
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_EXEC;
    e->duration_ns = bpf_ktime_get_ns() - es->ts;
    e->success     = (ctx->ret == 0);
    fill_common(e, pid, comm);

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
    __type(key, uint64_t);
    __type(value, struct open_start);
} opens SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct open_start os = {};
    os.ts = bpf_ktime_get_ns();
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
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_OPEN;
    e->duration_ns = bpf_ktime_get_ns() - os->ts;
    e->success     = (ctx->ret >= 0);
    fill_common(e, pid, comm);

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
    if (should_filter_out(pid, comm))
        return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        return 0;
    }

    e->type    = EVENT_EXIT;
    e->success = true;
    fill_common(e, pid, comm);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

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
    __type(key, uint64_t);
    __type(value, struct connect_start);
} connects SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
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
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_CONNECT;
    e->duration_ns = bpf_ktime_get_ns() - cs->ts;
    e->success     = (ctx->ret == 0 || ctx->ret == -115 /* EINPROGRESS */);
    e->family      = cs->family;
    e->dport       = cs->dport;
    __builtin_memcpy(e->daddr, cs->daddr, sizeof(e->daddr));
    fill_common(e, pid, comm);

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&connects, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_UNLINK — tracepoint/syscalls/sys_{enter,exit}_unlinkat
 * Covers both unlink() and unlinkat() — glibc routes unlink() through
 * unlinkat(AT_FDCWD, path, 0) on modern kernels.
 * ══════════════════════════════════════════════════════════════════════════ */

struct unlink_start {
    uint64_t ts;
    char     path[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct unlink_start);
} unlinks SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct unlink_start us = {};
    us.ts = bpf_ktime_get_ns();
    /* unlinkat: args[0]=dirfd, args[1]=pathname, args[2]=flags */
    bpf_probe_read_user_str(us.path, sizeof(us.path),
                            (const char *)ctx->args[1]);

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&unlinks, &id, &us, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int handle_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct unlink_start *us = bpf_map_lookup_elem(&unlinks, &id);
    if (!us)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_UNLINK;
    e->duration_ns = bpf_ktime_get_ns() - us->ts;
    e->success     = (ctx->ret == 0);
    fill_common(e, pid, comm);
    __builtin_memcpy(e->filename, us->path, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&unlinks, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_RENAME — tracepoint/syscalls/sys_{enter,exit}_renameat2
 * Covers rename(), renameat(), renameat2() — all route through renameat2
 * on kernels 3.15+. Old path stored in filename[], new path in args[].
 * ══════════════════════════════════════════════════════════════════════════ */

struct rename_start {
    uint64_t ts;
    char     old_path[128];
    char     new_path[128];
};

/*
 * rename_start is 264 bytes — exceeds safe BPF stack usage when combined
 * with other locals. Use a PERCPU_ARRAY scratch buffer instead.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct rename_start);
} rename_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct rename_start);
} renames SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t zero = 0;
    struct rename_start *rs = bpf_map_lookup_elem(&rename_scratch, &zero);
    if (!rs)
        return 0;

    __builtin_memset(rs, 0, sizeof(*rs));
    rs->ts = bpf_ktime_get_ns();

    /* renameat2: args[1]=oldpath, args[3]=newpath */
    bpf_probe_read_user_str(rs->old_path, sizeof(rs->old_path),
                            (const char *)ctx->args[1]);
    bpf_probe_read_user_str(rs->new_path, sizeof(rs->new_path),
                            (const char *)ctx->args[3]);

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&renames, &id, rs, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int handle_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct rename_start *rs = bpf_map_lookup_elem(&renames, &id);
    if (!rs)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_RENAME;
    e->duration_ns = bpf_ktime_get_ns() - rs->ts;
    e->success     = (ctx->ret == 0);
    fill_common(e, pid, comm);
    __builtin_memcpy(e->filename, rs->old_path, sizeof(e->filename));
    __builtin_memcpy(e->args,     rs->new_path, 128);   /* new path */

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&renames, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_CHMOD — tracepoint/syscalls/sys_{enter,exit}_fchmodat
 * Covers chmod() and fchmodat() — glibc routes chmod() through fchmodat().
 * ══════════════════════════════════════════════════════════════════════════ */

struct chmod_start {
    uint64_t ts;
    char     path[128];
    uint32_t mode;
    uint32_t pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct chmod_start);
} chmods SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_fchmodat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct chmod_start cs = {};
    cs.ts   = bpf_ktime_get_ns();
    cs.mode = (uint32_t)ctx->args[2];
    /* fchmodat: args[0]=dirfd, args[1]=pathname, args[2]=mode */
    bpf_probe_read_user_str(cs.path, sizeof(cs.path),
                            (const char *)ctx->args[1]);

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&chmods, &id, &cs, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int handle_fchmodat_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct chmod_start *cs = bpf_map_lookup_elem(&chmods, &id);
    if (!cs)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_CHMOD;
    e->duration_ns = bpf_ktime_get_ns() - cs->ts;
    e->success     = (ctx->ret == 0);
    e->mode        = cs->mode;
    fill_common(e, pid, comm);
    __builtin_memcpy(e->filename, cs->path, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&chmods, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_BIND — tracepoint/syscalls/sys_{enter,exit}_bind
 * Captures local address a process binds to (server-side network events).
 * IPv4 and IPv6 only; UNIX sockets are ignored.
 * ══════════════════════════════════════════════════════════════════════════ */

struct bind_start {
    uint64_t ts;
    uint8_t  family;
    uint16_t lport;
    uint8_t  laddr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct bind_start);
} binds SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_bind")
int handle_bind_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* bind: args[0]=sockfd, args[1]=sockaddr*, args[2]=addrlen */
    uint16_t family = 0;
    bpf_probe_read_user(&family, sizeof(family), (void *)ctx->args[1]);

    struct bind_start bs = {};
    bs.ts     = bpf_ktime_get_ns();
    bs.family = (uint8_t)family;

    struct sockaddr_in  sin  = {};
    struct sockaddr_in6 sin6 = {};

    if (family == AF_INET) {
        bpf_probe_read_user(&sin, sizeof(sin), (void *)ctx->args[1]);
        bs.lport = bpf_ntohs(sin.sin_port);
        __builtin_memcpy(bs.laddr, &sin.sin_addr.s_addr, 4);
    } else if (family == AF_INET6) {
        bpf_probe_read_user(&sin6, sizeof(sin6), (void *)ctx->args[1]);
        bs.lport = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(bs.laddr, &sin6.sin6_addr.in6_u.u6_addr8, 16);
    } else {
        return 0;
    }

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&binds, &id, &bs, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int handle_bind_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct bind_start *bs = bpf_map_lookup_elem(&binds, &id);
    if (!bs)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_BIND;
    e->duration_ns = bpf_ktime_get_ns() - bs->ts;
    e->success     = (ctx->ret == 0);
    e->family      = bs->family;
    e->dport       = bs->lport;    /* dport field reused for local port */
    __builtin_memcpy(e->daddr, bs->laddr, sizeof(e->daddr));
    fill_common(e, pid, comm);

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&binds, &id);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EVENT_PTRACE — tracepoint/syscalls/sys_{enter,exit}_ptrace
 * Captures ptrace attach/traceme attempts. No user-memory reads needed —
 * request and target pid come directly from the syscall arg registers.
 * ══════════════════════════════════════════════════════════════════════════ */

struct ptrace_start {
    uint64_t ts;
    int      request;
    int      target_pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, uint64_t);
    __type(value, struct ptrace_start);
} ptraces SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* ptrace: args[0]=request, args[1]=pid, args[2]=addr, args[3]=data */
    struct ptrace_start ps = {};
    ps.ts         = bpf_ktime_get_ns();
    ps.request    = (int)ctx->args[0];
    ps.target_pid = (int)ctx->args[1];

    uint64_t id = bpf_get_current_pid_tgid();
    if (should_drop_pid((uint32_t)(id >> 32)))
        return 0;
    bpf_map_update_elem(&ptraces, &id, &ps, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ptrace")
int handle_ptrace_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();

    struct ptrace_start *ps = bpf_map_lookup_elem(&ptraces, &id);
    if (!ps)
        goto cleanup;

    uint32_t pid = (uint32_t)(id >> 32);
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (should_filter_out(pid, comm))
        goto cleanup;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e) {
        note_drop();
        goto cleanup;
    }

    e->type        = EVENT_PTRACE;
    e->duration_ns = bpf_ktime_get_ns() - ps->ts;
    e->success     = (ctx->ret == 0);
    e->ptrace_req  = ps->request;
    e->target_pid  = ps->target_pid;
    fill_common(e, pid, comm);

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&ptraces, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
