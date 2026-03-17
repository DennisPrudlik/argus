#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "argus.h"

/* Intermediate per-pid state saved on execve entry */
struct exec_start {
    uint64_t ts;
    char     filename[128];
};

/* Hash map: pid -> exec_start (entry data until exit) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, uint32_t);
    __type(value, struct exec_start);
} execs SEC(".maps");

/* Ring buffer: kernel -> userspace event stream */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    struct exec_start es = {};

    es.ts = bpf_ktime_get_ns();
    /* args[0] is const char __user *filename */
    bpf_probe_read_user_str(es.filename, sizeof(es.filename),
                            (const char *)ctx->args[0]);

    bpf_map_update_elem(&execs, &pid, &es, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    struct exec_start *es = bpf_map_lookup_elem(&execs, &pid);
    if (!es)
        return 0;

    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if (!e)
        goto cleanup;

    e->pid        = pid;
    e->duration_ns = bpf_ktime_get_ns() - es->ts;
    e->success    = (ctx->ret == 0);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    /* After a successful exec, comm reflects the new process name */
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, es->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&execs, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
