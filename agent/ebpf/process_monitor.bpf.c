// SPDX-License-Identifier: GPL-2.0
// eBPF program for process execution monitoring
// Attaches to: tracepoint/sched/sched_process_exec
//              tracepoint/sched/sched_process_exit
//              tracepoint/syscalls/sys_enter_execve
//
// Compiled with: clang -O2 -g -target bpf -D__TARGET_ARCH_x86
//                -I/usr/include/x86_64-linux-gnu
//                -c process_monitor.bpf.c -o process_monitor.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 512
#define MAX_ARGS_COUNT 20

// ─── Structs ──────────────────────────────────────────────────

struct process_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 action;          // 1=exec, 2=exit, 3=fork
    __s32 exit_code;
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
    char  args[MAX_ARGS_LEN];
    __u32 args_len;        // valid bytes in args[] (NUL-separated argv); 0 if none
};

// ─── Maps ─────────────────────────────────────────────────────

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

// Per-CPU array for storing exec args temporarily
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_event);
} heap SEC(".maps");

// Track PIDs being execved (for correlating execve enter/exit)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct process_event);
} execve_map SEC(".maps");

// ─── Helper: get parent PID ───────────────────────────────────

static __always_inline __u32 get_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    __u32 ppid;
    BPF_CORE_READ_INTO(&parent, task, real_parent);
    BPF_CORE_READ_INTO(&ppid, parent, tgid);
    return ppid;
}

// ─── Tracepoint: sched_process_exec ──────────────────────────

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event *event;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;

    // Only report thread group leaders (main process)
    if (pid != tid)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->ppid = get_ppid();
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->action = 1; // exec
    event->exit_code = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read filename from context
    unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&event->filename, sizeof(event->filename),
                       (void *)ctx + fname_off);

    // Capture argv in-kernel from the new process address space. This is the
    // critical fix for short-lived processes: the command line is available
    // immediately at exec time, with no dependency on a racy /proc/<pid>/cmdline
    // read in userland (which loses the race for sub-second processes and leaves
    // detection rules that key on CommandLine — base64 -d, /dev/tcp/, curl /tmp —
    // unable to match). argv lives between mm->arg_start and mm->arg_end as a
    // run of NUL-separated strings.
    event->args_len = 0;
    event->args[0] = '\0';
    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        __u64 arg_start = 0, arg_end = 0;
        BPF_CORE_READ_INTO(&arg_start, task, mm, arg_start);
        BPF_CORE_READ_INTO(&arg_end, task, mm, arg_end);
        if (arg_start && arg_end > arg_start) {
            __u64 len = arg_end - arg_start;
            if (len > MAX_ARGS_LEN - 1)
                len = MAX_ARGS_LEN - 1;
            // Mask to prove 0 <= len < MAX_ARGS_LEN to the verifier (MAX_ARGS_LEN
            // is a power of two, so this is exact for the clamped range above).
            len &= (MAX_ARGS_LEN - 1);
            if (bpf_probe_read_user(&event->args, len, (void *)arg_start) == 0)
                event->args_len = (__u32)len;
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ─── Tracepoint: sched_process_exit ──────────────────────────

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct process_event *event;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;

    // Only report thread group leaders
    if (pid != tid)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->ppid = 0;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->action = 2; // exit
    // The sched_process_exit tracepoint template has no exit_code field and the
    // userland loader does not use it, so leave it zero.
    event->exit_code = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// NOTE: a kprobe/sys_execve program previously captured argv into execve_map,
// but (a) the userland loader never attached it nor read execve_map, and
// (b) its unbounded bpf_probe_read_user_str size argument was rejected by the
// verifier ("R2 min value is negative"). It was removed. Command-line capture
// for eBPF events is a follow-up (enrich from /proc/<pid>/cmdline in the loader,
// as the polling collector already does).

char _license[] SEC("license") = "GPL";
