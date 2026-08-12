// SPDX-License-Identifier: GPL-2.0
// eBPF — host-integrity syscall detection: kernel module loading, namespace
// manipulation, and Linux capability changes.
//
// Three MITRE ATT&CK techniques whose only prior coverage was a CommandLine
// match on well-known CLI tools (insmod/modprobe, nsenter, chmod +s — see
// sigma_builtins.go T1547.006/T1611 and migration 309's T1548.001 chmod rule).
// A CommandLine-only rule is trivially bypassed by calling the underlying
// syscall directly from a custom or renamed binary (a small C program, a
// Python ctypes one-liner). Hooking the syscalls themselves closes that gap:
//
//	T1547.006 Kernel Modules and Extensions : init_module / finit_module
//	T1611     Escape to Host (namespaces)   : unshare / setns
//	T1548.001 Setuid/Capability Abuse       : capset
//
// Tracepoints (stable ABI): syscalls/sys_enter_{init_module,finit_module,
// unshare,setns,capset}. Report-only (never blocks). Same ring-buffer shape as
// the other sensors (see fileless_monitor.bpf.c).
//
// Noise note: unshare/setns/capset are routinely called by container runtimes
// (runc/containerd-shim/crun/conmon) on every container start/exec — that is
// NOT filtered here (comm-based allowlisting belongs in userspace, same as the
// existing process/credaccess runtime-noise filters), so the Go runner must
// apply isRuntimeNoiseProc before emitting these two kinds.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

char _license[] SEC("license") = "GPL";

// One host-integrity signal. Field order/padding mirrored by
// hostIntegrityEvent in hostintegrity_runner.go — keep in sync.
struct hostintegrity_event {
    __u32 pid;
    __u32 kind; // 1=init_module 2=finit_module 3=unshare 4=setns 5=capset
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} hostintegrity_events SEC(".maps");

static __always_inline void emit(__u32 kind)
{
    struct hostintegrity_event *e =
        bpf_ringbuf_reserve(&hostintegrity_events, sizeof(*e), 0);
    if (!e)
        return;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->kind = kind;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

// init_module(module_image, len, param_values) — load a kernel module from an
// already-read buffer (the classic in-memory LKM-rootkit load path).
SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_init_module(struct trace_event_raw_sys_enter *ctx)
{
    emit(1);
    return 0;
}

// finit_module(fd, param_values, flags) — load a kernel module from an open
// file descriptor (the on-disk .ko counterpart of init_module).
SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_finit_module(struct trace_event_raw_sys_enter *ctx)
{
    emit(2);
    return 0;
}

// unshare(flags) — disassociate parts of the process's execution context
// (namespaces), the syscall nsenter/unshare(1) and container runtimes wrap.
SEC("tracepoint/syscalls/sys_enter_unshare")
int handle_unshare(struct trace_event_raw_sys_enter *ctx)
{
    emit(3);
    return 0;
}

// setns(fd, nstype) — join an existing namespace (the other half of
// nsenter-style container/host-boundary crossing).
SEC("tracepoint/syscalls/sys_enter_setns")
int handle_setns(struct trace_event_raw_sys_enter *ctx)
{
    emit(4);
    return 0;
}

// capset(header, data) — set the calling thread's capability sets. Dropping
// capabilities (containers doing least-privilege setup) and RAISING/adding
// capabilities (privilege escalation, e.g. granting CAP_SYS_ADMIN to a shell)
// both go through this one syscall; userspace distinguishes by context.
SEC("tracepoint/syscalls/sys_enter_capset")
int handle_capset(struct trace_event_raw_sys_enter *ctx)
{
    emit(5);
    return 0;
}
