// SPDX-License-Identifier: GPL-2.0
// eBPF — fileless / in-memory execution detection.
//
// Reflective / fileless malware stages a payload in anonymous memory
// (memfd_create) and executes it WITHOUT a file on disk via
// execveat(fd, "", ..., AT_EMPTY_PATH). That execveat form — running an fd with an
// empty path — is the canonical fileless-native-exec signature (T1620 Reflective
// Code Loading / T1055 Process Injection) and is rare in normal software, so it is
// a high-fidelity signal that the on-disk scanners and command-line rules miss
// (see docs/results/live-20260702-linux-evasion-adversarial.md, T1620 = MISS).
//
// Tracepoints (stable ABI): syscalls/sys_enter_execveat, syscalls/sys_enter_memfd_create.
// Report-only (never blocks). Same shape as the other ring-buffer sensors.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define AT_EMPTY_PATH 0x1000

char _license[] SEC("license") = "GPL";

// One fileless-execution signal. Field order/padding mirrored by
// filelessEvent in fileless_runner.go — keep in sync.
struct fileless_event {
    __u32 pid;
    __u32 kind; // 1 = memfd_create (staging), 2 = execveat(AT_EMPTY_PATH) (exec)
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} fileless_events SEC(".maps");

static __always_inline void emit(__u32 kind)
{
    struct fileless_event *e =
        bpf_ringbuf_reserve(&fileless_events, sizeof(*e), 0);
    if (!e)
        return;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->kind = kind;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

// execveat(dfd, filename, argv, envp, flags) — args[4] is flags. AT_EMPTY_PATH set
// means "execute the fd itself" (memfd / O_PATH fd) = fileless native execution.
SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long flags = (unsigned long)ctx->args[4];
    if (flags & AT_EMPTY_PATH)
        emit(2);
    return 0;
}

// memfd_create(name, flags) — anonymous memory-backed file, the staging step for
// fileless payloads. Weaker signal (some runtimes use it), reported for correlation.
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd(struct trace_event_raw_sys_enter *ctx)
{
    emit(1);
    return 0;
}
