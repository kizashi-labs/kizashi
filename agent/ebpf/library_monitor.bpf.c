// SPDX-License-Identifier: GPL-2.0
// eBPF uprobe on dlopen() for shared-object (.so) load monitoring.
//
// This is the Linux counterpart to the Windows image_load ETW collector: it
// surfaces dynamically-loaded shared objects so DLL/SO side-loading and
// LD_PRELOAD-style injection can be detected (ATT&CK T1574.006).
//
// Attaches a uprobe to dlopen in the C library. The first argument is the
// library path the process is loading.
//
// Compiled with: clang -O2 -g -target bpf -D__TARGET_ARCH_x86
//                -c library_monitor.bpf.c -o library_monitor.bpf.o
// (generated via bpf2go on a clang + BTF host; see ebpf_loader.go go:generate)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256
#define TASK_COMM_LEN 16

// ─── Struct ───────────────────────────────────────────────────

struct library_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    char  path[MAX_PATH_LEN];      // the dlopen()'d shared object path
    char  comm[TASK_COMM_LEN];     // the LOADING process, not the loaded object
};

// ─── Maps ─────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MB
} lib_events SEC(".maps");

// ─── uprobe: dlopen(const char *filename, int flags) ──────────

SEC("uprobe/dlopen")
int BPF_KPROBE(handle_dlopen, const char *filename)
{
    if (!filename)
        return 0;

    struct library_event *e = bpf_ringbuf_reserve(&lib_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);
    // Without this the userspace side had nothing to put in ProcessName and fell
    // back to the .so's own basename — which made every event answer "what was
    // loaded" twice and "who loaded it" never. Side-loading detection needs the
    // loader (sshd, a service, a shell) far more than it needs the object again.
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
