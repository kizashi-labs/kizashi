// SPDX-License-Identifier: GPL-2.0
// eBPF LSM (KRSI) — credential / memory access detection. Hook:
// lsm/ptrace_access_check. Fires when one process attempts to ptrace or read the
// memory of ANOTHER (gdb -p <pid>, open of /proc/<pid>/mem, process_vm_readv) —
// the Linux equivalent of LSASS access, covering T1003 (credential dumping from
// process memory) and T1055 (process injection via ptrace).
//
// AUDIT-ONLY: this hook never denies (it returns the incoming LSM verdict), it
// only reports the tracer/target pair to userspace, which emits a
// credential_access event (the same class the Windows agent already produces).
//
// Same shape as tamper_lsm.bpf.c: a ring buffer + compile-time-constant returns
// so the LSM verifier can prove R0 ∈ [-4095, 0].
//
// ⚠️ STATUS: tag-gated. NOT verifier-validated until loaded on an lsm=bpf host
// (see docs/Linuxカーネル防御検証ランブック.md).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

char _license[] SEC("license") = "GPL";

// One cross-process memory/ptrace access. Field order/padding is mirrored by
// credAccessEvent in credaccess_runner.go — keep in sync.
struct credaccess_event {
    __u32 tracer_pid; // current tgid (the accessing process)
    __u32 tracer_uid;
    __u32 target_pid; // the process whose memory is being accessed
    __u32 mode;       // PTRACE_MODE_* flags
    char  tracer_comm[TASK_COMM_LEN];
    char  target_comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} credaccess_events SEC(".maps");

SEC("lsm/ptrace_access_check")
int BPF_PROG(check_ptrace, struct task_struct *child, unsigned int mode, int ret)
{
    // Honor an earlier LSM denial.
    if (ret != 0)
        return ret;

    __u32 tracer = bpf_get_current_pid_tgid() >> 32;

    __u32 target = 0;
    BPF_CORE_READ_INTO(&target, child, tgid);

    // Ignore kernel threads and a process accessing itself (debug of own child
    // via fork is still cross-tgid and reported; genuine self-access is not).
    if (target == 0 || tracer == target)
        return 0;

    struct credaccess_event *ev =
        bpf_ringbuf_reserve(&credaccess_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->tracer_pid = tracer;
    ev->tracer_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->target_pid = target;
    ev->mode = mode;
    bpf_get_current_comm(&ev->tracer_comm, sizeof(ev->tracer_comm));
    BPF_CORE_READ_STR_INTO(&ev->target_comm, child, comm);

    bpf_ringbuf_submit(ev, 0);
    return 0; // audit-only: never deny
}
