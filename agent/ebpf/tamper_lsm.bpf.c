// SPDX-License-Identifier: GPL-2.0
// eBPF LSM (KRSI) — agent self-protection: detect/deny attempts to KILL the EDR
// agent process (Ph4 tamper). Hook: lsm/task_kill. Returning -EPERM blocks the
// signal before it is delivered; in audit mode the attempt is only reported.
//
// "You can't kill the EDR" is the headline tamper-protection property. This is
// the kernel-level complement to the agent's existing userland binary self-
// integrity check. See docs/design/Linux改ざん防止と実行前防御設計.md (§3-2).
//
// Same shape as prevention_lsm.bpf.c: per-target mode (1=audit, 2=enforce-
// eligible) + a global enforce switch (fail-open default), and every exit is a
// compile-time-constant return so the LSM verifier can prove R0 ∈ [-4095, 0].
//
// ⚠️ STATUS: tag-gated PoC. NOT verifier-validated until loaded on an lsm=bpf
// host (see docs/Linuxカーネル防御検証ランブック.md).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define EPERM 1
#define SIGKILL 9
#define SIGTERM 15
#define SIGSTOP 19

char _license[] SEC("license") = "GPL";

// Tamper decision streamed to userspace. Field order/padding mirrored by
// tamperEvent in tamper_runner.go — keep in sync.
struct tamper_event {
    __u32 target_pid; // the protected (agent) tgid being signalled
    __u32 sender_pid; // who sent the signal
    __u32 sender_uid;
    __s32 sig;        // signal number
    __u8  enforced;   // 1 = signal denied (-EPERM); 0 = audit-only
    __u8  _pad[3];
    char  sender_comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} tamper_events SEC(".maps");

// Protected PIDs: key = tgid to protect (the agent), value = mode
// (1 = audit-only, 2 = enforce-eligible). Userland registers the agent's own
// tgid at startup.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} protected_pids SEC(".maps");

// Global config array:
//   index 0 = enforce switch (0 = audit-all / fail-open default; 1 = enforce)
//   index 1 = disarm flag   (0 = armed; 1 = temporarily disarmed)
// Disarm lets a legitimate operator stop/update the agent while enforce is on:
// when disarmed, kills are reported but allowed, so systemctl/SIGTERM succeeds.
// The agent sets disarm on SIGUSR1 (a signal not in the guarded set). Without
// this, enforcing kill-protection on the agent's own PID would also block its
// legitimate shutdown — the self-lock the design (§3-2) warns about.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u8);
} tamper_config SEC(".maps");

static __always_inline void report_kill(__u32 target, __u32 sender, __u32 suid,
                                        __s32 sig, __u8 enforced)
{
    struct tamper_event *ev =
        bpf_ringbuf_reserve(&tamper_events, sizeof(*ev), 0);
    if (!ev)
        return;
    ev->target_pid = target;
    ev->sender_pid = sender;
    ev->sender_uid = suid;
    ev->sig = sig;
    ev->enforced = enforced;
    bpf_get_current_comm(&ev->sender_comm, sizeof(ev->sender_comm));
    bpf_ringbuf_submit(ev, 0);
}

SEC("lsm/task_kill")
int BPF_PROG(check_kill, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred, int ret)
{
    // Honor an earlier LSM denial.
    if (ret != 0)
        return ret;

    // Only guard lethal / stop signals — let benign signals through cheaply.
    if (sig != SIGKILL && sig != SIGTERM && sig != SIGSTOP)
        return 0;

    __u32 tgid = 0;
    BPF_CORE_READ_INTO(&tgid, p, tgid);

    __u8 *mode = bpf_map_lookup_elem(&protected_pids, &tgid);
    if (!mode)
        return 0; // target not protected → allow

    __u32 sender = bpf_get_current_pid_tgid() >> 32;
    if (sender == tgid)
        return 0; // self-signal (agent signalling itself) → allow

    __u32 suid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 zero = 0, one = 1;
    __u8 *cfg = bpf_map_lookup_elem(&tamper_config, &zero);
    __u8 global_enforce = cfg ? *cfg : 0;
    __u8 *darm = bpf_map_lookup_elem(&tamper_config, &one);
    __u8 disarmed = darm ? *darm : 0;

    // Two explicit branches, each a constant return, for the LSM verifier.
    // Deny only when enforce is on, the target is enforce-eligible, and we are
    // NOT disarmed (disarm is the legitimate-stop escape hatch).
    if (global_enforce == 1 && *mode == 2 && disarmed == 0) {
        report_kill(tgid, sender, suid, sig, 1);
        return -EPERM; // block the kill
    }

    report_kill(tgid, sender, suid, sig, 0);
    return 0; // reported, but allowed (audit / fail-open)
}
