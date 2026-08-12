// SPDX-License-Identifier: GPL-2.0
// eBPF LSM (KRSI) PoC — block execve of blocklisted binaries (Ph0).
//
// Hook: lsm/bprm_check_security. Returning -EPERM denies the exec *before* the
// new image runs. This is the prevention primitive the observe-only tracepoints
// (process_monitor.bpf.c) cannot provide — a tracepoint can only watch, an LSM
// hook can refuse. See docs/design/Linux改ざん防止と実行前防御設計.md (§2, Ph0).
//
// Requires:
//   - kernel >= 5.7 (BPF LSM); enforce target is >= 5.13 (付録A-1)
//   - CONFIG_BPF_LSM=y AND boot param `lsm=...,bpf`  (see runbook)
//   - BTF at /sys/kernel/btf/vmlinux (CO-RE)
//
// Compiled with: clang -O2 -g -target bpf -D__TARGET_ARCH_x86
//                -c prevention_lsm.bpf.c -o prevention_lsm.bpf.o
//
// ⚠️ STATUS: Ph0 PoC. NOT verifier-validated on hardware yet. Must be loaded on a
// `lsm=bpf`-enabled VM (RHEL 10.1 / Ubuntu 22.04) per the runbook before any
// claim that it works. Do not wire into the production agent until Ph2+.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH_LEN 256
#define EPERM 1

char _license[] SEC("license") = "GPL";

// Decision record streamed to userspace for the audit log. Field order/padding
// is mirrored verbatim by preventionEvent in prevention_lsm.go — keep in sync.
struct prevention_event {
    __u32 pid;
    __u32 uid;
    __u8  blocked;   // 1 = path matched the blocklist
    __u8  enforced;  // 1 = -EPERM actually returned (enforce); 0 = audit-only
    char  filename[MAX_PATH_LEN];
};

// Ring buffer for decisions (audit + enforce both report here).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} prevention_events SEC(".maps");

// Blocklist: exact match on a 256-byte, zero-padded binary path. Userland writes
// the absolute path (zero-padded to MAX_PATH_LEN) as the key. The value is the
// per-path mode: 1 = audit-only (report, never deny — alert rules), 2 = enforce-
// eligible (deny when the global switch is on — block rules). Per-path mode lets
// alert and block rules coexist (Ph3).
// O(1) hash lookup keeps the hot path cheap (設計 §4-1: kernel does O(1) only).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, char[MAX_PATH_LEN]);
    __type(value, __u8);
} blocked_paths SEC(".maps");

// Config map: index 0 is the global enforce switch (0 = audit-all, fail-open
// default: nothing is denied even for mode-2 paths; 1 = enforce: mode-2 paths
// denied). This is the deliberate audit→enforce promotion lever (Ph2→Ph3); it
// stays 0 until an operator opts in, so blocking is never silently enabled.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} prevention_config SEC(".maps");

// Per-CPU scratch for the lookup key (256 bytes is too large for the BPF stack).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_PATH_LEN]);
} path_scratch SEC(".maps");

// report_decision emits one decision to the ring buffer. Factored out so the
// two exit branches below each end in a compile-time-constant return, which the
// LSM verifier requires (R0 must be a provable scalar in [-4095, 0]).
static __always_inline void report_decision(const char *filename, __u8 enforced)
{
    struct prevention_event *ev =
        bpf_ringbuf_reserve(&prevention_events, sizeof(*ev), 0);
    if (!ev)
        return;
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->blocked = 1;
    ev->enforced = enforced;
    bpf_probe_read_kernel_str(ev->filename, MAX_PATH_LEN, filename);
    bpf_ringbuf_submit(ev, 0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(check_exec, struct linux_binprm *bprm, int ret)
{
    // Honor an earlier LSM denial — never turn a "deny" into an "allow".
    if (ret != 0)
        return ret;

    __u32 zero = 0;
    char *key = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!key)
        return 0;

    // Exact-match hash lookups require the full key to match byte-for-byte, so
    // zero the scratch before copying the (possibly shorter) path into it.
    __builtin_memset(key, 0, MAX_PATH_LEN);

    const char *filename = BPF_CORE_READ(bprm, filename);
    if (!filename)
        return 0;
    if (bpf_probe_read_kernel_str(key, MAX_PATH_LEN, filename) < 0)
        return 0;

    __u8 *mode = bpf_map_lookup_elem(&blocked_paths, key);
    if (!mode)
        return 0; // not blocklisted → allow

    // Deny only when the path is enforce-eligible (mode 2 = block rule) AND the
    // global enforce switch is on. Audit paths (mode 1) and audit-all global
    // state (cfg 0, the default) report but always allow → fail-open.
    //
    // Two explicit branches, each ending in a compile-time-constant return, so
    // the LSM verifier can prove R0 ∈ {-EPERM, 0}. (Computing an `enforced`
    // scalar and feeding it to a single return made the verifier reject R0 as an
    // "unknown scalar" — observed on kernel 6.12.)
    __u8 *cfg = bpf_map_lookup_elem(&prevention_config, &zero);
    __u8 global_enforce = cfg ? *cfg : 0;

    if (global_enforce == 1 && *mode == 2) {
        report_decision(filename, 1);
        return -EPERM; // deny the exec
    }

    report_decision(filename, 0);
    return 0; // reported, but allowed (audit / fail-open)
}
