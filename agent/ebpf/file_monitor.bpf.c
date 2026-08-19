// SPDX-License-Identifier: GPL-2.0
// eBPF program for file operation monitoring
// Attaches to: tracepoint/syscalls/sys_enter_openat,
//              tracepoint/syscalls/sys_exit_openat,
//              kprobe/vfs_unlink, kprobe/vfs_rename

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256
#define TASK_COMM_LEN 16

// File event actions
#define FILE_OPEN    1
#define FILE_CREATE  2
#define FILE_WRITE   3
#define FILE_DELETE  4
#define FILE_RENAME  5
#define FILE_EXEC    6

// Open flags (from fcntl.h)
#define O_WRONLY   00000001
#define O_RDWR     00000002
#define O_CREAT    00000100
#define O_TRUNC    00001000
#define O_APPEND   00002000

struct file_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u8  action;
    __u8  pad[3];
    char  comm[TASK_COMM_LEN];
    char  path[MAX_PATH_LEN];
    char  old_path[MAX_PATH_LEN]; // for renames
    __s32 ret;
    int   flags;
    int   mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} file_events SEC(".maps");

// Staging map for open calls (enter → exit correlation)
struct openat_args {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    char  path[MAX_PATH_LEN];
    int   flags;
    int   mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);  // pid_tgid
    __type(value, struct openat_args);
} openat_map SEC(".maps");

// ─── dentry → 絶対パス ───────────────────────────────────────
//
// kprobe から取れるのは dentry だけで、dentry->d_name は basename しか持たない。
// ユーザ空間側 (file_ebpf_collector.go の pathAllowed) は監視ルートへの前方一致で
// 判定するため、"f1.txt" のような basename は必ず捨てられる。実測では unlink/rename
// のイベントが 1 件も届いておらず、削除・リネームを伴うランサムウェアが Linux で
// 完全に不可視だった。openat 経路だけが届いていたのは、tracepoint がシスコール引数
// からフルパスを取れるため。
//
// bpf_d_path() はこのフック種別では使えない (BTF の allowlist にある関数でしか
// 許可されない) ので、d_parent を遡って自前で組み立てる。
//
// verifier 対策:
//   - ループ回数は定数。#pragma unroll で完全展開する
//   - 書き込みオフセットは常に PATH_MASK でマスクし、範囲を静的に保証する
//   - 1 セグメントごとに残量を計算して渡す。残量が尽きたら書かずに抜ける
// 深さの上限。検証EC2 の実測（7 日 / Linux エージェント 1 台 / file イベント
// 87,655 件）では最深 21 段で、12 段では 6,008 件 (7.5%) が上限を超えていた。
// 超過分は「先頭側」が欠けるため、ユーザ空間の pathAllowed が監視ルートへの
// 前方一致に失敗し、イベントごと捨てられる——つまり #778 で直したはずの欠落が、
// 深いパスにだけ残っていた。しかも欠けていた 6,008 件のうち 5,870 件が
// /home/ubuntu 配下、すなわちランサムウェアが暗号化する場所そのものである。
// 実測の 21 段に余裕を足して 24 段とする。
#define MAX_PATH_DEPTH 24
#define PATH_MASK (MAX_PATH_LEN - 1)
// 1 セグメント（パス要素 1 つ）に許す最大長。NAME_MAX を丸ごと許すと verifier が
// 「末尾付近から 255 バイト書きうる」と解釈して弾くので上限を切る。
#define SEG_MAX 64
// 書き込み開始位置の上限。ここを超えなければ off + 1 + SEG_MAX は常に領域内
// (191 + 1 + 64 = 256)。実効の最大パス長は 255 バイト。
//
// 以前は 127 だった。マスクとして使うには 2 の冪 - 1 である必要があったためだが、
// それだと実効 191 バイトで頭打ちになり、実測 129〜191 バイトの 1,994 件 (2.3%) が
// 末尾を失っていた。マスクをやめ、比較だけで境界を証明する形に変える
// (dst が char (*)[MAX_PATH_LEN] なので verifier は領域長を知っており、
//  比較の通過側で umax = 191 が確定する)。
#define PATH_WRITE_LIMIT 191

static __always_inline void dentry_full_path(struct dentry *dentry,
                                             char (*dstp)[MAX_PATH_LEN])
{
    char *dst = *dstp;
    const unsigned char *segs[MAX_PATH_DEPTH];
    struct dentry *d = dentry;
    __u32 n = 0;

#pragma unroll
    for (int i = 0; i < MAX_PATH_DEPTH; i++) {
        struct dentry *parent = BPF_CORE_READ(d, d_parent);
        if (!parent || parent == d)
            break;
        segs[n] = BPF_CORE_READ(d, d_name.name);
        n++;
        d = parent;
    }

    dst[0] = '\0';
    if (n == 0)
        return;

    // 書き込み位置は「必ず SEG_MAX + NUL が収まる」範囲に閉じ込める。
    // off をマスクしてから使うのではなく、マスク済みの値しか off に入れない
    // ことで、verifier が各反復の開始時点で範囲を確定できるようにする。
    __u32 off = 0;
#pragma unroll
    for (int i = MAX_PATH_DEPTH - 1; i >= 0; i--) {
        if ((__u32)i >= n)
            continue;
        if (off > PATH_WRITE_LIMIT)
            break;                         // 通過側で off <= 191 が確定する
        dst[off] = '/';
        int w = bpf_probe_read_kernel_str(&dst[off + 1], SEG_MAX, segs[i]);
        if (w <= 0)
            break;
        // w は [1, SEG_MAX]。off は [0,191] なので次の off は最大 191+64=255。
        off = (off + 1 + (__u32)(w - 1)) & PATH_MASK;
    }
    dst[off & PATH_MASK] = '\0';
}

// ─── tracepoint: sys_enter_openat ────────────────────────────

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    int flags = (int)ctx->args[2];

    // Only track write-related opens (create, write, truncate, append)
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)))
        return 0;

    struct openat_args args = {};
    args.timestamp_ns = bpf_ktime_get_ns();
    args.pid = id >> 32;
    args.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    args.flags = flags;
    args.mode = (int)ctx->args[3];

    // NOTE: no `__user` qualifier here. `__user` is a sparse annotation defined by the
    // kernel's own <linux/compiler.h>; bpftool-generated vmlinux.h does NOT define it,
    // so clang parses `const char __user *p` as two declarators and fails with
    // "expected ';' at end of declaration". This file had no bpf2go generation step in
    // CI until 2026-08-03, so the error went unnoticed. bpf_probe_read_user_str already
    // states the address space, making the annotation redundant anyway — see the
    // dlopen uprobe in library_monitor.bpf.c for the same plain-pointer form.
    const char *user_path = (const char *)ctx->args[1];
    bpf_probe_read_user_str(args.path, sizeof(args.path), user_path);

    bpf_map_update_elem(&openat_map, &id, &args, BPF_ANY);
    return 0;
}

// ─── tracepoint: sys_exit_openat ─────────────────────────────

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct openat_args *args = bpf_map_lookup_elem(&openat_map, &id);
    if (!args)
        return 0;

    // Ignore failed opens (ret < 0)
    if (ctx->ret < 0) {
        bpf_map_delete_elem(&openat_map, &id);
        return 0;
    }

    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&openat_map, &id);
        return 0;
    }

    event->timestamp_ns = args->timestamp_ns;
    event->pid = args->pid;
    event->uid = args->uid;
    event->flags = args->flags;
    event->mode = args->mode;
    event->ret = ctx->ret;
    event->action = (args->flags & O_CREAT) ? FILE_CREATE : FILE_WRITE;

    bpf_get_current_comm(event->comm, sizeof(event->comm));
    __builtin_memcpy(event->path, args->path, MAX_PATH_LEN);

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&openat_map, &id);
    return 0;
}

// ─── kprobe: vfs_unlink (file delete) ────────────────────────

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(handle_vfs_unlink, struct user_namespace *mnt_userns,
               struct inode *dir, struct dentry *dentry,
               struct inode **delegated_inode)
{
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->action = FILE_DELETE;
    event->ret = 0;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // basename ではなく絶対パスを入れる。ユーザ空間は監視ルートへの前方一致で
    // 判定するので、basename だと必ず捨てられる (dentry_full_path の説明を参照)。
    dentry_full_path(dentry, &event->path);
    event->old_path[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ─── kprobe: vfs_rename ──────────────────────────────────────

SEC("kprobe/vfs_rename")
int BPF_KPROBE(handle_vfs_rename, struct renamedata *rd)
{
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->action = FILE_RENAME;
    event->ret = 0;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    struct dentry *old_dentry, *new_dentry;
    BPF_CORE_READ_INTO(&old_dentry, rd, old_dentry);
    BPF_CORE_READ_INTO(&new_dentry, rd, new_dentry);

    // path = 新しい名前 / old_path = 元の名前。どちらも絶対パスにする。
    // 名前の割り当てが逆に見えるが、ユーザ空間の FileEvent は Path を「今の場所」、
    // OldPath を「元の場所」として扱うため、こちらが正しい対応付けになる。
    dentry_full_path(new_dentry, &event->path);
    dentry_full_path(old_dentry, &event->old_path);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
