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

    const char __user *user_path = (const char *)ctx->args[1];
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

    // Read filename from dentry
    struct qstr dname;
    BPF_CORE_READ_INTO(&dname, dentry, d_name);
    bpf_probe_read_kernel_str(event->path, sizeof(event->path),
                               dname.name);

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

    struct qstr old_name, new_name;
    BPF_CORE_READ_INTO(&old_name, old_dentry, d_name);
    BPF_CORE_READ_INTO(&new_name, new_dentry, d_name);

    bpf_probe_read_kernel_str(event->path, sizeof(event->path), old_name.name);
    bpf_probe_read_kernel_str(event->old_path, sizeof(event->old_path), new_name.name);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
