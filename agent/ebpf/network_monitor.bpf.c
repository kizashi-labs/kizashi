// SPDX-License-Identifier: GPL-2.0
// eBPF program for network connection monitoring
// Attaches to: kprobe/tcp_connect, kprobe/tcp_close,
//              tracepoint/sock/inet_sock_set_state

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET  2
#define AF_INET6 10
#define TASK_COMM_LEN 16

struct net_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u8  action;          // 1=connect, 2=accept, 3=close, 4=send, 5=recv
    __u8  proto;           // 6=TCP, 17=UDP
    __u8  af;              // AF_INET or AF_INET6
    __u8  pad;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u8  src_ip6[16];
    __u8  dst_ip6[16];
    __u16 src_port;
    __u16 dst_port;
    __u64 bytes_sent;
    __u64 bytes_recv;
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} net_events SEC(".maps");

// Track active connections: pid+{src:port,dst:port} -> bytes
struct conn_key {
    __u32 pid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct conn_stats {
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 start_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key);
    __type(value, struct conn_stats);
} active_conns SEC(".maps");

// ─── Helper ───────────────────────────────────────────────────

static __always_inline void fill_net_event_from_sock(
    struct net_event *event, struct sock *sk, __u8 action)
{
    __u16 family;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->action = action;
    event->af = family;
    event->proto = 6; // TCP

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    if (family == AF_INET) {
        BPF_CORE_READ_INTO(&event->src_ip4, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&event->dst_ip4, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&event->src_port, sk, __sk_common.skc_num);
        __be16 dport;
        BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
        event->dst_port = bpf_ntohs(dport);
    }
}

// ─── kprobe: tcp_connect (outbound) ──────────────────────────

SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk)
{
    struct net_event *event = bpf_ringbuf_reserve(&net_events, sizeof(*event), 0);
    if (!event) return 0;

    fill_net_event_from_sock(event, sk, 1); // action=connect
    event->bytes_sent = 0;
    event->bytes_recv = 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ─── tracepoint: inet_sock_set_state (connection state changes) ──

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // Only care about TCP connections reaching ESTABLISHED or CLOSE
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    if (ctx->newstate == TCP_CLOSE || ctx->newstate == TCP_CLOSE_WAIT) {
        struct net_event *event = bpf_ringbuf_reserve(&net_events, sizeof(*event), 0);
        if (!event) return 0;

        event->timestamp_ns = bpf_ktime_get_ns();
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        event->action = 3; // close
        event->af = ctx->family;
        event->proto = 6;

        if (ctx->family == AF_INET) {
            // The inet_sock_set_state tracepoint exposes saddr/daddr as __u8[4]
            // byte arrays, not __u32; copy the 4 bytes into the u32 fields.
            __builtin_memcpy(&event->src_ip4, ctx->saddr, 4);
            __builtin_memcpy(&event->dst_ip4, ctx->daddr, 4);
        }
        event->src_port = ctx->sport;
        event->dst_port = ctx->dport;

        bpf_get_current_comm(event->comm, sizeof(event->comm));
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
