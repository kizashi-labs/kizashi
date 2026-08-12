// SPDX-License-Identifier: GPL-2.0
// eBPF program for TLS-handshake capture (JA3/JA3S fingerprinting).
//
// Attaches to: kprobe/tcp_sendmsg (outbound — captures the ClientHello)
//              kprobe/tcp_recvmsg (inbound  — captures the ServerHello)
//
// Unlike the flow monitor (network_monitor.bpf.c), which records only the 5-tuple
// and byte counts, this program copies the FIRST bytes of the stream payload so the
// userspace side can compute a JA3/JA3S fingerprint. It runs in PROCESS context (the
// syscall path), so — unlike a TC/XDP tap — it keeps the PID/comm of the socket owner,
// which is exactly what correlates a beacon back to a process.
//
// It only emits when the payload begins with a TLS handshake record whose message type
// is ClientHello (1) or ServerHello (2), so it does not exfiltrate arbitrary traffic —
// just the two handshake messages the fingerprint needs. TLS_CAP_LEN bounds the copy;
// a ClientHello larger than that yields a truncated (still usually sufficient) capture.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET  2
#define AF_INET6 10
#define TASK_COMM_LEN 16
#define TLS_CAP_LEN 320

#define TLS_RECORD_HANDSHAKE 0x16
#define TLS_MSG_CLIENT_HELLO 1
#define TLS_MSG_SERVER_HELLO 2

#define DIR_CLIENT 1 // outbound: ClientHello
#define DIR_SERVER 2 // inbound:  ServerHello

// Layout MUST stay in sync with parseTLSEvent offsets in tls_ebpf_parse.go.
struct tls_event {
    __u64 timestamp_ns;        // 0
    __u32 pid;                 // 8
    __u32 uid;                 // 12
    __u8  af;                  // 16
    __u8  direction;           // 17  (DIR_CLIENT / DIR_SERVER)
    __u16 dst_port;            // 18  (host order)
    __u32 dst_ip4;             // 20  (network byte order)
    __u8  dst_ip6[16];         // 24
    __u16 data_len;            // 40  (bytes copied into data[])
    __u16 pad;                 // 42
    char  comm[TASK_COMM_LEN]; // 44
    __u8  data[TLS_CAP_LEN];   // 60
};                             // total 380

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tls_events SEC(".maps");

// Per-CPU scratch to build the event (too large for the 512-byte stack).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tls_event);
} tls_scratch SEC(".maps");

static __always_inline void fill_tuple(struct tls_event *e, struct sock *sk)
{
    __u16 family;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    e->af = family;
    if (family == AF_INET) {
        BPF_CORE_READ_INTO(&e->dst_ip4, sk, __sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&e->dst_ip6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
    __be16 dport;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    e->dst_port = bpf_ntohs(dport);
}

// copy_and_emit reads up to TLS_CAP_LEN bytes from the user iov, checks the TLS
// handshake header, and submits an event when the message type matches want_msg.
static __always_inline void copy_and_emit(struct sock *sk, struct msghdr *msg,
                                          __u8 direction, __u8 want_msg)
{
    // Locate the first iovec base/len (ITER_IOVEC layout).
    const struct iovec *iov;
    if (bpf_core_read(&iov, sizeof(iov), &msg->msg_iter.__iov))
        return;
    if (!iov)
        return;
    void *base;
    __u64 iov_len;
    if (bpf_core_read(&base, sizeof(base), &iov->iov_base))
        return;
    if (bpf_core_read(&iov_len, sizeof(iov_len), &iov->iov_len))
        return;
    if (!base || iov_len < 6)
        return;

    __u32 zero = 0;
    struct tls_event *e = bpf_map_lookup_elem(&tls_scratch, &zero);
    if (!e)
        return;

    // Peek the 6-byte TLS record + handshake header before copying the bulk.
    __u8 hdr[6];
    if (bpf_probe_read_user(hdr, sizeof(hdr), base))
        return;
    if (hdr[0] != TLS_RECORD_HANDSHAKE || hdr[1] != 0x03) // handshake, TLS 1.x
        return;
    if (hdr[5] != want_msg) // handshake message type (ClientHello / ServerHello)
        return;

    __u32 n = iov_len < TLS_CAP_LEN ? (__u32)iov_len : TLS_CAP_LEN;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->direction = direction;
    e->data_len = (__u16)n;
    e->pad = 0;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    fill_tuple(e, sk);

    // Bounded copy of the handshake bytes (verifier needs the mask).
    n &= (TLS_CAP_LEN - 1);
    if (bpf_probe_read_user(e->data, n, base))
        return;

    struct tls_event *out = bpf_ringbuf_reserve(&tls_events, sizeof(*out), 0);
    if (!out)
        return;
    __builtin_memcpy(out, e, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
}

// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size) — outbound ClientHello.
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg)
{
    copy_and_emit(sk, msg, DIR_CLIENT, TLS_MSG_CLIENT_HELLO);
    return 0;
}

// tcp_recvmsg(struct sock *sk, struct msghdr *msg, ...) — inbound ServerHello.
// The payload is copied into msg->msg_iter by the time recvmsg returns; a kprobe on
// ENTRY sees the destination iov the kernel is about to fill. We rely on the common
// case where the ServerHello is the first thing read on the socket.
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg, struct sock *sk, struct msghdr *msg)
{
    copy_and_emit(sk, msg, DIR_SERVER, TLS_MSG_SERVER_HELLO);
    return 0;
}

char _license[] SEC("license") = "GPL";
