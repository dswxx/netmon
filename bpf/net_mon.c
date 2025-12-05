//go:build ignore

#include "../headers/vmlinux.h"
#include "../headers/bpf_helpers.h"
#include "../headers/bpf_tracing.h"
#include "../headers/bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct process_key {
    u32 pid;
    char comm[16]; 
};

struct traffic_stats {
    u64 tx_bytes;
    u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct process_key);
    __type(value, struct traffic_stats);
} proc_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); 
    __type(value, struct sock *);
} active_udp_reads SEC(".maps");

static __always_inline int is_loopback(__u32 ip) {
    return (ip & 0x000000FF) == 0x7F;
}

static __always_inline void update_stats(u32 pid, u64 tx, u64 rx) {
    struct process_key key = { .pid = pid };
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    struct traffic_stats *val = bpf_map_lookup_elem(&proc_stats, &key);
    if (val) {
        if (tx) __sync_fetch_and_add(&val->tx_bytes, tx);
        if (rx) __sync_fetch_and_add(&val->rx_bytes, rx);
    } else {
        struct traffic_stats init_val = { .tx_bytes = tx, .rx_bytes = rx };
        bpf_map_update_elem(&proc_stats, &key, &init_val, BPF_ANY);
    }
}

// ==========================================
// Hooks
// ==========================================

// 【核心修复】tcp_sendmsg 有 3 个参数！
// 原型: int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
// 我们加一个 void *msg 占位，把 size 挤到第 3 个位置去
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, void *msg, size_t size) {
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    if (is_loopback(daddr)) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    update_stats(pid_tgid >> 32, size, 0);
    return 0;
}

// tcp_cleanup_rbuf 只有 2 个参数，你是对的
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(kprobe_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    if (copied <= 0) return 0;
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    if (is_loopback(daddr)) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    update_stats(pid_tgid >> 32, 0, copied);
    return 0;
}

// 【核心修复】udp_sendmsg 也有 3 个参数！
// 原型: int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, void *msg, size_t size) {
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    if (is_loopback(daddr)) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    update_stats(pid_tgid >> 32, size, 0);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(kprobe_udp_recvmsg, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&active_udp_reads, &id, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(kretprobe_udp_recvmsg, int ret) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct sock **sk_ptr = bpf_map_lookup_elem(&active_udp_reads, &id);
    if (!sk_ptr) return 0;
    struct sock *sk = *sk_ptr;

    if (ret > 0) {
        __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        if (!is_loopback(daddr)) {
            update_stats(pid, 0, ret);
        }
    }
    bpf_map_delete_elem(&active_udp_reads, &id);
    return 0;
}
