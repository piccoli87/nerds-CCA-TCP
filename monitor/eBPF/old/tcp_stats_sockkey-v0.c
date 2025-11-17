// tcp_stats_sockkey.c
// BPF (BCC) — estatísticas por conexão TCP indexadas pelo ponteiro do `struct sock` (u64).
// Hooks: kprobe tcp_sendmsg, tcp_retransmit_skb, tcp_set_state

#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <bcc/proto.h>

struct flow_addr_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  proto;
    u8  pad[3];
};

struct flow_stats_t {
    struct flow_addr_t addr; // preenchido na primeira vez que conseguirmos ler
    u64 pkts_sent;
    u64 bytes_sent;
    u64 retransmits;
    u32 last_state;
    u64 last_seen_ns;
};

BPF_HASH(flow_stats, u64, struct flow_stats_t, 16384);

/* Helper: tenta preencher os campos de endereço/porta a partir de struct sock */
static inline void try_fill_addr(struct flow_stats_t *s, struct sock *sk) {
    // se já preenchido, saia
    if (s->addr.proto != 0) return;

    // Ler endereços/ports de __sk_common
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    // leituras seguras (bpf_probe_read_kernel)
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    s->addr.saddr = saddr;
    s->addr.daddr = daddr;
    s->addr.sport = sport;
    s->addr.dport = dport;
    s->addr.proto = IPPROTO_TCP; // sabemos que são conexões TCP nos hooks
}

/* kprobe: tcp_sendmsg(sk, msg, size) */
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk) return 0;
    u64 sk_ptr = (u64)sk;
    struct flow_stats_t zero = {};
    struct flow_stats_t *s = flow_stats.lookup_or_init(&sk_ptr, &zero);
    if (!s) return 0;

    // preencha endereço/ports se ainda não estiverem
    try_fill_addr(s, sk);

    __sync_fetch_and_add(&s->pkts_sent, 1);
    __sync_fetch_and_add(&s->bytes_sent, (u64)size);
    s->last_seen_ns = bpf_ktime_get_ns();
    return 0;
}

/* kprobe: tcp_retransmit_skb(sk, skb) */
int kprobe__tcp_retransmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if (!sk) return 0;
    u64 sk_ptr = (u64)sk;
    struct flow_stats_t zero = {};
    struct flow_stats_t *s = flow_stats.lookup_or_init(&sk_ptr, &zero);
    if (!s) return 0;

    try_fill_addr(s, sk);

    __sync_fetch_and_add(&s->retransmits, 1);
    s->last_seen_ns = bpf_ktime_get_ns();
    return 0;
}

/* kprobe: tcp_set_state(sk, state) */
int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    if (!sk) return 0;
    u64 sk_ptr = (u64)sk;
    struct flow_stats_t zero = {};
    struct flow_stats_t *s = flow_stats.lookup_or_init(&sk_ptr, &zero);
    if (!s) return 0;

    try_fill_addr(s, sk);

    s->last_state = state;
    s->last_seen_ns = bpf_ktime_get_ns();
    return 0;
}
