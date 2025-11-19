// tcp_stats_sockkey.c
// Versão com RTT (srtt) e CWND adicionados.
// Guarda também o ponteiro para tcp_congestion_ops (cc_ops_ptr) para inspeção userland.
// Hooks: kprobe tcp_sendmsg, tcp_retransmit_skb, tcp_set_state

#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <bcc/proto.h>

/* Compat: fallback para bpf_probe_read_kernel se necessário */
#ifndef bpf_probe_read_kernel
# define bpf_probe_read_kernel(dst, size, src) bpf_probe_read(dst, size, src)
#endif

/* Pode ajudar em alguns ambientes a incluir inet_connection_sock */
#include <net/inet_connection_sock.h>

#pragma clang diagnostic ignored "-Wmacro-redefined"

struct flow_addr_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  proto;
    u8  pad[3];
};

struct flow_stats_t {
    struct flow_addr_t addr; // preenchido na primeira leitura possível
    u64 pkts_sent;
    u64 bytes_sent;
    u64 retransmits;
    u32 last_state;
    u64 last_seen_ns;

    /* Novas métricas */
    u32 srtt_us;    // valor cru (do kernel) - mantenho crudo para inspeção
    u32 rtt_us;     // srtt_us convertido (divide por 8) => microsegundos
    u32 cwnd;       // snd_cwnd (unidade: MSS segments)

    /* ponteiro para struct tcp_congestion_ops (armazenado para inspeção em userland) */
    u64 cc_ops_ptr;
};

BPF_HASH(flow_stats, u64, struct flow_stats_t, 16384);

/* Helper: tenta preencher os campos de endereço/porta a partir de struct sock */
static inline void try_fill_addr(struct flow_stats_t *s, struct sock *sk) {
    /* se já preenchido, saia */
    if (s->addr.proto != 0) return;

    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;

    /* leituras seguras */
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    /* skc_num costuma conter o port local (num) */
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    s->addr.saddr = saddr;
    s->addr.daddr = daddr;
    s->addr.sport = sport;
    s->addr.dport = dport;
    s->addr.proto = IPPROTO_TCP;
}

/* Função auxiliar para ler srtt_us e snd_cwnd se possível */
static inline void try_read_tcp_metrics(struct flow_stats_t *s, struct sock *sk) {
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    u32 srtt_raw = 0;
    u32 cwnd = 0;

    /* leitura segura dos campos do tcp_sock */
    bpf_probe_read_kernel(&srtt_raw, sizeof(srtt_raw), &tp->srtt_us);
    bpf_probe_read_kernel(&cwnd, sizeof(cwnd), &tp->snd_cwnd);

    /* Atualiza no map */
    s->srtt_us = srtt_raw;
    /* Conversão aproximada: srtt_us no kernel historicamente vem escalado (>>3) em algumas versões.
       Para evitar perda de informação guardamos o raw e calculamos rtt_us = raw >> 3. */
    s->rtt_us = srtt_raw >> 3;
    s->cwnd = cwnd;
}

/* Apenas lê o ponteiro para as congestion ops (não tenta acessar membros do tipo incompleto) */
static inline void try_read_cc_ops_ptr(struct flow_stats_t *s, struct sock *sk) {
    /* inet_connection_sock cast */
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    u64 ops_ptr = 0;

    /* Lê o ponteiro icsk->icsk_ca_ops (apenas o ponteiro) */
    /* Se bpf_probe_read_kernel não estiver disponível, o fallback bpf_probe_read é usado */
    bpf_probe_read_kernel(&ops_ptr, sizeof(ops_ptr), &icsk->icsk_ca_ops);

    s->cc_ops_ptr = ops_ptr;
}

/* kprobe: tcp_sendmsg(sk, msg, size) */
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk) return 0;
    u64 sk_ptr = (u64)sk;
    struct flow_stats_t zero = {};
    struct flow_stats_t *s = flow_stats.lookup_or_init(&sk_ptr, &zero);
    if (!s) return 0;

    try_fill_addr(s, sk);

    __sync_fetch_and_add(&s->pkts_sent, 1);
    __sync_fetch_and_add(&s->bytes_sent, (u64)size);

    /* ler métricas TCP (srtt, cwnd) */
    try_read_tcp_metrics(s, sk);

    /* ler ponteiro para congestion ops (userland resolve/inspeciona) */
    try_read_cc_ops_ptr(s, sk);

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

    /* ler métricas TCP (srtt, cwnd) - útil para detectar quando retransmissões coincidem com variação de rtt */
    try_read_tcp_metrics(s, sk);

    /* ler ponteiro para congestion ops */
    try_read_cc_ops_ptr(s, sk);

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

    /* ler métricas também aqui (estado muda frequentemente após eventos de perda) */
    try_read_tcp_metrics(s, sk);

    /* ler ponteiro para congestion ops */
    try_read_cc_ops_ptr(s, sk);

    s->last_seen_ns = bpf_ktime_get_ns();
    return 0;
}
