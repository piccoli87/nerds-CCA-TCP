// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <linux/ktime.h>
#include <linux/rhashtable.h>

#define PROC_NAME "tcp_metrics"

static char *src_ip = NULL;
static char *dst_ip = NULL;

module_param(src_ip, charp, 0);
MODULE_PARM_DESC(src_ip, "Source IP address filter");

module_param(dst_ip, charp, 0);
MODULE_PARM_DESC(dst_ip, "Destination IP address filter");

static __be32 src_ip_be = 0;
static __be32 dst_ip_be = 0;

static struct net *monitor_netns = NULL;

/* Estrutura auxiliar para armazenar estado anterior */
struct flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

struct flow_data {
    struct rhash_head node;
    struct flow_key key;
    u64 last_retrans_total;
    u64 last_ts_ns;
};

/* Tabela hash para acompanhar retransmissões */
static struct rhashtable flow_table;

static const struct rhashtable_params flow_ht_params = {
    .key_offset = offsetof(struct flow_data, key),
    .head_offset = offsetof(struct flow_data, node),
    .key_len = sizeof(struct flow_key),
    .automatic_shrinking = true,
};

static inline void make_flow_key(struct flow_key *key, struct inet_sock *inet)
{
    key->saddr = inet->inet_saddr;
    key->daddr = inet->inet_daddr;
    key->sport = inet->inet_sport;
    key->dport = inet->inet_dport;
}

/* Função principal que exibe as métricas */
static int tcp_metrics_show(struct seq_file *m, void *v)
{
    struct inet_hashinfo *hashinfo = &tcp_hashinfo;
    struct hlist_nulls_node *node;
    struct sock *sk;
    int i;

    seq_puts(m, "SADDR           DADDR           SPORT DPORT CWND   SRTT(us) RTTVAR(us) RET  ΔRET(1s) SNDWND  RCVWND  DSCP ECN ALG        TIMESTAMP(ns)\n");

    if (!monitor_netns) {
        seq_puts(m, "Error: namespace not initialized\n");
        return 0;
    }

    rcu_read_lock();
    for (i = 0; i <= hashinfo->ehash_mask; i++) {
        struct hlist_nulls_head *head = &hashinfo->ehash[i].chain;
        hlist_nulls_for_each_entry_rcu(sk, node, head, __sk_common.skc_nulls_node) {
            struct inet_sock *inet;
            struct tcp_sock *tp;
            u16 sport, dport;
            u32 cwnd, srtt, rttvar, sndwnd, rcvwnd;
            u64 timestamp, delta_retrans = 0;
            u32 retrans;         // <-- valor instantâneo (retrans_out)
            u64 total_retrans;   // <-- acumulado para cálculo de ΔRET(1s)
            u8 tos, dscp, ecn;
            const char *alg = "unknown";
            struct flow_key key;
            struct flow_data *entry;
            ktime_t now = ktime_get_real();
            u64 now_ns = ktime_to_ns(now);

            if (sk->sk_family != AF_INET)
                continue;
            if (sk->sk_state != TCP_ESTABLISHED)
                continue;
            if (sock_net(sk) != monitor_netns)
                continue;

            inet = inet_sk(sk);

            if ((src_ip_be && inet->inet_saddr != src_ip_be) ||
                (dst_ip_be && inet->inet_daddr != dst_ip_be))
                continue;

            tp = tcp_sk(sk);

            sport = ntohs(inet->inet_sport);
            dport = ntohs(inet->inet_dport);
            cwnd = tp->snd_cwnd;
            srtt = tp->srtt_us >> 3;
            rttvar = tp->mdev_us >> 3;
            retrans = tp->retrans_out;         // <-- instantâneo
            total_retrans = tp->total_retrans; // <-- acumulado
            sndwnd = tp->snd_wnd;
            rcvwnd = tp->rcv_wnd;

            tos = inet->tos;
            dscp = tos >> 2;
            ecn = tos & 0x03;
            timestamp = now_ns;

            if (inet_csk(sk)->icsk_ca_ops && inet_csk(sk)->icsk_ca_ops->name) {
                alg = inet_csk(sk)->icsk_ca_ops->name;
                if (strncmp(alg, "tcp_", 4) == 0)
                    alg += 4;
            }

            make_flow_key(&key, inet);
            entry = rhashtable_lookup_fast(&flow_table, &key, flow_ht_params);

            if (!entry) {
                entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
                if (entry) {
                    entry->key = key;
                    entry->last_retrans_total = total_retrans;
                    entry->last_ts_ns = now_ns;
                    rhashtable_insert_fast(&flow_table, &entry->node, flow_ht_params);
                }
            } else {
                /* calcula delta de retransmissões em 1s */
                if (now_ns - entry->last_ts_ns >= 1000000000ULL) {
                    if (total_retrans >= entry->last_retrans_total)
                        delta_retrans = total_retrans - entry->last_retrans_total;
                    entry->last_retrans_total = total_retrans;
                    entry->last_ts_ns = now_ns;
                }
            }

            seq_printf(m,
                "%-15pI4 %-15pI4 %5u %5u %5u %9u %9u %4u %8llu %7u %7u %4u %3u %-10s %llu\n",
                &inet->inet_saddr, &inet->inet_daddr,
                sport, dport, cwnd, srtt, rttvar,
                retrans, delta_retrans, sndwnd, rcvwnd,
                dscp, ecn, alg, timestamp);
        }
    }
    rcu_read_unlock();
    return 0;
}

static int tcp_metrics_open(struct inode *inode, struct file *file)
{
    return single_open(file, tcp_metrics_show, NULL);
}

static const struct proc_ops tcp_metrics_fops = {
    .proc_open = tcp_metrics_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init tcp_monitor_init(void)
{
    struct proc_dir_entry *entry;
    int ret;

    pr_info("tcp_monitor: iniciando módulo...\n");

    monitor_netns = get_net(current->nsproxy->net_ns);

    if (src_ip && !in4_pton(src_ip, -1, (u8 *)&src_ip_be, -1, NULL)) {
        pr_err("tcp_monitor: IP de origem inválido: %s\n", src_ip);
        return -EINVAL;
    }

    if (dst_ip && !in4_pton(dst_ip, -1, (u8 *)&dst_ip_be, -1, NULL)) {
        pr_err("tcp_monitor: IP de destino inválido: %s\n", dst_ip);
        return -EINVAL;
    }

    ret = rhashtable_init(&flow_table, &flow_ht_params);
    if (ret) {
        pr_err("tcp_monitor: falha ao inicializar tabela hash\n");
        return ret;
    }

    entry = proc_create(PROC_NAME, 0, NULL, &tcp_metrics_fops);
    if (!entry) {
        pr_err("tcp_monitor: falha ao criar /proc/%s\n", PROC_NAME);
        rhashtable_destroy(&flow_table);
        put_net(monitor_netns);
        return -ENOMEM;
    }

    pr_info("tcp_monitor: monitorando conexões TCP no namespace atual\n");
    return 0;
}

static void __exit tcp_monitor_exit(void)
{
    struct rhashtable_iter iter;
    struct flow_data *entry;

    remove_proc_entry(PROC_NAME, NULL);
    if (monitor_netns)
        put_net(monitor_netns);

    rhashtable_walk_enter(&flow_table, &iter);
    rhashtable_walk_start(&iter);
    while ((entry = rhashtable_walk_next(&iter)) && !IS_ERR(entry))
        kfree(entry);
    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    rhashtable_destroy(&flow_table);

    pr_info("tcp_monitor: módulo removido\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pedro Pecolo & ChatGPT");
MODULE_DESCRIPTION("TCP metrics monitor com RET instantâneo e ΔRET(1s) acumulado");

module_init(tcp_monitor_init);
module_exit(tcp_monitor_exit);
