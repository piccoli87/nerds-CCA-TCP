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

static int tcp_metrics_show(struct seq_file *m, void *v)
{
    struct inet_hashinfo *hashinfo = &tcp_hashinfo;
    struct hlist_nulls_node *node;
    struct sock *sk;
    int i;

    seq_puts(m, "SADDR           DADDR           SPORT DPORT CWND   SRTT    RTTVAR RET SNDWND  RCVWND   DSCP  ECN  ALG       TIMESTAMP\n");

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
            u32 cwnd, srtt, rttvar, retrans, sndwnd, rcvwnd;
            u64 timestamp;
            u8 tos;
            const char *alg;

            // Filtra apenas conexões IPv4, TCP estabelecido e do mesmo namespace
            if (sk->sk_family != AF_INET)
                continue;
            if (sk->sk_state != TCP_ESTABLISHED)
                continue;
            if (sock_net(sk) != monitor_netns)
                continue;

            inet = inet_sk(sk);

            // Filtro por IPs, se definidos
            if ((src_ip_be && inet->inet_saddr != src_ip_be) ||
                (dst_ip_be && inet->inet_daddr != dst_ip_be))
                continue;

            tp = tcp_sk(sk);

            sport = ntohs(inet->inet_sport);
            dport = ntohs(inet->inet_dport);
            cwnd = tp->snd_cwnd;
            srtt = tp->srtt_us >> 3;  // srtt_us is fixed point with 3 bits fraction
            rttvar = tp->mdev_us >> 3;
            retrans = tp->retrans_out;
            sndwnd = sk->sk_sndbuf;
            rcvwnd = sk->sk_rcvbuf;
            timestamp = ktime_get_ns();
            tos = inet->tos;
            u8 dscp = tos >> 2;
            u8 ecn = tos & 0x03;

            alg = inet_csk(sk)->icsk_ca_ops->name;
            if (strncmp(alg, "tcp_", 4) == 0)
                alg += 4;  // remove o prefixo "tcp_"

            seq_printf(m, "%-15pI4 %-15pI4 %5u %5u %5u %7u %7u %3u %7u %7u %4u %3u %-10s %llu\n",
                       &inet->inet_saddr, &inet->inet_daddr,
                       sport, dport, cwnd, srtt, rttvar, retrans, sndwnd, rcvwnd,
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

    pr_info("tcp_monitor: iniciando módulo...\n");

    // Armazena o namespace atual do processo que carregou o módulo
    monitor_netns = get_net(current->nsproxy->net_ns);

    if (src_ip && !in4_pton(src_ip, -1, (u8 *)&src_ip_be, -1, NULL)) {
        pr_err("tcp_monitor: IP de origem inválido: %s\n", src_ip);
        return -EINVAL;
    }

    if (dst_ip && !in4_pton(dst_ip, -1, (u8 *)&dst_ip_be, -1, NULL)) {
        pr_err("tcp_monitor: IP de destino inválido: %s\n", dst_ip);
        return -EINVAL;
    }

    entry = proc_create(PROC_NAME, 0, NULL, &tcp_metrics_fops);
    if (!entry) {
        pr_err("tcp_monitor: falha ao criar /proc/%s\n", PROC_NAME);
        put_net(monitor_netns);  // libera se falhar
        return -ENOMEM;
    }

    pr_info("tcp_monitor: monitorando conexões TCP no namespace atual\n");
    return 0;
}

static void __exit tcp_monitor_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    if (monitor_netns)
        put_net(monitor_netns);
    pr_info("tcp_monitor: módulo removido\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adaptado por ChatGPT");
MODULE_DESCRIPTION("TCP metrics monitor (filtra por namespace de rede e identifica algoritmo)");

module_init(tcp_monitor_init);
module_exit(tcp_monitor_exit);
