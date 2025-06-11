#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/kprobes.h>
#include <linux/hash.h>
#include <linux/jhash.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pedro P. Pecolo Filho");
MODULE_DESCRIPTION("Monitor de métricas TCP para kernel 6.8+");
MODULE_VERSION("1.1");

#define TCP_CA_NAME_MAX 16

struct tcp_metrics {
    u32 saddr, daddr;
    u16 sport, dport;
    u32 cwnd;
    u32 srtt_us;
    u32 rttvar_us;
    u32 retrans;
    u32 snd_wnd;
    u32 rcv_wnd;
    char ca_name[TCP_CA_NAME_MAX];
    struct hlist_node __node;
};

#define METRICS_HASH_BITS 8
static DEFINE_HASHTABLE(tcp_metrics_hash, METRICS_HASH_BITS);
static DEFINE_SPINLOCK(metrics_lock);

static u32 metrics_hash_key(__be32 s, __be32 d, __be16 sp, __be16 dp)
{
    return jhash_3words((__force u32)s, (__force u32)d,
                        (__force u32)(sp << 16 | dp), 0);
}

static void update_metrics(const struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct tcp_metrics *tm;
    u32 key;

    if (!sk || !tp || !icsk)
        return;

    key = metrics_hash_key(inet_sk(sk)->inet_saddr,
                           inet_sk(sk)->inet_daddr,
                           inet_sk(sk)->inet_sport,
                           inet_sk(sk)->inet_dport);

    spin_lock(&metrics_lock);
    hash_for_each_possible(tcp_metrics_hash, tm, __node, key) {
        if (tm->saddr == inet_sk(sk)->inet_saddr &&
            tm->daddr == inet_sk(sk)->inet_daddr &&
            tm->sport == ntohs(inet_sk(sk)->inet_sport) &&
            tm->dport == ntohs(inet_sk(sk)->inet_dport)) {

            tm->cwnd = tp->snd_cwnd;
            tm->srtt_us = tp->srtt_us;
            tm->rttvar_us = tp->rttvar_us;
            tm->retrans = tp->retrans_out;
            tm->snd_wnd = tp->snd_wnd;
            tm->rcv_wnd = tp->rcv_wnd;
            strncpy(tm->ca_name, icsk->icsk_ca_ops ? icsk->icsk_ca_ops->name : "unknown", TCP_CA_NAME_MAX);
            tm->ca_name[TCP_CA_NAME_MAX - 1] = '\0';
            spin_unlock(&metrics_lock);
            return;
        }
    }

    tm = kmalloc(sizeof(*tm), GFP_ATOMIC);
    if (!tm) {
        spin_unlock(&metrics_lock);
        return;
    }

    tm->saddr = inet_sk(sk)->inet_saddr;
    tm->daddr = inet_sk(sk)->inet_daddr;
    tm->sport = ntohs(inet_sk(sk)->inet_sport);
    tm->dport = ntohs(inet_sk(sk)->inet_dport);
    tm->cwnd = tp->snd_cwnd;
    tm->srtt_us = tp->srtt_us;
    tm->rttvar_us = tp->rttvar_us;
    tm->retrans = tp->retrans_out;
    tm->snd_wnd = tp->snd_wnd;
    tm->rcv_wnd = tp->rcv_wnd;
    strncpy(tm->ca_name, icsk->icsk_ca_ops ? icsk->icsk_ca_ops->name : "unknown", TCP_CA_NAME_MAX);
    tm->ca_name[TCP_CA_NAME_MAX - 1] = '\0';

    hash_add(tcp_metrics_hash, &tm->__node, key);
    spin_unlock(&metrics_lock);
}

static struct kprobe kp_retrans = { .symbol_name = "tcp_retransmit_skb" };
static struct kprobe kp_xmit   = { .symbol_name = "tcp_write_xmit" };
static struct kprobe kp_ack    = { .symbol_name = "tcp_ack" };

static int handler_retrans(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->di;
    if (sk) {
        printk(KERN_INFO "TCP retransmission: %pI4:%u -> %pI4:%u\n",
               &inet_sk(sk)->inet_saddr, ntohs(inet_sk(sk)->inet_sport),
               &inet_sk(sk)->inet_daddr, ntohs(inet_sk(sk)->inet_dport));
        update_metrics(sk);
    }
    return 0;
}

static int handler_xmit(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->di;
    if (sk) update_metrics(sk);
    return 0;
}

static int handler_ack(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->di;
    if (sk) update_metrics(sk);
    return 0;
}

static int proc_show(struct seq_file *m, void *v)
{
    struct tcp_metrics *tm;
    unsigned bkt;
    seq_printf(m, "SADDR       DADDR       SPORT DPORT CWND  SRTT  RTTVAR RET  SNDWND RCVWND ALG\n");
    spin_lock(&metrics_lock);
    hash_for_each(tcp_metrics_hash, bkt, tm, __node) {
        seq_printf(m, "%pI4 %pI4 %5u %5u %4u %6u %7u %4u %7u %7u %s\n",
                   &tm->saddr, &tm->daddr, tm->sport, tm->dport,
                   tm->cwnd, tm->srtt_us, tm->rttvar_us,
                   tm->retrans, tm->snd_wnd, tm->rcv_wnd,
                   tm->ca_name);
    }
    spin_unlock(&metrics_lock);
    return 0;
}

static int proc_open(struct inode *i, struct file *f)
{
    return single_open(f, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open    = proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init tcp_monitor_init(void)
{
    int ret;
    printk(KERN_INFO "[tcp_monitor_68] initializing...\n");

    kp_retrans.pre_handler = handler_retrans;
    kp_xmit.pre_handler   = handler_xmit;
    kp_ack.pre_handler    = handler_ack;

    ret = register_kprobe(&kp_retrans);
    if (ret) return ret;
    ret = register_kprobe(&kp_xmit);
    if (ret) {
        unregister_kprobe(&kp_retrans);
        return ret;
    }
    ret = register_kprobe(&kp_ack);
    if (ret) {
        unregister_kprobe(&kp_retrans);
        unregister_kprobe(&kp_xmit);
        return ret;
    }

    proc_create("tcp_metrics", 0, NULL, &proc_fops);
    return 0;
}

static void __exit tcp_monitor_exit(void)
{
    struct tcp_metrics *tm;
    struct hlist_node *tmp;
    unsigned bkt;

    printk(KERN_INFO "[tcp_monitor_68] exiting...\n");
    unregister_kprobe(&kp_retrans);
    unregister_kprobe(&kp_xmit);
    unregister_kprobe(&kp_ack);
    remove_proc_entry("tcp_metrics", NULL);

    spin_lock(&metrics_lock);
    hash_for_each_safe(tcp_metrics_hash, bkt, tmp, tm, __node) {
        hash_del(&tm->__node);
        kfree(tm);
    }
    spin_unlock(&metrics_lock);
}

module_init(tcp_monitor_init);
module_exit(tcp_monitor_exit);
