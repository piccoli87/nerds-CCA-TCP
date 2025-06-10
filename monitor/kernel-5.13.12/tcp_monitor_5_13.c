// Módulo de monitoramento TCP para Kernel Linux 5.13.12
// Licença: GPL

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
MODULE_AUTHOR("Seu Nome");
MODULE_DESCRIPTION("Monitor de métricas TCP");
MODULE_VERSION("1.0");

#if LINUX_VERSION_CODE != KERNEL_VERSION(5, 13, 12)
#error "Este módulo foi desenvolvido especificamente para o kernel 5.13.12"
#endif

// Estrutura para armazenar métricas TCP
struct tcp_metrics {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 cwnd;
    u32 rtt;
    u32 rtt_var;
    u32 retrans;
    u32 snd_wnd;
    u32 rcv_wnd;
    struct hlist_node __node; // Necessário para usar em hash table
};

// Tabela hash para armazenar métricas
#define METRICS_HASH_BITS 8
static DEFINE_HASHTABLE(tcp_metrics_hash, METRICS_HASH_BITS);

// Lock para proteger a tabela hash
static DEFINE_SPINLOCK(metrics_lock);

// Função para obter chave hash
static u32 metrics_hash_key(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
    return jhash_3words((__force u32)saddr, (__force u32)daddr,
                        (__force u32)(sport << 16 | dport), 0);
}

// Atualiza ou cria entrada de métricas
static void update_metrics(const struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct tcp_metrics *tm;
    u32 hash_key;
    
    if (!sk || !tp)
        return;
    
    hash_key = metrics_hash_key(inet_sk(sk)->inet_saddr,
                                inet_sk(sk)->inet_daddr,
                                inet_sk(sk)->inet_sport,
                                inet_sk(sk)->inet_dport);
    
    spin_lock(&metrics_lock);
    
    // Procura por entrada existente
    hash_for_each_possible(tcp_metrics_hash, tm, __node, hash_key) {
        if (tm->saddr == (__force u32)inet_sk(sk)->inet_saddr &&
            tm->daddr == (__force u32)inet_sk(sk)->inet_daddr &&
            tm->sport == (__force u16)inet_sk(sk)->inet_sport &&
            tm->dport == (__force u16)inet_sk(sk)->inet_dport) {
            
            // Atualiza métricas
            tm->cwnd = tp->snd_cwnd;
            tm->rtt = tp->rcv_rtt_est.rtt_us;
            tm->rtt_var = tp->rcv_rtt_est.var_us;
            tm->retrans = tp->retrans_out;
            tm->snd_wnd = tp->snd_wnd;
            tm->rcv_wnd = tp->rcv_wnd;
            
            spin_unlock(&metrics_lock);
            return;
        }
    }
    
    // Cria nova entrada se não encontrada
    tm = kmalloc(sizeof(*tm), GFP_ATOMIC);
    if (!tm) {
        spin_unlock(&metrics_lock);
        return;
    }
    
    tm->saddr = (__force u32)inet_sk(sk)->inet_saddr;
    tm->daddr = (__force u32)inet_sk(sk)->inet_daddr;
    tm->sport = (__force u16)inet_sk(sk)->inet_sport;
    tm->dport = (__force u16)inet_sk(sk)->inet_dport;
    tm->cwnd = tp->snd_cwnd;
    tm->rtt = tp->rcv_rtt_est.rtt_us;
    tm->rtt_var = tp->rcv_rtt_est.var_us;
    tm->retrans = tp->retrans_out;
    tm->snd_wnd = tp->snd_wnd;
    tm->rcv_wnd = tp->rcv_wnd;
    
    hash_add(tcp_metrics_hash, &tm->__node, hash_key);
    
    spin_unlock(&metrics_lock);
}

// Kprobe para tcp_retransmit_skb
static struct kprobe kp_retrans = {
    .symbol_name = "tcp_retransmit_skb",
};

// Handler para kprobe de retransmissão
static int handler_retrans(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->di; // Parâmetro 1: struct sock *sk
    
    if (sk) {
        printk(KERN_INFO "Retransmissão detectada para conexão %pI4:%d -> %pI4:%d\n",
               &inet_sk(sk)->inet_saddr, ntohs(inet_sk(sk)->inet_sport),
               &inet_sk(sk)->inet_daddr, ntohs(inet_sk(sk)->inet_dport));
        update_metrics(sk);
    }
    
    return 0;
}

// Kprobe para tcp_write_xmit
static struct kprobe kp_xmit = {
    .symbol_name = "tcp_write_xmit",
};

// Handler para kprobe de transmissão
static int handler_xmit(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->di; // Parâmetro 1: struct sock *sk
    
    if (sk) {
        update_metrics(sk);
    }
    
    return 0;
}

// Kprobe para tcp_ack
static struct kprobe kp_ack = {
    .symbol_name = "tcp_ack",
};

// Handler para kprobe de ACK
static int handler_ack(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->di; // Parâmetro 1: struct sock *sk
    
    if (sk) {
        update_metrics(sk);
    }
    
    return 0;
}

// Função para exibir métricas via /proc
static int proc_show(struct seq_file *m, void *v)
{
    struct tcp_metrics *tm;
    unsigned int bkt;
    
    seq_printf(m, "Endereço Origem | Endereço Destino | Porta Origem | Porta Destino | CWND | RTT(us) | RTT_VAR | Retrans | SND_WND | RCV_WND\n");
    seq_printf(m, "-----------------------------------------------------------------------------------------------------------------\n");
    
    spin_lock(&metrics_lock);
    
    hash_for_each(tcp_metrics_hash, bkt, tm, __node) {
        seq_printf(m, "%pI4 | %pI4 | %5u | %5u | %4u | %6u | %6u | %7u | %7u | %7u\n",
                   &tm->saddr, &tm->daddr, tm->sport, tm->dport,
                   tm->cwnd, tm->rtt, tm->rtt_var, tm->retrans, tm->snd_wnd, tm->rcv_wnd);
    }
    
    spin_unlock(&metrics_lock);
    
    return 0;
}

// Operações do arquivo /proc
static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

// Inicialização do módulo
static int __init tcp_monitor_init(void)
{
    int ret;
    
    printk(KERN_INFO "Iniciando módulo de monitoramento TCP\n");
    
    // Registrar kprobes
    kp_retrans.pre_handler = handler_retrans;
    ret = register_kprobe(&kp_retrans);
    if (ret < 0) {
        printk(KERN_ERR "Falha ao registrar kprobe para retransmissão: %d\n", ret);
        return ret;
    }
    
    kp_xmit.pre_handler = handler_xmit;
    ret = register_kprobe(&kp_xmit);
    if (ret < 0) {
        printk(KERN_ERR "Falha ao registrar kprobe para transmissão: %d\n", ret);
        unregister_kprobe(&kp_retrans);
        return ret;
    }
    
    kp_ack.pre_handler = handler_ack;
    ret = register_kprobe(&kp_ack);
    if (ret < 0) {
        printk(KERN_ERR "Falha ao registrar kprobe para ACK: %d\n", ret);
        unregister_kprobe(&kp_retrans);
        unregister_kprobe(&kp_xmit);
        return ret;
    }
    
    // Criar arquivo em /proc
    proc_create("tcp_metrics", 0, NULL, &proc_fops);
    
    return 0;
}

// Limpeza do módulo
static void __exit tcp_monitor_exit(void)
{
    struct tcp_metrics *tm;
    unsigned int bkt;
    struct hlist_node *tmp;
    
    printk(KERN_INFO "Removendo módulo de monitoramento TCP\n");
    
    // Remover kprobes
    unregister_kprobe(&kp_retrans);
    unregister_kprobe(&kp_xmit);
    unregister_kprobe(&kp_ack);
    
    // Remover arquivo /proc
    remove_proc_entry("tcp_metrics", NULL);
    
    // Limpar tabela hash
    spin_lock(&metrics_lock);
    hash_for_each_safe(tcp_metrics_hash, bkt, tmp, tm, __node) {
        hash_del(&tm->__node);
        kfree(tm);
    }
    spin_unlock(&metrics_lock);
}

module_init(tcp_monitor_init);
module_exit(tcp_monitor_exit);
