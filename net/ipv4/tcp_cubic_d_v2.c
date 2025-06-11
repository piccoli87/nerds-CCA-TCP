// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP CUBIC-D: CUBIC with Delay Variation Monitoring + BER Loss Detection
 * Combina escalabilidade do CUBIC com sensibilidade a variação de delay
 * e diferenciação de perdas por BER.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define BICTCP_BETA_SCALE    1024
#define BICTCP_HZ           10
#define CUBIC_D_MIN_SAMPLES 8    // Número mínimo de amostras para decisão

// EWMA para RTT
#define CUBIC_D_EWMA_ALPHA 8
#define CUBIC_D_VAR_ALPHA 4

struct cubic_d {
    // Estrutura original do CUBIC
    u32 cnt;
    u32 last_max_cwnd;
    u32 last_cwnd;
    u32 last_time;
    u32 bic_origin_point;
    u32 bic_K;
    u32 epoch_start;
    u32 ack_cnt;
    u32 tcp_cwnd;

    // Monitoramento de delay (CDG-like)
    struct {
        u32 min;
        u32 max;
    } delay;
    u32 delay_prev;
    u8 delack;

    // Estados adicionais
    enum {
        CUBIC_D_NORMAL,
        CUBIC_D_CAUTION,
        CUBIC_D_BACKOFF,
        CUBIC_D_BER_LOSS
    } state;

    u32 samples;

    // Estatísticas dinâmicas de RTT
    u32 rtt_ewma;
    u32 rtt_var;

    // Contadores de perda
    u32 loss_ber_count;
    u32 loss_cong_count;
};

static int cubic_d_beta __read_mostly = 717; // 717/1024 ~= 0.7
static int cubic_d_delay_thresh __read_mostly = 4; // Threshold inicial (não usado diretamente agora)

module_param(cubic_d_beta, int, 0644);
MODULE_PARM_DESC(cubic_d_beta, "beta for multiplicative decrease");
module_param(cubic_d_delay_thresh, int, 0644);
MODULE_PARM_DESC(cubic_d_delay_thresh, "initial delay threshold (percentage)");

static void cubic_d_reset(struct cubic_d *ca)
{
    memset(ca, 0, sizeof(*ca));
    ca->state = CUBIC_D_NORMAL;
    ca->delay.min = ~0U;
    ca->delay.max = 0;
    ca->samples = 0;
    ca->rtt_ewma = 0;
    ca->rtt_var = 0;
}

static void cubic_d_update_delay_stats(struct cubic_d *ca, u32 rtt)
{
    u32 diff;

    if (ca->rtt_ewma == 0)
        ca->rtt_ewma = rtt;
    else
        ca->rtt_ewma = (ca->rtt_ewma * (CUBIC_D_EWMA_ALPHA - 1) + rtt)
                       / CUBIC_D_EWMA_ALPHA;

    diff = (rtt > ca->rtt_ewma) ? (rtt - ca->rtt_ewma) : (ca->rtt_ewma - rtt);
    if (ca->rtt_var == 0)
        ca->rtt_var = diff;
    else
        ca->rtt_var = (ca->rtt_var * (CUBIC_D_VAR_ALPHA - 1) + diff)
                      / CUBIC_D_VAR_ALPHA;
}

static u32 cubic_d_get_dynamic_thresh(struct cubic_d *ca)
{
    u32 k = 3; // Aumentado de 2 para 3 para maior tolerância à variação de delay
    return ca->rtt_ewma + (k * ca->rtt_var);
}

static void cubic_d_update(struct cubic_d *ca, u32 cwnd, u32 acked)
{
    u32 delta, t, offs, bic_target, max_cnt;

    ca->ack_cnt += acked;

    if (ca->epoch_start == 0) {
        ca->epoch_start = tcp_jiffies32;

        if (cwnd < ca->last_max_cwnd) {
            ca->bic_K = int_sqrt((ca->last_max_cwnd - cwnd) << BICTCP_HZ);
            ca->bic_origin_point = ca->last_max_cwnd;
        } else {
            ca->bic_K = 0;
            ca->bic_origin_point = cwnd;
        }

        ca->ack_cnt = acked;
        ca->tcp_cwnd = cwnd;
        ca->last_time = tcp_jiffies32;
        ca->last_cwnd = cwnd;
    }

    t = ((tcp_jiffies32 >> (BICTCP_HZ - HZ)) - (ca->epoch_start >> (BICTCP_HZ - HZ))) << BICTCP_HZ;

    if (t < ca->bic_K << BICTCP_HZ)
        offs = (ca->bic_K << BICTCP_HZ) - t;
    else
        offs = t - (ca->bic_K << BICTCP_HZ);

    delta = (offs * offs) >> (2 * BICTCP_HZ);

    if (t < ca->bic_K << BICTCP_HZ)
        bic_target = ca->bic_origin_point - delta;
    else
        bic_target = ca->bic_origin_point + delta;

    if (bic_target > cwnd)
        ca->cnt = cwnd / (bic_target - cwnd);
    else
        ca->cnt = 100 * cwnd;

    // Ajuste para permitir maior exploração da cwnd no estado CAUTION
    max_cnt = (ca->state == CUBIC_D_CAUTION) ? 40 : 20;
    if (ca->cnt > max_cnt)
        ca->cnt = max_cnt;
}

static void cubic_d_acked(struct sock *sk, const struct ack_sample *sample)
{
    struct cubic_d *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    u32 delay;

    if (sample->rtt_us <= 0)
        return;

    delay = sample->rtt_us;

    if (tp->sacked_out == 0) {
        if (sample->pkts_acked == 1 && ca->delack) {
            ca->delay.min = min(ca->delay.min, delay);
            ca->delack--;
            return;
        } else if (sample->pkts_acked > 1 && ca->delack < 5) {
            ca->delack++;
        }
    }

    ca->delay.min = min_not_zero(ca->delay.min, delay);
    ca->delay.max = max(ca->delay.max, delay);

    cubic_d_update_delay_stats(ca, delay);

    if (ca->samples < CUBIC_D_MIN_SAMPLES) {
        ca->samples++;
        return;
    }

    {
        u32 thresh = cubic_d_get_dynamic_thresh(ca);

        if (ca->delay.max > thresh) {
            if (ca->state == CUBIC_D_NORMAL) {
                ca->state = CUBIC_D_CAUTION;

                // Ajuste para explorar mais a cwnd (exemplo: reduzir beta para menos agressivo)
                tp->snd_cwnd = (tp->snd_cwnd * (cubic_d_beta + 100)) / BICTCP_BETA_SCALE;
                tp->snd_cwnd = max(tp->snd_cwnd, 2U);
            }
        } else if (ca->delay.max <= ca->delay.min) {
            ca->state = CUBIC_D_NORMAL;
        }
    }
}

static void cubic_d_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct cubic_d *ca = inet_csk_ca(sk);

    if (!tcp_is_cwnd_limited(sk))
        return;

    if (ca->state == CUBIC_D_BACKOFF) {
        tcp_reno_cong_avoid(sk, ack, acked);
        return;
    }

    if (tcp_in_slow_start(tp)) {
        acked = tcp_slow_start(tp, acked);
        if (!acked)
            return;
    }

    cubic_d_update(ca, tp->snd_cwnd, acked);

    if (ca->state == CUBIC_D_CAUTION)
        ca->cnt = max(ca->cnt, 16U);  // maior agressividade para aumentar cwnd mais rápido

    tcp_cong_avoid_ai(tp, ca->cnt, acked);
}

static u32 cubic_d_ssthresh(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    struct cubic_d *ca = inet_csk_ca(sk);

    if (ca->state == CUBIC_D_BACKOFF) {
        return max((tp->snd_cwnd * cubic_d_beta) / BICTCP_BETA_SCALE, 2U);
    }

    ca->epoch_start = 0;
    if (tp->snd_cwnd < ca->last_max_cwnd) {
        ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + cubic_d_beta))
                            / (2 * BICTCP_BETA_SCALE);
    } else {
        ca->last_max_cwnd = tp->snd_cwnd;
    }

    return max((tp->snd_cwnd * cubic_d_beta) / BICTCP_BETA_SCALE, 2U);
}

static void cubic_d_state(struct sock *sk, u8 new_state)
{
    struct cubic_d *ca = inet_csk_ca(sk);

    if (new_state == TCP_CA_Loss) {
        u32 thresh = cubic_d_get_dynamic_thresh(ca);

        if (ca->samples >= CUBIC_D_MIN_SAMPLES &&
            ca->delay.max <= thresh) {
            ca->state = CUBIC_D_BER_LOSS;
            ca->loss_ber_count++;
        } else {
            ca->state = CUBIC_D_BACKOFF;
            ca->loss_cong_count++;
        }

        cubic_d_reset(ca);
    }
}

static void cubic_d_init(struct sock *sk)
{
    struct cubic_d *ca = inet_csk_ca(sk);
    cubic_d_reset(ca);
}

static void cubic_d_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
    struct cubic_d *ca = inet_csk_ca(sk);

    if (ev == CA_EVENT_TX_START) {
        ca->epoch_start = 0;
    }
}

static struct tcp_congestion_ops cubic_d __read_mostly = {
    .init           = cubic_d_init,
    .ssthresh       = cubic_d_ssthresh,
    .cong_avoid     = cubic_d_cong_avoid,
    .set_state      = cubic_d_state,
    .undo_cwnd      = tcp_reno_undo_cwnd,
    .cwnd_event     = cubic_d_cwnd_event,
    .pkts_acked     = cubic_d_acked,
    .owner          = THIS_MODULE,
    .name           = "cubic_d",
};

static int __init cubic_d_register(void)
{
    return tcp_register_congestion_control(&cubic_d);
}

static void __exit cubic_d_unregister(void)
{
    tcp_unregister_congestion_control(&cubic_d);
}

module_init(cubic_d_register);
module_exit(cubic_d_unregister);

MODULE_AUTHOR("Seu Nome");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP CUBIC-D with Delay Variation Monitoring and BER Loss Detection");

