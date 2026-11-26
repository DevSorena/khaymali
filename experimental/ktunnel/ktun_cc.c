// SPDX-License-Identifier: GPL-2.0
/* Custom Loss-Tolerant TCP Congestion Control for Multiplexed Tunnels (`ktun_cc`) */
#include <linux/module.h>
#include <net/tcp.h>

static void ktun_cc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    (void)ack;
    if (!tcp_is_cwnd_limited(sk))
        return;
    if (tcp_in_slow_start(tp)) {
        acked = tcp_slow_start(tp, acked);
        if (!acked)
            return;
    }
    /* Fast recovery & steady window growth */
    tcp_cong_avoid_ai(tp, max(tp->snd_cwnd / 2U, 1U), acked);
}

static u32 ktun_cc_ssthresh(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    /* Only reduce window by 12.5% (7/8) on packet loss instead of 50% */
    return max((tp->snd_cwnd * 7U) >> 3, 16U);
}

static struct tcp_congestion_ops ktun_cc_ops __read_mostly = {
    .name       = "ktun_cc",
    .owner      = THIS_MODULE,
    .ssthresh   = ktun_cc_ssthresh,
    .cong_avoid = ktun_cc_cong_avoid,
    .undo_cwnd  = tcp_reno_undo_cwnd,
};

static int __init ktun_cc_init(void)
{
    return tcp_register_congestion_control(&ktun_cc_ops);
}

static void __exit ktun_cc_exit(void)
{
    tcp_unregister_congestion_control(&ktun_cc_ops);
}

module_init(ktun_cc_init);
module_exit(ktun_cc_exit);
MODULE_LICENSE("GPL");
