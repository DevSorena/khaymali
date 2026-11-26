// SPDX-License-Identifier: GPL-2.0
/*
 * Khaymali v0.9.0 Hardened Kernel TCP-Mux + FakeTLS L3 Tunnel (`mux0`)
 *
 * Security & Stability Hardenings over initial prototype:
 *   1. Keyed rolling keystream (`obfs_secret` 32-hex param) with backward-compatible
 *      `obfs_key` fallback instead of static single-byte XOR alone.
 *   2. Strict `record_len` and `inner_len` boundary checks preventing malformed packet injection.
 *   3. Bounds-checked `/proc/net/ktun_sync` parser and safe `mux0` teardown.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_arp.h>
#include <linux/percpu.h>
#include <linux/atomic.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/protocol.h>
#include "ktun_proto.h"

#define DRV_NAME "k_tcpmux"
#define MUX_FLOW_COUNT 8
#define TLS_RECORD_HDR_LEN 5
#define MUX_FRAME_HDR_LEN 4
#define TOTAL_ENCAP_OVERHEAD (sizeof(struct iphdr) + sizeof(struct tcphdr) + \
                              TLS_RECORD_HDR_LEN + MUX_FRAME_HDR_LEN)

static char *local_ip_str = "10.0.0.1";
module_param(local_ip_str, charp, 0644);
static char *remote_ip_str = "10.0.0.2";
module_param(remote_ip_str, charp, 0644);
static int is_server = 0;
module_param(is_server, int, 0644);
static int server_port = 443;
module_param(server_port, int, 0644);
static int base_client_port = 49152;
module_param(base_client_port, int, 0644);
static int obfs_key = 0x7A;
module_param(obfs_key, int, 0600);
static char *obfs_secret = "";
module_param(obfs_secret, charp, 0600);

static u8 parsed_secret[16];
static bool has_parsed_secret = false;

struct __packed tls_mux_hdr {
    __u8   content_type;
    __u8   version_maj;
    __u8   version_min;
    __be16 record_len;
    __be16 stream_id;
    __u8   mux_flags;
    __u8   pad_len;
};

struct tcp_subflow {
    atomic_t seq;
    atomic_t ack_seq;
    __be16   src_port;
    __be16   dst_port;
    atomic_t active;
} ____cacheline_aligned_in_smp;

struct ktunnel_priv {
    struct net_device *dev;
    __be32 local_ip;
    __be32 remote_ip;
    atomic_t rr_counter;
    struct tcp_subflow flows[MUX_FLOW_COUNT];
};

static struct net_device *ktun_dev;
static struct proc_dir_entry *ktun_proc_entry;

static void parse_hex_secret(void)
{
    size_t slen = strlen(obfs_secret);
    size_t i;

    if (slen < 32) {
        has_parsed_secret = false;
        return;
    }
    for (i = 0; i < 16; i++) {
        char tmp[3] = { obfs_secret[i * 2], obfs_secret[i * 2 + 1], '\0' };
        u8 val = 0;
        if (kstrtou8(tmp, 16, &val) != 0) {
            has_parsed_secret = false;
            return;
        }
        parsed_secret[i] = val;
    }
    has_parsed_secret = true;
}

static inline void fast_obfuscate_payload(u8 *data, unsigned int len, u8 key, u32 seq_salt)
{
    unsigned int mask_len = min_t(unsigned int, len, 128);
    unsigned int i;

    if (has_parsed_secret) {
        u32 state = seq_salt ^ 0x9E3779B9U;
        for (i = 0; i < mask_len; i++) {
            state = state * 1664525U + 1013904223U;
            data[i] ^= parsed_secret[i & 0x0F] ^ (u8)(state >> 24);
        }
    } else {
        for (i = 0; i < mask_len; i++)
            data[i] ^= (key + (i & 0x0F));
    }
}

static netdev_tx_t ktun_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct ktunnel_priv *priv = netdev_priv(dev);
    struct iphdr *outer_iph;
    struct tcphdr *outer_tcph;
    struct tls_mux_hdr *tlsh;
    struct tcp_subflow *flow = NULL;
    struct rtable *rt;
    struct flowi4 fl4;
    u32 flow_idx = 0, start_idx, i, seq_num, payload_len;
    u16 inner_tot_len;

    if (skb->protocol != htons(ETH_P_IP)) {
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        if (skb_checksum_help(skb)) {
            dev->stats.tx_dropped++;
            dev_kfree_skb_any(skb);
            return NETDEV_TX_OK;
        }
    }

    inner_tot_len = skb->len;
    if (inner_tot_len == 0 || inner_tot_len > KTUN_MAX_PAYLOAD) {
        dev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    /* Round-Robin with Active-Flow Fallback (prevents single-flow stalls) */
    start_idx = (u32)atomic_inc_return(&priv->rr_counter);
    for (i = 0; i < MUX_FLOW_COUNT; i++) {
        u32 candidate = (start_idx + i) & (MUX_FLOW_COUNT - 1);
        if (atomic_read(&priv->flows[candidate].active)) {
            flow_idx = candidate;
            flow = &priv->flows[flow_idx];
            break;
        }
    }
    if (!flow) {
        flow_idx = start_idx & (MUX_FLOW_COUNT - 1);
        flow = &priv->flows[flow_idx];
    }

    if (unlikely(skb_cow_head(skb, TOTAL_ENCAP_OVERHEAD + 64))) {
        dev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    skb_orphan(skb);
    nf_reset_ct(skb);
    skb_dst_drop(skb);

    payload_len = inner_tot_len + sizeof(struct tls_mux_hdr);
    seq_num = (u32)atomic_add_return(payload_len, &flow->seq) - payload_len;

    tlsh = (struct tls_mux_hdr *)skb_push(skb, sizeof(struct tls_mux_hdr));
    tlsh->content_type = 0x17;
    tlsh->version_maj  = 0x03;
    tlsh->version_min  = 0x03;
    tlsh->record_len   = htons(inner_tot_len + MUX_FRAME_HDR_LEN);
    tlsh->stream_id    = htons((u16)flow_idx);
    tlsh->mux_flags    = 0x01;
    tlsh->pad_len      = 0x00;

    fast_obfuscate_payload((u8 *)&tlsh->stream_id,
                           inner_tot_len + MUX_FRAME_HDR_LEN,
                           (u8)obfs_key,
                           seq_num);

    skb_push(skb, sizeof(struct tcphdr));
    skb_reset_transport_header(skb);
    outer_tcph = tcp_hdr(skb);
    memset(outer_tcph, 0, sizeof(struct tcphdr));
    outer_tcph->source  = flow->src_port;
    outer_tcph->dest    = flow->dst_port;
    outer_tcph->seq     = htonl(seq_num);
    outer_tcph->ack_seq = htonl(atomic_read(&flow->ack_seq));
    outer_tcph->doff    = sizeof(struct tcphdr) >> 2;
    outer_tcph->psh     = 1;
    outer_tcph->ack     = 1;
    outer_tcph->window  = htons(65535);

    skb_push(skb, sizeof(struct iphdr));
    skb_reset_network_header(skb);
    outer_iph = ip_hdr(skb);
    memset(outer_iph, 0, sizeof(struct iphdr));
    outer_iph->version  = 4;
    outer_iph->ihl      = 5;
    outer_iph->tos      = 0;
    outer_iph->tot_len  = htons(skb->len);
    outer_iph->id       = 0;
    outer_iph->frag_off = htons(IP_DF);
    outer_iph->ttl      = 64;
    outer_iph->protocol = IPPROTO_TCP;
    outer_iph->saddr    = priv->local_ip;
    outer_iph->daddr    = priv->remote_ip;
    ip_send_check(outer_iph);

    outer_tcph->check = 0;
    skb->ip_summed = CHECKSUM_NONE;
    outer_tcph->check = tcp_v4_check(skb->len - sizeof(struct iphdr),
                                     outer_iph->saddr, outer_iph->daddr,
                                     csum_partial(outer_tcph,
                                                  skb->len - sizeof(struct iphdr), 0));

    memset(&fl4, 0, sizeof(fl4));
    fl4.daddr = priv->remote_ip;
    fl4.saddr = priv->local_ip;
    fl4.flowi4_proto = IPPROTO_TCP;

    rt = ip_route_output_key(dev_net(dev), &fl4);
    if (IS_ERR(rt)) {
        dev->stats.tx_errors++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    skb_dst_set(skb, &rt->dst);
    dev_sw_netstats_tx_add(dev, 1, inner_tot_len);
    ip_local_out(dev_net(dev), NULL, skb);
    return NETDEV_TX_OK;
}

static unsigned int ktun_nf_rx_hook(void *priv_data,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    struct ktunnel_priv *priv;
    struct iphdr *iph, *inner_iph;
    struct tcphdr *tcph;
    struct tls_mux_hdr *tlsh;
    unsigned int ip_hdr_len, tcp_hdr_len, hdr_len, inner_len, rec_len;
    u32 rx_seq, seg_len;
    int i, flow_idx = -1;

    (void)priv_data;
    (void)state;

    if (!ktun_dev)
        return NF_ACCEPT;

    priv = netdev_priv(ktun_dev);

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP || iph->saddr != priv->remote_ip)
        return NF_ACCEPT;

    ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) ||
        !pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((u8 *)iph + ip_hdr_len);
    tcp_hdr_len = tcph->doff * 4;

    if (tcp_hdr_len < sizeof(struct tcphdr))
        return NF_ACCEPT;

    for (i = 0; i < MUX_FLOW_COUNT; i++) {
        if (tcph->source == priv->flows[i].dst_port &&
            tcph->dest   == priv->flows[i].src_port) {
            flow_idx = i;
            break;
        }
    }

    if (flow_idx < 0) {
        u16 sport = ntohs(tcph->source);
        u16 dport = ntohs(tcph->dest);
        if (sport >= base_client_port && sport < base_client_port + MUX_FLOW_COUNT)
            flow_idx = sport - base_client_port;
        else if (dport >= base_client_port && dport < base_client_port + MUX_FLOW_COUNT)
            flow_idx = dport - base_client_port;
        else
            return NF_ACCEPT;
    }

    hdr_len = ip_hdr_len + tcp_hdr_len + sizeof(struct tls_mux_hdr);
    if (!pskb_may_pull(skb, hdr_len + sizeof(struct iphdr)))
        return NF_ACCEPT;

    if (skb_try_make_writable(skb, skb->len))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((u8 *)iph + ip_hdr_len);
    tlsh = (struct tls_mux_hdr *)((u8 *)tcph + tcp_hdr_len);

    if (tlsh->content_type != 0x17 ||
        tlsh->version_maj  != 0x03 ||
        tlsh->version_min  != 0x03)
        return NF_ACCEPT;

    rec_len = ntohs(tlsh->record_len);
    if (rec_len < MUX_FRAME_HDR_LEN + sizeof(struct iphdr) ||
        ip_hdr_len + tcp_hdr_len + TLS_RECORD_HDR_LEN + rec_len > skb->len)
        return NF_ACCEPT;

    rx_seq = ntohl(tcph->seq);
    seg_len = skb->len - ip_hdr_len - tcp_hdr_len;
    atomic_set(&priv->flows[flow_idx].ack_seq, rx_seq + seg_len);

    fast_obfuscate_payload((u8 *)&tlsh->stream_id,
                           rec_len,
                           (u8)obfs_key,
                           rx_seq);

    __skb_pull(skb, hdr_len);
    skb_reset_network_header(skb);
    skb_reset_mac_header(skb);
    inner_iph = ip_hdr(skb);

    if (inner_iph->version != 4 || inner_iph->ihl < 5) {
        dev_kfree_skb_any(skb);
        return NF_STOLEN;
    }

    inner_len = ntohs(inner_iph->tot_len);
    if (inner_len < sizeof(struct iphdr) || inner_len > skb->len) {
        dev_kfree_skb_any(skb);
        return NF_STOLEN;
    }

    if (skb->len > inner_len)
        __skb_trim(skb, inner_len);

    skb_set_transport_header(skb, inner_iph->ihl * 4);

    skb->protocol = htons(ETH_P_IP);
    skb->pkt_type = PACKET_HOST;
    skb->dev = ktun_dev;
    skb->ip_summed = CHECKSUM_UNNECESSARY;

    skb_orphan(skb);
    nf_reset_ct(skb);
    skb_dst_drop(skb);

    dev_sw_netstats_rx_add(ktun_dev, skb->len);
    netif_rx(skb);
    return NF_STOLEN;
}

static ssize_t ktun_proc_write(struct file *file, const char __user *ubuf,
                               size_t count, loff_t *ppos)
{
    struct ktunnel_priv *priv;
    char buf[128];
    unsigned int idx, s_port, d_port;
    u32 snd_nxt, rcv_nxt;

    (void)file;
    (void)ppos;

    if (!ktun_dev || count == 0 || count >= sizeof(buf))
        return -EINVAL;
    if (copy_from_user(buf, ubuf, count))
        return -EFAULT;
    buf[count] = '\0';

    if (sscanf(buf, "%u %u %u %u %u", &idx, &snd_nxt, &rcv_nxt, &s_port, &d_port) != 5)
        return -EINVAL;

    if (idx >= MUX_FLOW_COUNT || s_port == 0 || s_port > 65535 || d_port == 0 || d_port > 65535)
        return -EINVAL;

    priv = netdev_priv(ktun_dev);
    atomic_set(&priv->flows[idx].seq, snd_nxt);
    atomic_set(&priv->flows[idx].ack_seq, rcv_nxt);
    priv->flows[idx].src_port = htons((u16)s_port);
    priv->flows[idx].dst_port = htons((u16)d_port);
    atomic_set(&priv->flows[idx].active, 1);

    return count;
}

static int ktun_proc_show(struct seq_file *m, void *v)
{
    struct ktunnel_priv *priv = netdev_priv(ktun_dev);
    int i;

    (void)v;
    seq_printf(m, "Flow\tActive\tSrcPort\tDstPort\tSND_NXT\t\tRCV_NXT\n");
    for (i = 0; i < MUX_FLOW_COUNT; i++) {
        seq_printf(m, "%d\t%d\t%u\t%u\t%u\t%u\n",
                   i,
                   atomic_read(&priv->flows[i].active),
                   ntohs(priv->flows[i].src_port),
                   ntohs(priv->flows[i].dst_port),
                   (u32)atomic_read(&priv->flows[i].seq),
                   (u32)atomic_read(&priv->flows[i].ack_seq));
    }
    return 0;
}

static int ktun_proc_open(struct inode *inode, struct file *file)
{
    (void)inode;
    return single_open(file, ktun_proc_show, NULL);
}

static const struct proc_ops ktun_proc_ops = {
    .proc_open    = ktun_proc_open,
    .proc_read    = seq_read,
    .proc_write   = ktun_proc_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static struct nf_hook_ops ktun_nf_ops = {
    .hook     = ktun_nf_rx_hook,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static const struct net_device_ops ktun_netdev_ops = {
    .ndo_start_xmit  = ktun_xmit,
    .ndo_get_stats64 = dev_get_tstats64,
};

static void ktun_setup(struct net_device *dev)
{
    dev->netdev_ops      = &ktun_netdev_ops;
    dev->type            = ARPHRD_NONE;
    dev->flags           = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
    dev->addr_len        = 0;
    dev->mtu             = 1340;
    dev->needed_headroom = TOTAL_ENCAP_OVERHEAD + 64;
    dev->features        = 0;
    dev->hw_features     = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    dev->pcpu_stat_type  = NETDEV_PCPU_STAT_TSTATS;
#endif
}

static int __init ktun_init(void)
{
    struct ktunnel_priv *priv;
    int ret, i;

    parse_hex_secret();

    ktun_dev = alloc_netdev(sizeof(struct ktunnel_priv), "mux%d",
                            NET_NAME_UNKNOWN, ktun_setup);
    if (!ktun_dev)
        return -ENOMEM;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
    ktun_dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
    if (!ktun_dev->tstats) {
        free_netdev(ktun_dev);
        return -ENOMEM;
    }
#endif

    priv = netdev_priv(ktun_dev);
    priv->dev = ktun_dev;
    priv->local_ip  = in_aton(local_ip_str);
    priv->remote_ip = in_aton(remote_ip_str);
    atomic_set(&priv->rr_counter, 0);

    for (i = 0; i < MUX_FLOW_COUNT; i++) {
        u16 c_port = base_client_port + i;
        atomic_set(&priv->flows[i].seq, get_random_u32());
        atomic_set(&priv->flows[i].ack_seq, get_random_u32());
        atomic_set(&priv->flows[i].active, 0);
        priv->flows[i].src_port = htons(is_server ? server_port : c_port);
        priv->flows[i].dst_port = htons(is_server ? c_port : server_port);
    }

    ret = register_netdev(ktun_dev);
    if (ret)
        goto err_free;

    ret = nf_register_net_hook(&init_net, &ktun_nf_ops);
    if (ret)
        goto err_unreg;

    ktun_proc_entry = proc_create("ktun_sync", 0600, init_net.proc_net, &ktun_proc_ops);
    if (!ktun_proc_entry) {
        ret = -ENOMEM;
        goto err_nf;
    }

    return 0;

err_nf:
    nf_unregister_net_hook(&init_net, &ktun_nf_ops);
err_unreg:
    unregister_netdev(ktun_dev);
err_free:
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
    free_percpu(ktun_dev->tstats);
#endif
    free_netdev(ktun_dev);
    return ret;
}

static void __exit ktun_exit(void)
{
    if (ktun_proc_entry)
        proc_remove(ktun_proc_entry);
    nf_unregister_net_hook(&init_net, &ktun_nf_ops);
    unregister_netdev(ktun_dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
    free_percpu(ktun_dev->tstats);
#endif
    free_netdev(ktun_dev);
}

module_init(ktun_init);
module_exit(ktun_exit);
MODULE_DESCRIPTION("Khaymali v0.9.0 Hardened Kernel TCP-Mux + FakeTLS Tunnel");
MODULE_LICENSE("GPL");
