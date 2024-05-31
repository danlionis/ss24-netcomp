#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

const volatile struct {
    __u8 backend_count;
    struct in_addr vip;
} l4_lb_cfg = {};

/* This is the data record stored in the map */
struct backend {
    __be32 ip;
    __u64 num_flows;
    __u64 num_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct backend);
    __uint(max_entries, 1024);
} backend_map SEC(".maps");

struct connection {
    __be32 dst_addr;
    __be32 src_addr;
    __be16 dst_port;
    __be16 src_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct connection);
    __type(value, int);
    __uint(max_entries, 1024);
} connections_map SEC(".maps");

__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

__attribute__((__always_inline__)) static inline void ipv4_csum(void *data_start, int data_size,
                                                                __u64 *csum) {
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void
ipv4_l4_csum(void *data_start, __u32 data_size, __u64 *csum, struct iphdr *iph) {
    __u32 tmp = 0;
    *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
    *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
    tmp = __builtin_bswap32((__u32)(iph->protocol));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    tmp = __builtin_bswap32((__u32)(data_size));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper(*csum);
}

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off,
                                        struct ethhdr **ethhdr) {
    struct ethhdr *eth = (struct ethhdr *)data;
    int hdr_size = sizeof(*eth);

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if ((void *)eth + hdr_size > data_end)
        return -1;

    *nh_off += hdr_size;
    *ethhdr = eth;

    return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off,
                                       struct iphdr **iphdr) {
    struct iphdr *ip = data + *nh_off;
    int hdr_size;

    if ((void *)ip + sizeof(*ip) > data_end)
        return -1;

    hdr_size = ip->ihl * 4;

    /* Sanity check packet field is valid */
    if (hdr_size < sizeof(*ip))
        return -1;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if ((void *)ip + hdr_size > data_end)
        return -1;

    // It can also be written as:
    // if (data + *nh_off + hdr_size > data_end)
    //    return -1;

    *nh_off += hdr_size;
    *iphdr = ip;

    return ip->protocol;
}

static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off,
                                        struct udphdr **udphdr) {
    struct udphdr *udp = data + *nh_off;
    int hdr_size = sizeof(*udp);

    if ((void *)udp + hdr_size > data_end)
        return -1;

    *nh_off += hdr_size;
    *udphdr = udp;

    int len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
    if (len < 0)
        return -1;

    return len;
}

__u64 backend_load(int i) {
    struct backend *tmp = bpf_map_lookup_elem(&backend_map, &i);
    if (!tmp) {
        return UINT32_MAX;
    }
    return tmp->num_packets / tmp->num_flows;
}

SEC("xdp")
int l4_lb(struct xdp_md *ctx) {
    void *data_end;
    void *data;
    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    __u16 nf_off = 0;
    struct ethhdr *eth;
    int eth_type;

    bpf_printk("Packet received");

    eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

    if (eth_type != bpf_ntohs(ETH_P_IP))
        goto pass;

    bpf_printk("Packet is IPv4");

    // Handle IPv4 and parse ICMP
    int ip_type;
    struct iphdr *iphdr;
    ip_type = parse_iphdr(data, data_end, &nf_off, &iphdr);

    if (ip_type != IPPROTO_UDP)
        goto pass;
    bpf_printk("Packet is UDP");

    struct udphdr *udphdr;
    if (parse_udphdr(data, data_end, &nf_off, &udphdr) < 0)
        goto drop;

    __be32 dst_addr = iphdr->daddr;
    __be32 src_addr = iphdr->saddr;
    __be16 dst_port = udphdr->dest;
    __be16 src_port = udphdr->source;

    struct connection conn = {
        .dst_addr = dst_addr,
        .src_addr = src_addr,
        .dst_port = dst_port,
        .src_port = src_port,
    };

    struct backend *backend;
    int *backend_idx_ptr = bpf_map_lookup_elem(&connections_map, &conn);
    int new_flow = 0;
    int backend_idx = -1;

    if (backend_idx_ptr) {
        backend_idx = *backend_idx_ptr;
    }

    if (backend_idx == -1) {
        new_flow = 1;
        // conn not assigned to a backend
        __u32 min_load = UINT32_MAX;

        for (int i = 0; i < l4_lb_cfg.backend_count; i++) {
            __u64 load = backend_load(i);
            if (load < min_load) {
                min_load = load;
                backend_idx = i;
            }
        }
    }

    backend = bpf_map_lookup_elem(&backend_map, &backend_idx);
    if (!backend) {
        return XDP_ABORTED;
    }

    __sync_fetch_and_add(&backend->num_packets, 1);
    if (new_flow) {
        __sync_fetch_and_add(&backend->num_flows, 1);
    }

    // encapsulate packet in new ip packet

    // adjust head size
    __u16 ihl = iphdr->ihl * 4;
    if (bpf_xdp_adjust_head(ctx, 0 - ihl) != 0) {
        bpf_printk("could not adjust head");
        return XDP_DROP;
    }

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    struct ethhdr *old_eth = data + sizeof(struct iphdr);
    if ((void *)old_eth + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;
    __builtin_memcpy(data, old_eth, sizeof(*old_eth));

    struct iphdr *outer_iphdr;
    outer_iphdr = (void *)eth + sizeof(struct ethhdr);
    iphdr = (void *)outer_iphdr + sizeof(struct iphdr);
    if ((void *)eth + sizeof(struct ethhdr) > data_end ||
        (void *)outer_iphdr + sizeof(struct iphdr) > data_end ||
        (void *)iphdr + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    unsigned char tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);

    __builtin_memcpy(outer_iphdr, iphdr, sizeof(*outer_iphdr));

    outer_iphdr->daddr = backend->ip;
    outer_iphdr->protocol = IPPROTO_IPIP;
    outer_iphdr->tot_len = bpf_htons(bpf_ntohs(outer_iphdr->tot_len) + outer_iphdr->ihl * 4);

    __u32 csum;
    csum = bpf_csum_diff(&iphdr->daddr, sizeof(iphdr->daddr), &outer_iphdr->daddr,
                         sizeof(outer_iphdr->daddr), iphdr->check);
    csum = bpf_csum_diff((void *)&iphdr->protocol, sizeof(iphdr->protocol),
                         (void *)&outer_iphdr->protocol, sizeof(outer_iphdr->protocol), csum);
    outer_iphdr->check = ~csum;

    bpf_printk("TX packet");
    return XDP_TX;

drop:
    return XDP_DROP;
pass:
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
