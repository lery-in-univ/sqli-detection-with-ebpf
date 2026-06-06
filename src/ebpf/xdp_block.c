// BCC로 로드할 XDP 기반 IPv4 source IP 차단 프로그램

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_HASH(blocked_ips, u32, u8);

int xdp_block(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != 0x0008) {
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)((char *)data + sizeof(*eth));
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    u32 src_ip = ip->saddr;
    u8 *blocked = blocked_ips.lookup(&src_ip);
    if (blocked != 0) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
