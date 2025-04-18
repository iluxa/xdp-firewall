// +build ignore

/*
 * Copyright (C) 2025 Ilya Gavrilov <gilyav@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifdef FW_DEBUG
#define fw_debug_log(fmt, ...) bpf_printk(fmt "", ##__VA_ARGS__)
#else
#define fw_debug_log(fmt, ...) \
    {                          \
    }
#endif

#define MAX_RULES 100000
#define ACTION_ALLOW 0
#define ACTION_DENY 1
#define ACTION_UNKNOWN 255

#define RULE_FOUND 0
#define RULE_NOT_FOUND -1
#define RULE_CONTINUE -2

struct cidr_key
{
    __u32 prefix_len;
    __u32 id;
    __u32 addr;
};

struct cidr_value
{
    __u32 inner_id;            // Inner map ID for next field (e.g., dest CIDR)
    struct cidr_key next_cidr; // Less specific CIDR
};

struct proto_key
{
    __u32 id;
    __u16 proto; // 0xff_ff for any protocol
    __u16 pad1;
};

struct port_key
{
    __u32 id;
    __u32 port; // 0xff_ff_ff_ff for any port
};

struct rule_attrs
{
    __u32 action;
    __u32 id;
    __u32 priority;
};

struct pkt_stats
{
    __u64 pkts;
    __u64 bytes;
};

struct cidr_map
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct cidr_key);
    __type(value, struct cidr_value);
    __uint(max_entries, MAX_RULES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
};

struct cidr_map src_cidr_map SEC(".maps");
struct cidr_map dst_cidr_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct proto_key);
    __type(value, __u32); // Inner map ID for ports
    __uint(max_entries, MAX_RULES);
} proto_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_key);
    __type(value, __u32);
    __uint(max_entries, MAX_RULES);
} src_port_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_key);
    __type(value, struct rule_attrs);
    __uint(max_entries, MAX_RULES);
} dst_port_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, struct pkt_stats);
    __uint(max_entries, MAX_RULES);
} stats SEC(".maps");

static __always_inline int parse_ipv4(void *data, void *data_end, __u32 *src_ip, __u32 *dst_ip, __u8 *proto, __u16 *src_port, __u16 *dst_port)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return 0;
        *src_port = bpf_ntohs(tcp->source);
        *dst_port = bpf_ntohs(tcp->dest);
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return 0;
        *src_port = bpf_ntohs(udp->source);
        *dst_port = bpf_ntohs(udp->dest);
    }
    else
    {
        *src_port = 0;
        *dst_port = 0;
    }
    return 1;
}

// returns RULE_FOUND if rule is found, RULE_NOT_FOUND otherwise
static __always_inline int check_proto(void *data, void *data_end, __u32 id, __u8 proto, __u16 src_port, __u16 dst_port, __u32 *rule_id, __u32 *action, __u32 *prio)
{
    struct proto_key pr_all_key = {
        .id = id,
        .proto = 0xffff,
        .pad1 = 0,
    };

    struct proto_key pr_key = {
        .id = id,
        .proto = proto,
        .pad1 = 0,
    };

    __u32 *proto_val = bpf_map_lookup_elem(&proto_map, &pr_key);
    if (!proto_val)
    {
        proto_val = bpf_map_lookup_elem(&proto_map, &pr_all_key);
    }
    if (!proto_val)
    {
        return RULE_NOT_FOUND;
    }
    fw_debug_log("proto: %u", *proto_val);

    struct port_key port_all_key = {
        .id = *proto_val,
        .port = 0xffffffff,
    };

    // Check source port
    struct port_key src_port_key = {
        .id = *proto_val,
        .port = src_port,
    };
    __u32 *port_val = bpf_map_lookup_elem(&src_port_map, &src_port_key);
    if (!port_val)
    {
        port_val = bpf_map_lookup_elem(&src_port_map, &port_all_key);
    }
    if (!port_val)
    {
        return RULE_NOT_FOUND;
    }
    fw_debug_log("\tsrc_port_val: %u", *port_val);

    // Check dest port
    struct port_key dst_port_key = {
        .id = *port_val,
        .port = dst_port,
    };
    struct rule_attrs *dst_rule = bpf_map_lookup_elem(&dst_port_map, &dst_port_key);
    if (!dst_rule)
    {
        port_all_key.id = *port_val;
        dst_rule = bpf_map_lookup_elem(&dst_port_map, &port_all_key);
    }
    if (!dst_rule)
    {
        return RULE_NOT_FOUND;
    }
    fw_debug_log("\tfound rule: %u action: %u", dst_rule->id, dst_rule->action);

    *rule_id = dst_rule->id;
    *action = dst_rule->action;
    *prio = dst_rule->priority;
    return RULE_FOUND;
}

// returns 0 if rule is found, <0 otherwise
static __always_inline int check_by_cidr(void *data, void *data_end, void *primary_map, void *secondary_map, __u8 primary_bits, __u32 primary_ip, __u32 secondary_ip, __u8 proto, __u16 src_port, __u16 dst_port, struct cidr_key *next_cidr, __u32 *rule_id, __u32 *action, __u32 *prio)
{
    struct cidr_key src_key = {
        .prefix_len = primary_bits,
        .id = 0,
        .addr = primary_ip,
    };
    fw_debug_log("SRC lookup: %d %d %pi4", src_key.prefix_len, src_key.id, &src_key.addr);
    struct cidr_value *src_value = bpf_map_lookup_elem(primary_map, &src_key);
    if (!src_value)
    {
        if (primary_bits == 0)
        {
            return RULE_NOT_FOUND;
        }
        return RULE_CONTINUE;
    }
    *next_cidr = src_value->next_cidr;
    struct cidr_key dst_key = {
        .prefix_len = 64,
        .id = src_value->inner_id,
        .addr = secondary_ip,
    };
    struct cidr_value *dst_value = bpf_map_lookup_elem(secondary_map, &dst_key);
    if (!dst_value)
    {
        if (primary_bits == 0)
        {
            return RULE_NOT_FOUND;
        }
        return RULE_CONTINUE;
    }
    fw_debug_log("\tdst_inner_id: %u proto: 0x%x", dst_value->inner_id, proto);

    if (check_proto(data, data_end, dst_value->inner_id, proto, src_port, dst_port, rule_id, action, prio) == RULE_FOUND)
    {
        return RULE_FOUND;
    }
    else
    {
        if (primary_ip == 0)
        {
            return RULE_NOT_FOUND;
        }
        fw_debug_log("\tnext_cidr: id: %u addr: %pi4/%u", next_cidr->id, &next_cidr->addr, next_cidr->prefix_len - 32);
        fw_debug_log("\tsrc_inner_id: %u addr: %pi4", src_value->inner_id, &secondary_ip);
        return RULE_CONTINUE;
    }
}

SEC("xdp")
int fw(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 src_ip = 0;
    __u32 dst_ip = 0;
    __u8 proto = 0;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    if (!parse_ipv4(data, data_end, &src_ip, &dst_ip, &proto, &src_port, &dst_port))
        return XDP_PASS;

    fw_debug_log("\npkt: %pi4:%u -> %pi4:%u proto: %u", &src_ip, src_port, &dst_ip, dst_port, proto);

    struct cidr_key next_cidr;

    __u32 action_src = ACTION_UNKNOWN;
    int ret_src = 0;
    __u8 src_bits = 64;
    __u32 rule_id_src = 0;
    __u32 prio_src = 0;
    __builtin_memset(&next_cidr, 0, sizeof(next_cidr));

    __u32 primary_ip = src_ip;
    __u32 secondary_ip = dst_ip;
    for (int i = 0; i < 32; i++)
    {
        ret_src = check_by_cidr(data, data_end, &src_cidr_map, &dst_cidr_map, src_bits, primary_ip, secondary_ip, proto, src_port, dst_port, &next_cidr, &rule_id_src, &action_src, &prio_src);
        if (ret_src != RULE_CONTINUE)
        {
            break;
        }
        primary_ip = next_cidr.addr;
        src_bits = next_cidr.prefix_len;
    }

    fw_debug_log("\ncheck_by_dst");
    __u32 action_dst = ACTION_UNKNOWN;
    int ret_dst;
    __u32 rule_id_dst;
    __u32 prio_dst;
    src_bits = 64;
    __u8 dst_bits = 64;
    __builtin_memset(&next_cidr, 0, sizeof(next_cidr));
    primary_ip = dst_ip;
    secondary_ip = src_ip;
    for (int i = 0; i < 32; i++)
    {
        ret_dst = check_by_cidr(data, data_end, &dst_cidr_map, &src_cidr_map, dst_bits, primary_ip, secondary_ip, proto, src_port, dst_port, &next_cidr, &rule_id_dst, &action_dst, &prio_dst);
        if (ret_dst != RULE_CONTINUE)
        {
            break;
        }
        primary_ip = next_cidr.addr;
        dst_bits = next_cidr.prefix_len;
    }

    if (ret_src != RULE_FOUND && ret_dst != RULE_FOUND)
    {
        return XDP_PASS;
    }

    __u32 rule_id;
    __u32 action;

    if (ret_src == RULE_FOUND && ret_dst == RULE_FOUND)
    {
        action = prio_dst < prio_src ? action_dst : action_src;
        rule_id = prio_dst < prio_src ? rule_id_dst : rule_id_src;
    }
    else
    {
        action = ret_src == RULE_FOUND ? action_src : action_dst;
        rule_id = ret_src == RULE_FOUND ? rule_id_src : rule_id_dst;
    }

    struct pkt_stats *stat = bpf_map_lookup_elem(&stats, &rule_id);
    if (stat)
    {
        stat->pkts++;
        stat->bytes += data_end - data;
    }

    return action == ACTION_ALLOW ? XDP_PASS : XDP_DROP;
}

char _license[] SEC("license") = "GPL";