// Copyright 2024 Anton Kulpinov

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "defs.h"
#include "ip4maps.h"
#include "ip6maps.h"

// Force emitting struct packet into the ELF.
const struct ip4_pair_addr_key *ip4key_unused __attribute__((unused));
const struct ip4_pair_addr_value *ip4addr_unused __attribute__((unused));
const struct ip4_pair_value *ip4val_unused __attribute__((unused));

const struct ip6_pair_addr_key *ip6key_unused __attribute__((unused));
const struct ip6_pair_addr_value *ip6addr_unused __attribute__((unused));
const struct ip6_pair_value *ip6val_unused __attribute__((unused));

// Implemenation

static void __always_inline count_packet(struct iphdr *ip, struct ip4_pair_addr_key *key, struct ip4_pair_addr_value *map_val) {
    
    // Addr pair has no ips in lpm trie
    if (map_val->flags == FLAG_NONE) {
        struct ip4_pair_value *val = bpf_map_lookup_elem(&ip4_packets, key);

        // Actual counting of bytes
        if (val) {
            __sync_lock_test_and_set(&val->ts, bpf_ktime_get_coarse_ns());
            __sync_fetch_and_add(&val->bytes, bpf_ntohs(ip->tot_len));
        } else {
            struct ip4_pair_value pair = { 
                .bytes = bpf_ntohs(ip->tot_len),
                .ts = bpf_ktime_get_coarse_ns(),
            };
            bpf_map_update_elem(&ip4_packets, key, &pair, BPF_NOEXIST);
        }
    } else {
        struct ip4_pair_value *val = bpf_map_lookup_elem(&ip4_packets_agg, map_val);

        // Actual counting of bytes
        if (val) {
            __sync_lock_test_and_set(&val->ts, bpf_ktime_get_coarse_ns());
            __sync_fetch_and_add(&val->bytes, bpf_ntohs(ip->tot_len));
        } else {
            struct ip4_pair_value pair = { 
                .bytes = bpf_ntohs(ip->tot_len),
                .ts = bpf_ktime_get_coarse_ns(),
            };
            bpf_map_update_elem(&ip4_packets_agg, map_val, &pair, BPF_NOEXIST);
        }
    }
}
static void __always_inline count_packet6(struct ipv6hdr *ip, struct ip6_pair_addr_key *key, struct ip6_pair_addr_value *map_val) {
    
    // Addr pair has no ips in lpm trie
    if (map_val->flags == FLAG_NONE) {
        struct ip6_pair_value *val = bpf_map_lookup_elem(&ip6_packets, key);

        // Actual counting of bytes
        if (val) {
            __sync_lock_test_and_set(&val->ts, bpf_ktime_get_coarse_ns());
            __sync_fetch_and_add(&val->bytes, bpf_ntohs(ip->payload_len) + sizeof(struct ipv6hdr));
        } else {
            struct ip6_pair_value pair = { 
                .bytes = bpf_ntohs(ip->payload_len) + sizeof(struct ipv6hdr),
                .ts = bpf_ktime_get_coarse_ns(),
            };
            bpf_map_update_elem(&ip6_packets, key, &pair, BPF_NOEXIST);
        }
    } else {
        struct ip6_pair_value *val = bpf_map_lookup_elem(&ip6_packets_agg, map_val);

        // Actual counting of bytes
        if (val) {
            __sync_lock_test_and_set(&val->ts, bpf_ktime_get_coarse_ns());
            __sync_fetch_and_add(&val->bytes, bpf_ntohs(ip->payload_len) + sizeof(struct ipv6hdr));
        } else {
            struct ip6_pair_value pair = { 
                .bytes = bpf_ntohs(ip->payload_len) + sizeof(struct ipv6hdr),
                .ts = bpf_ktime_get_coarse_ns(),
            };
            bpf_map_update_elem(&ip6_packets_agg, map_val, &pair, BPF_NOEXIST);
        }
    }
}

static __always_inline void process_ip6(void *iph, void *data_end) {
        struct ipv6hdr *ip = (void *)iph;
        if ((void *)ip + sizeof(struct ipv6hdr) > data_end) {
            return;
        }

        // Lookup addr pair in the addr hash
        struct ip6_pair_addr_key key = {
            .src = ip->saddr,
            .dst = ip->daddr,
        };

        // Lookup that pair of the addresses in the address hash
        struct ip6_pair_addr_value *map_val = bpf_map_lookup_elem(&ip6_address, &key);

        // We don't know that pair of addresses, lookup lpm trie and update the address hash
        if (!map_val) {
            struct ip6_lpm_trie_key k = {
                .lpm_key = {
                    .prefixlen = 128,
                },
                .addr = ip->saddr,
            };

            __u32 *src_idx = bpf_map_lookup_elem(&ip6_lpm_trie, &k);

            k.addr = ip->daddr;

            __u32 *dst_idx = bpf_map_lookup_elem(&ip6_lpm_trie, &k);

            struct ip6_pair_addr_value val = {
                .flags = FLAG_NONE | (src_idx ? FLAG_SRC_I : 0) | (dst_idx ? FLAG_DST_I : 0),
                .addrs = key,
            };

            if (src_idx) {
                __builtin_memset(&val.addrs.src, 0, sizeof(val.addrs.src));
                val.addrs.src.in6_u.u6_addr32[0] = *src_idx;
            }

            if (dst_idx) {
                __builtin_memset(&val.addrs.dst, 0, sizeof(val.addrs.dst));
                val.addrs.dst.in6_u.u6_addr32[0] = *dst_idx;
            }

            bpf_map_update_elem(&ip6_address, &key, &val, BPF_NOEXIST);

            count_packet6(ip, &key, &val);
        } else {
            count_packet6(ip, &key, map_val);
        }
}
static __always_inline void process_ip(void *iph, void *data_end) {
            struct iphdr *ip = (void *)iph;
        if ((void *)ip + sizeof(struct iphdr) > data_end) {
            return;
        }

        // Lookup addr pair in the addr hash
        struct ip4_pair_addr_key key = {
            .src = ip->saddr,
            .dst = ip->daddr,
        };

        // Lookup that pair of the addresses in the address hash
        struct ip4_pair_addr_value *map_val = bpf_map_lookup_elem(&ip4_address, &key);

        // We don't know that pair of addresses, lookup lpm trie and update the address hash
        if (!map_val) {
            struct ip4_lpm_trie_key k = {
                .lpm_key = {
                    .prefixlen = 32,
                },
                .addr = ip->saddr,
            };  

            __u32 *src_idx = bpf_map_lookup_elem(&ip4_lpm_trie, &k);

            k.addr = ip->daddr;

            __u32 *dst_idx = bpf_map_lookup_elem(&ip4_lpm_trie, &k);

            struct ip4_pair_addr_value val = {
                .flags = FLAG_NONE | (src_idx ? FLAG_SRC_I : 0) | (dst_idx ? FLAG_DST_I : 0),
                .addrs = key,
            };

            if (src_idx) {
                val.addrs.src = *src_idx;
            }

            if (dst_idx) {
                val.addrs.dst = *dst_idx;
            }

            bpf_map_update_elem(&ip4_address, &key, &val, BPF_NOEXIST);

            count_packet(ip, &key, &val);
        } else {
            count_packet(ip, &key, map_val);
        }
}

static __always_inline void get_ip_and_count(void *data, 
                                             void *data_end) {
	// Let's process ethernet frame first
    struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return;
	}
    void *iph = data + sizeof(struct ethhdr);

    __be16 h_proto = h_proto = eth->h_proto;

    // Check if the packet is VLAN tagged
    if (eth->h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr = iph;
        iph += sizeof(struct vlan_hdr);
        if (iph + 1 > data_end) {
            return;
        }

        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    // IPv4
	if (h_proto == bpf_htons(ETH_P_IP)) {
        process_ip(iph, data_end);
    } else // IPv6
            if (h_proto == bpf_htons(ETH_P_IPV6)) {
                process_ip6(iph, data_end);
            }
}

// XDP and TC programs

SEC("xdp")
int cnt_xdp_prog_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

    get_ip_and_count(data, data_end);
    return XDP_PASS;
}

SEC("tc")
int cnt_tc_prog_func(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    get_ip_and_count(data, data_end);
    return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "Dual MIT/GPL";