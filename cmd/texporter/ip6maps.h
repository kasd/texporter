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

#ifndef __IP6MAPS_H__
#define __IP6MAPS_H__

struct ip6_pair_addr_key {
    struct in6_addr src;
    struct in6_addr dst;
};

struct __attribute__((packed)) ip6_pair_addr_value {
    __u8 flags;
    struct ip6_pair_addr_key addrs;
};

struct ip6_pair_value {
    __u64 bytes;
    __u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, IP6_PACKETS_MAX_ENTRINES);
    __type(key, struct ip6_pair_addr_key);
    __type(value, struct ip6_pair_addr_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip6_address SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, IP6_PACKETS_MAX_ENTRINES);
    __type(key, struct ip6_pair_addr_key);
    __type(value, struct ip6_pair_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip6_packets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, IP6_PACKETS_MAX_ENTRINES);
    __type(key, struct ip6_pair_addr_value);
    __type(value, struct ip6_pair_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip6_packets_agg SEC(".maps");

struct ip6_lpm_trie_key {
	struct bpf_lpm_trie_key lpm_key;
	struct in6_addr addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, IP6_LPM_MAP_MAX_ENTRINES);
    __type(key, struct ip6_lpm_trie_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip6_lpm_trie SEC(".maps");

#endif