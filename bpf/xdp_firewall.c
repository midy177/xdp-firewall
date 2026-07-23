#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define ACTION_ALLOW 1
#define ACTION_DENY 2
#define FAMILY_V4 4
#define FAMILY_V6 6
#define PROTO_ANY 0
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#define IPV6_HOP_BY_HOP 0
#define IPV6_ROUTING 43
#define IPV6_FRAGMENT 44
#define IPV6_DESTINATION 60

enum stat_index {
    STAT_PASS = 0,
    STAT_RULE_DROP = 1,
    STAT_GEO_DROP = 2,
    STAT_RATE_DROP = 3,
    STAT_MAX = 4,
};

struct rule_key {
    __u32 prefixlen;
    __u8 family;
    __u8 proto;
    __be16 dport;
    __u8 addr[16];
};

struct geo_key {
    __u32 prefixlen;
    __u8 family;
    __u8 pad[3];
    __u8 addr[16];
};

struct trusted_key {
    __u32 prefixlen;
    __u8 family;
    __u8 pad[3];
    __u8 addr[16];
};

struct rule_value {
    __u8 action;
    __u32 priority;
};

struct geo_value {
    __u16 country;
};

struct country_value {
    __u8 action;
    __u32 packets_per_second;
    __u32 burst;
};

struct rate_key {
    __u16 country;
    __u8 family;
    __u8 proto;
    __u8 addr[16];
};

struct rate_bucket {
    __u64 tokens;
    __u64 updated_ns;
};

struct ipv6_fragment_header {
    __u8 nexthdr;
    __u8 reserved;
    __be16 frag_off;
    __be32 identification;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 262144);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} rule_cidrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 262144);
    __type(key, struct geo_key);
    __type(value, struct geo_value);
} geo_cidrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 4096);
    __type(key, struct trusted_key);
    __type(value, __u8);
} trusted_cidrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 676);
    __type(key, __u32);
    __type(value, struct country_value);
} country_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1048576);
    __type(key, struct rate_key);
    __type(value, struct rate_bucket);
} rate_buckets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void incr_stat(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value)
        *value += 1;
}

static __always_inline void copy_addr(__u8 family, const void *src, __u8 dst[16])
{
    __builtin_memset(dst, 0, 16);
    if (family == FAMILY_V4) {
        __builtin_memcpy(dst, src, 4);
    } else {
        __builtin_memcpy(dst, src, 16);
    }
}

static __always_inline __u32 full_prefix_len(__u8 family)
{
    return family == FAMILY_V4 ? 64 : 160;
}

static __always_inline struct rule_value *lookup_rule(__u8 family, __u8 proto, __u16 dport, __u8 addr[16])
{
    struct rule_key key = {};
    key.prefixlen = full_prefix_len(family);
    key.family = family;
    key.proto = proto;
    key.dport = dport;
    __builtin_memcpy(key.addr, addr, 16);

    struct rule_value *value = bpf_map_lookup_elem(&rule_cidrs, &key);
    if (value)
        return value;

    key.dport = 0;
    value = bpf_map_lookup_elem(&rule_cidrs, &key);
    if (value)
        return value;

    key.proto = PROTO_ANY;
    key.dport = dport;
    value = bpf_map_lookup_elem(&rule_cidrs, &key);
    if (value)
        return value;

    key.proto = PROTO_ANY;
    key.dport = 0;
    return bpf_map_lookup_elem(&rule_cidrs, &key);
}

static __always_inline int ipv6_extension_header(__u8 proto)
{
    return proto == IPV6_HOP_BY_HOP || proto == IPV6_ROUTING ||
           proto == IPV6_FRAGMENT || proto == IPV6_DESTINATION;
}

static __always_inline void *skip_ipv6_extensions(void *cursor, void *data_end, __u8 *proto)
{
#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (!ipv6_extension_header(*proto))
            return cursor;
        if (*proto == IPV6_FRAGMENT) {
            struct ipv6_fragment_header *frag = cursor;
            if ((void *)(frag + 1) > data_end)
                return 0;
            *proto = frag->nexthdr;
            return cursor + sizeof(*frag);
        }
        struct ipv6_opt_hdr *ext = cursor;
        if ((void *)(ext + 1) > data_end)
            return 0;
        __u64 len = ((__u64)ext->hdrlen + 1) * 8;
        cursor += len;
        if (cursor > data_end)
            return 0;
        *proto = ext->nexthdr;
    }
    return cursor;
}

static __always_inline struct geo_value *lookup_geo(__u8 family, __u8 addr[16])
{
    struct geo_key key = {};
    key.prefixlen = full_prefix_len(family);
    key.family = family;
    __builtin_memcpy(key.addr, addr, 16);
    return bpf_map_lookup_elem(&geo_cidrs, &key);
}

static __always_inline __u8 *lookup_trusted(__u8 family, __u8 addr[16])
{
    struct trusted_key key = {};
    key.prefixlen = full_prefix_len(family);
    key.family = family;
    __builtin_memcpy(key.addr, addr, 16);
    return bpf_map_lookup_elem(&trusted_cidrs, &key);
}

static __always_inline int country_rate_limited(__u16 country, __u8 family, __u8 proto, __u8 addr[16], struct country_value *policy)
{
    if (policy->packets_per_second == 0 || policy->burst == 0)
        return 0;

    struct rate_key key = {};
    key.country = country;
    key.family = family;
    key.proto = proto;
    __builtin_memcpy(key.addr, addr, 16);

    __u64 now = bpf_ktime_get_ns();
    struct rate_bucket initial = {
        .tokens = policy->burst - 1,
        .updated_ns = now,
    };
    struct rate_bucket *bucket = bpf_map_lookup_elem(&rate_buckets, &key);
    if (!bucket) {
        bpf_map_update_elem(&rate_buckets, &key, &initial, BPF_ANY);
        return 0;
    }

    __u64 elapsed = now - bucket->updated_ns;
    __u64 refill = elapsed * policy->packets_per_second / 1000000000ULL;
    __u64 tokens = bucket->tokens;
    if (refill > 0) {
        tokens += refill;
        if (tokens > policy->burst)
            tokens = policy->burst;
        bucket->updated_ns = now;
    }
    if (tokens == 0)
        return 1;
    bucket->tokens = tokens - 1;
    return 0;
}

static __always_inline int handle_packet(__u8 family, __u8 proto, __u16 dport, __u8 src[16])
{
    if (lookup_trusted(family, src)) {
        incr_stat(STAT_PASS);
        return XDP_PASS;
    }

    struct rule_value *rule = lookup_rule(family, proto, dport, src);
    if (rule) {
        if (rule->action == ACTION_DENY) {
            incr_stat(STAT_RULE_DROP);
            return XDP_DROP;
        }
        if (rule->action == ACTION_ALLOW) {
            incr_stat(STAT_PASS);
            return XDP_PASS;
        }
    }

    struct geo_value *geo = lookup_geo(family, src);
    if (geo) {
        __u32 country_key = geo->country;
        struct country_value *country = bpf_map_lookup_elem(&country_rules, &country_key);
        if (country) {
            if (country->action == ACTION_DENY) {
                incr_stat(STAT_GEO_DROP);
                return XDP_DROP;
            }
            if (country_rate_limited(geo->country, family, proto, src, country)) {
                incr_stat(STAT_RATE_DROP);
                return XDP_DROP;
            }
        }
    }

    incr_stat(STAT_PASS);
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = eth->h_proto;
    void *cursor = eth + 1;
    __u8 src[16] = {};
    __u8 proto = PROTO_ANY;
    __u16 dport = 0;

    if (eth_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = cursor;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->ihl < 5)
            return XDP_DROP;
        proto = ip->protocol;
        copy_addr(FAMILY_V4, &ip->saddr, src);
        cursor = (void *)ip + ip->ihl * 4;
        if (cursor > data_end)
            return XDP_PASS;
        if (proto == PROTO_TCP) {
            struct tcphdr *tcp = cursor;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            dport = tcp->dest;
        } else if (proto == PROTO_UDP) {
            struct udphdr *udp = cursor;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            dport = udp->dest;
        }
        return handle_packet(FAMILY_V4, proto, dport, src);
    }

    if (eth_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = cursor;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        proto = ip6->nexthdr;
        copy_addr(FAMILY_V6, &ip6->saddr, src);
        cursor = ip6 + 1;
        cursor = skip_ipv6_extensions(cursor, data_end, &proto);
        if (!cursor)
            return XDP_PASS;
        if (proto == PROTO_TCP) {
            struct tcphdr *tcp = cursor;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            dport = tcp->dest;
        } else if (proto == PROTO_UDP) {
            struct udphdr *udp = cursor;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            dport = udp->dest;
        }
        return handle_packet(FAMILY_V6, proto, dport, src);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
