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
#define RULE_SOURCE_FIREWALL 1
#define RULE_SOURCE_THREAT 2

enum stat_index {
    STAT_PASS = 0,
    STAT_RULE_DROP = 1,
    STAT_GEO_DROP = 2,
    STAT_RATE_DROP = 3,
    STAT_FLOOD_DROP = 4,
    STAT_CUSTOM_RATE_DROP = 5,
    STAT_PARSE_DROP = 6,
    STAT_TEMP_BAN_DROP = 7,
    STAT_MAX = 8,
};

#define RATE_KIND_CUSTOM 1
#define RATE_KIND_IP 2
#define RATE_KIND_FLOOD 3

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
    __u8 source;
    __u8 pad[2];
    __s32 priority;
};

struct geo_value {
    __u16 country;
};

struct country_value {
    __u8 action;
};

struct defense_value {
    __u8 enabled;
    __u8 ip_rate_limit_enabled;
    __u8 flood_enabled;
    __u8 pad;
    __u32 ip_packets_per_second;
    __u32 ip_burst;
    __u32 flood_packets_per_second;
    __u32 flood_burst;
    __u64 flood_block_ns;
};

struct custom_rate_key {
    __u8 proto;
    __u8 pad;
    __be16 dport;
};

struct custom_rate_value {
    __u32 packets_per_second;
    __u32 burst;
};

struct temp_ban_key {
    __u8 family;
    __u8 proto;
    __be16 dport;
    __u8 addr[16];
};

struct temp_ban_value {
    __u64 expires_at_ns;
};

struct rate_key {
    __u8 kind;
    __u8 family;
    __u8 proto;
    __u8 pad;
    __be16 dport;
    __u8 addr[16];
};

struct rate_bucket {
    __u64 tokens;
    __u64 updated_ns;
    __u64 blocked_until_ns;
};

struct drop_event {
    __u64 time_ns;
    __u32 reason;
    __u8 family;
    __u8 proto;
    __be16 dport;
    __u8 addr[16];
    __u16 country;
    __u8 action;
    __u8 source;
    __u8 pad[4];
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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct defense_value);
} defense_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct custom_rate_key);
    __type(value, struct custom_rate_value);
} custom_rate_limits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct temp_ban_key);
    __type(value, struct temp_ban_value);
} temp_bans SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0);
    __type(key, __u32);
    __type(value, __u32);
} drop_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} drop_config SEC(".maps");

static __always_inline void incr_stat(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value)
        *value += 1;
}

static __always_inline void emit_drop_event(void *ctx, __u32 reason, __u8 family, __u8 proto, __u16 dport, __u8 addr[16], __u16 country, __u8 action, __u8 source)
{
    __u32 config_key = 0;
    __u8 *enabled = bpf_map_lookup_elem(&drop_config, &config_key);
    if (!enabled || *enabled == 0)
        return;

    struct drop_event event = {};
    event.time_ns = bpf_ktime_get_ns();
    event.reason = reason;
    event.family = family;
    event.proto = proto;
    event.dport = dport;
    __builtin_memcpy(event.addr, addr, 16);
    event.country = country;
    event.action = action;
    event.source = source;
    bpf_perf_event_output(ctx, &drop_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
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

static __always_inline int temp_ban_value_active(struct temp_ban_value *value, __u64 now)
{
    if (!value)
        return 0;

    return value->expires_at_ns > now;
}

static __always_inline int temp_ban_active(__u8 family, __u8 proto, __u16 dport, __u8 addr[16])
{
    struct temp_ban_key key = {};
    key.family = family;
    key.proto = proto;
    key.dport = dport;
    __builtin_memcpy(key.addr, addr, 16);

    __u64 now = bpf_ktime_get_ns();
    struct temp_ban_value *value = bpf_map_lookup_elem(&temp_bans, &key);
    if (temp_ban_value_active(value, now))
        return 1;

    key.dport = 0;
    value = bpf_map_lookup_elem(&temp_bans, &key);
    if (temp_ban_value_active(value, now))
        return 1;

    key.proto = PROTO_ANY;
    key.dport = dport;
    value = bpf_map_lookup_elem(&temp_bans, &key);
    if (temp_ban_value_active(value, now))
        return 1;

    key.proto = PROTO_ANY;
    key.dport = 0;
    value = bpf_map_lookup_elem(&temp_bans, &key);
    return temp_ban_value_active(value, now);
}

static __always_inline int token_bucket_limited(__u8 kind, __u8 family, __u8 proto, __u16 dport, __u8 addr[16], __u32 packets_per_second, __u32 burst, __u64 block_ns)
{
    if (packets_per_second == 0 || burst == 0)
        return 0;

    struct rate_key key = {};
    key.kind = kind;
    key.family = family;
    key.proto = proto;
    key.dport = dport;
    __builtin_memcpy(key.addr, addr, 16);

    __u64 now = bpf_ktime_get_ns();
    struct rate_bucket initial = {
        .tokens = burst - 1,
        .updated_ns = now,
        .blocked_until_ns = 0,
    };
    struct rate_bucket *bucket = bpf_map_lookup_elem(&rate_buckets, &key);
    if (!bucket) {
        bpf_map_update_elem(&rate_buckets, &key, &initial, BPF_ANY);
        return 0;
    }

    if (block_ns > 0 && bucket->blocked_until_ns > now)
        return 1;

    __u64 elapsed = now - bucket->updated_ns;
    __u64 refill = elapsed * packets_per_second / 1000000000ULL;
    __u64 tokens = bucket->tokens;
    if (refill > 0) {
        tokens += refill;
        if (tokens > burst)
            tokens = burst;
        bucket->updated_ns = now;
    }
    if (tokens == 0) {
        if (block_ns > 0)
            bucket->blocked_until_ns = now + block_ns;
        return 1;
    }
    bucket->tokens = tokens - 1;
    return 0;
}

static __always_inline struct custom_rate_value *lookup_custom_rate(__u8 proto, __u16 dport, __u8 *matched_proto, __u16 *matched_dport)
{
    struct custom_rate_key key = {};
    key.proto = proto;
    key.dport = dport;

    struct custom_rate_value *value = bpf_map_lookup_elem(&custom_rate_limits, &key);
    if (value) {
        *matched_proto = key.proto;
        *matched_dport = key.dport;
        return value;
    }

    key.dport = 0;
    value = bpf_map_lookup_elem(&custom_rate_limits, &key);
    if (value) {
        *matched_proto = key.proto;
        *matched_dport = key.dport;
        return value;
    }

    key.proto = PROTO_ANY;
    key.dport = dport;
    value = bpf_map_lookup_elem(&custom_rate_limits, &key);
    if (value) {
        *matched_proto = key.proto;
        *matched_dport = key.dport;
        return value;
    }

    key.proto = PROTO_ANY;
    key.dport = 0;
    value = bpf_map_lookup_elem(&custom_rate_limits, &key);
    if (value) {
        *matched_proto = key.proto;
        *matched_dport = key.dport;
        return value;
    }

    return 0;
}

static __always_inline int custom_dynamic_rate_limited(__u8 family, __u8 proto, __u16 dport, __u8 addr[16])
{
    __u8 matched_proto = PROTO_ANY;
    __u16 matched_dport = 0;
    struct custom_rate_value *limit = lookup_custom_rate(proto, dport, &matched_proto, &matched_dport);
    if (!limit)
        return 0;

    if (token_bucket_limited(RATE_KIND_CUSTOM, family, matched_proto, matched_dport, addr, limit->packets_per_second, limit->burst, 0))
        return STAT_CUSTOM_RATE_DROP;

    return 0;
}

static __always_inline int dynamic_defense_limited(__u8 family, __u8 proto, __u16 dport, __u8 addr[16])
{
    __u32 index = 0;
    struct defense_value *policy = bpf_map_lookup_elem(&defense_policy, &index);
    if (!policy || !policy->enabled)
        return 0;

    int custom_drop = custom_dynamic_rate_limited(family, proto, dport, addr);
    if (custom_drop)
        return custom_drop;

    if (policy->flood_enabled &&
        token_bucket_limited(RATE_KIND_FLOOD, family, PROTO_ANY, 0, addr, policy->flood_packets_per_second, policy->flood_burst, policy->flood_block_ns)) {
        return STAT_FLOOD_DROP;
    }

    if (policy->ip_rate_limit_enabled &&
        token_bucket_limited(RATE_KIND_IP, family, PROTO_ANY, 0, addr, policy->ip_packets_per_second, policy->ip_burst, 0)) {
        return STAT_RATE_DROP;
    }

    return 0;
}

static __always_inline int handle_packet(void *ctx, __u8 family, __u8 proto, __u16 dport, __u8 src[16])
{
    if (lookup_trusted(family, src) != 0) {
        incr_stat(STAT_PASS);
        return XDP_PASS;
    }

    if (temp_ban_active(family, proto, dport, src)) {
        incr_stat(STAT_TEMP_BAN_DROP);
        emit_drop_event(ctx, STAT_TEMP_BAN_DROP, family, proto, dport, src, 0, ACTION_DENY, 0);
        return XDP_DROP;
    }

    struct rule_value *rule = lookup_rule(family, proto, dport, src);
    if (rule) {
        if (rule->action == ACTION_DENY) {
            incr_stat(STAT_RULE_DROP);
            emit_drop_event(ctx, STAT_RULE_DROP, family, proto, dport, src, 0, rule->action, rule->source);
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
                emit_drop_event(ctx, STAT_GEO_DROP, family, proto, dport, src, geo->country, country->action, 0);
                return XDP_DROP;
            }
        }
    }

    int defense_drop = dynamic_defense_limited(family, proto, dport, src);
    if (defense_drop) {
        incr_stat(defense_drop);
        emit_drop_event(ctx, defense_drop, family, proto, dport, src, 0, ACTION_DENY, 0);
        return XDP_DROP;
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
        proto = ip->protocol;
        copy_addr(FAMILY_V4, &ip->saddr, src);
        if (ip->ihl < 5) {
            incr_stat(STAT_PARSE_DROP);
            emit_drop_event(ctx, STAT_PARSE_DROP, FAMILY_V4, proto, 0, src, 0, ACTION_DENY, 0);
            return XDP_DROP;
        }
        cursor = (void *)ip + ip->ihl * 4;
        if (cursor > data_end) {
            incr_stat(STAT_PARSE_DROP);
            emit_drop_event(ctx, STAT_PARSE_DROP, FAMILY_V4, proto, 0, src, 0, ACTION_DENY, 0);
            return XDP_DROP;
        }
        if (proto == PROTO_TCP) {
            struct tcphdr *tcp = cursor;
            if ((void *)(tcp + 1) > data_end) {
                incr_stat(STAT_PARSE_DROP);
                emit_drop_event(ctx, STAT_PARSE_DROP, FAMILY_V4, proto, 0, src, 0, ACTION_DENY, 0);
                return XDP_DROP;
            }
            dport = tcp->dest;
        } else if (proto == PROTO_UDP) {
            struct udphdr *udp = cursor;
            if ((void *)(udp + 1) > data_end) {
                incr_stat(STAT_PARSE_DROP);
                emit_drop_event(ctx, STAT_PARSE_DROP, FAMILY_V4, proto, 0, src, 0, ACTION_DENY, 0);
                return XDP_DROP;
            }
            dport = udp->dest;
        }
        return handle_packet(ctx, FAMILY_V4, proto, dport, src);
    }

    if (eth_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = cursor;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        proto = ip6->nexthdr;
        copy_addr(FAMILY_V6, &ip6->saddr, src);
        cursor = ip6 + 1;
        cursor = skip_ipv6_extensions(cursor, data_end, &proto);
        if (!cursor) {
            incr_stat(STAT_PARSE_DROP);
            emit_drop_event(ctx, STAT_PARSE_DROP, FAMILY_V6, proto, 0, src, 0, ACTION_DENY, 0);
            return XDP_DROP;
        }
        if (proto == PROTO_TCP) {
            struct tcphdr *tcp = cursor;
            if ((void *)(tcp + 1) > data_end) {
                incr_stat(STAT_PARSE_DROP);
                emit_drop_event(ctx, STAT_PARSE_DROP, FAMILY_V6, proto, 0, src, 0, ACTION_DENY, 0);
                return XDP_DROP;
            }
            dport = tcp->dest;
        } else if (proto == PROTO_UDP) {
            struct udphdr *udp = cursor;
            if ((void *)(udp + 1) > data_end) {
                incr_stat(STAT_PARSE_DROP);
                emit_drop_event(ctx, STAT_PARSE_DROP, FAMILY_V6, proto, 0, src, 0, ACTION_DENY, 0);
                return XDP_DROP;
            }
            dport = udp->dest;
        }
        return handle_packet(ctx, FAMILY_V6, proto, dport, src);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
