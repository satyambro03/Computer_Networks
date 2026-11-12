#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

struct rate_bucket {
    __u64 tokens;
    __u64 last_update_ns;
};

struct config_t {
    __u8 default_drop;
    __u8 frag_pass;
    __u32 rules_version;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct config_t);
    __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rule_entry);
    __uint(max_entries, MAX_RULES);
} rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats_record);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 65536);
} jail_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct rate_bucket);
    __uint(max_entries, 65536);
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline struct stats_record *get_stats() {
    __u32 key = 0;
    return bpf_map_lookup_elem(&stats_map, &key);
}

static __always_inline void log_event(__u32 line, __u32 verdict, __u32 src, __u32 dst, __u16 sport, __u16 dport, __u8 proto) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    e->line = line;
    e->verdict = verdict;
    e->src = src;
    e->dst = dst;
    e->sport = sport;
    e->dport = dport;
    e->proto = proto;
    bpf_ringbuf_submit(e, 0);
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct stats_record *rec = get_stats();

    if (data + sizeof(struct ethhdr) > data_end) {
        if (rec) rec->other++;
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    void *l3 = data + sizeof(struct ethhdr);

    if (h_proto == ETH_P_8021Q) {
        if (l3 + 4 > data_end) {
            if (rec) rec->other++;
            return XDP_PASS;
        }
        __u16 *vlan_hdr = (__u16 *)l3;
        h_proto = bpf_ntohs(vlan_hdr[1]);
        l3 += 4;
        if (h_proto == ETH_P_8021Q || h_proto == 0x88a8) {
            if (rec) rec->other++;
            return XDP_PASS;
        }
    }

    if (h_proto != ETH_P_IP) {
        if (rec) rec->other++;
        return XDP_PASS;
    }

    struct iphdr *iph = l3;
    if ((void *)(iph + 1) > data_end || iph->version != 4 || iph->ihl < 5) {
        if (rec) rec->malformed++;
        return XDP_DROP;
    }
    int ip_hdr_len = iph->ihl * 4;
    if (l3 + ip_hdr_len > data_end) {
        if (rec) rec->malformed++;
        return XDP_DROP;
    }

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u64 now = bpf_ktime_get_ns();

    __u64 *jail_exp = bpf_map_lookup_elem(&jail_map, &src_ip);
    if (jail_exp && now < *jail_exp) {
        if (rec) {
            rec->dropped++;
            rec->jailed++;
        }
        return XDP_DROP;
    }

    void *l4 = l3 + ip_hdr_len;
    __u16 sport = 0, dport = 0;
    __u8 proto = iph->protocol;
    __u8 icmp_type = 0;
    __u16 frag_off = bpf_ntohs(iph->frag_off) & 0x1FFF;

    if (frag_off == 0) {
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = l4;
            if ((void *)(tcph + 1) > data_end) {
                if (rec) rec->malformed++;
                return XDP_DROP;
            }
            sport = bpf_ntohs(tcph->source);
            dport = bpf_ntohs(tcph->dest);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udph = l4;
            if ((void *)(udph + 1) > data_end) {
                if (rec) rec->malformed++;
                return XDP_DROP;
            }
            sport = bpf_ntohs(udph->source);
            dport = bpf_ntohs(udph->dest);
        } else if (proto == IPPROTO_ICMP) {
            struct icmphdr *icmph = l4;
            if ((void *)(icmph + 1) > data_end) {
                if (rec) rec->malformed++;
                return XDP_DROP;
            }
            icmp_type = icmph->type;
        }
    }

    #pragma unroll
    for (__u32 i = 0; i < 32; i++) {
        __u32 k = i;
        struct rule_entry *r = bpf_map_lookup_elem(&rules_map, &k);
        if (!r || r->line_no == 0) break;

        if (r->proto != PROTO_ANY && r->proto != proto) continue;
        if (r->src_mask && ((src_ip & r->src_mask) != (r->src_ip & r->src_mask))) continue;
        if (r->dst_mask && ((dst_ip & r->dst_mask) != (r->dst_ip & r->dst_mask))) continue;

        if (frag_off == 0 && (proto == IPPROTO_TCP || proto == IPPROTO_UDP)) {
            if (r->dport_min && (dport < r->dport_min || dport > r->dport_max)) continue;
            if (r->sport_min && (sport < r->sport_min || sport > r->sport_max)) continue;
        } else if (r->dport_min || r->sport_min) {
            continue;
        }

        if (proto == IPPROTO_ICMP && r->icmp_type && icmp_type != r->icmp_type) continue;

        if (rec) rec->rule_hits[i]++;

        if (r->action == ACT_LIMIT) {
            __u64 map_key = ((__u64)i << 32) | src_ip;
            struct rate_bucket *b = bpf_map_lookup_elem(&rate_limit_map, &map_key);
            __u64 rate = r->rate ? r->rate : 10;
            __u64 burst = r->burst ? r->burst : 10;
            __u64 scale = 1000000000ULL;

            if (!b) {
                struct rate_bucket new_b = { .tokens = (burst - 1) * scale, .last_update_ns = now };
                bpf_map_update_elem(&rate_limit_map, &map_key, &new_b, BPF_ANY);
                if (rec) { rec->passed++; rec->rule_passed[i]++; }
                if (r->log) log_event(r->line_no, ACT_PASS, src_ip, dst_ip, sport, dport, proto);
                return XDP_PASS;
            } else {
                __u64 delta = now - b->last_update_ns;
                b->last_update_ns = now;
                b->tokens += delta * rate;
                if (b->tokens > burst * scale) b->tokens = burst * scale;
                if (b->tokens >= scale) {
                    b->tokens -= scale;
                    if (rec) { rec->passed++; rec->rule_passed[i]++; }
                    if (r->log) log_event(r->line_no, ACT_PASS, src_ip, dst_ip, sport, dport, proto);
                    return XDP_PASS;
                } else {
                    if (rec) { rec->dropped++; rec->rule_dropped[i]++; }
                    if (r->log) log_event(r->line_no, ACT_DROP, src_ip, dst_ip, sport, dport, proto);
                    return XDP_DROP;
                }
            }
        }

        if (r->action == ACT_JAIL) {
            __u64 expiry = now + ((__u64)r->jail_sec * 1000000000ULL);
            bpf_map_update_elem(&jail_map, &src_ip, &expiry, BPF_ANY);
            if (rec) { rec->dropped++; rec->jailed++; rec->rule_dropped[i]++; }
            if (r->log) log_event(r->line_no, ACT_DROP, src_ip, dst_ip, sport, dport, proto);
            return XDP_DROP;
        }

        if (r->action == ACT_DROP) {
            if (rec) { rec->dropped++; rec->rule_dropped[i]++; }
            if (r->log) log_event(r->line_no, ACT_DROP, src_ip, dst_ip, sport, dport, proto);
            return XDP_DROP;
        }

        if (r->action == ACT_BOUNCE) {
            unsigned char tmp[ETH_ALEN];
            __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
            if (rec) rec->bounced++;
            if (r->log) log_event(r->line_no, ACT_BOUNCE, src_ip, dst_ip, sport, dport, proto);
            return XDP_TX;
        }

        if (rec) { rec->passed++; rec->rule_passed[i]++; }
        if (r->log) log_event(r->line_no, ACT_PASS, src_ip, dst_ip, sport, dport, proto);
        return XDP_PASS;
    }

    __u32 cfg_k = 0;
    struct config_t *cfg = bpf_map_lookup_elem(&config_map, &cfg_k);
    if (frag_off != 0) {
        if (cfg && cfg->frag_pass) {
            if (rec) rec->passed++;
            return XDP_PASS;
        }
        if (rec) rec->dropped++;
        return XDP_DROP;
    }

    if (rec) rec->default_hits++;
    if (cfg && cfg->default_drop) {
        if (rec) rec->dropped++;
        return XDP_DROP;
    }
    if (rec) rec->passed++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
