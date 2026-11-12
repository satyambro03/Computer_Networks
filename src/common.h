#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

#define MAX_RULES 64
#define PROTO_ANY 0
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define PROTO_ICMP6 58

enum action {
    ACT_PASS = 0,
    ACT_DROP,
    ACT_BOUNCE,
    ACT_HONEYPOT,
    ACT_LIMIT,
    ACT_JAIL
};

struct rule_entry {
    __u32 src_ip;
    __u32 src_mask;
    __u32 dst_ip;
    __u32 dst_mask;
    __u16 sport_min;
    __u16 sport_max;
    __u16 dport_min;
    __u16 dport_max;
    __u32 rate;
    __u32 burst;
    __u32 jail_sec;
    __u8  proto;
    __u8  icmp_type;
    __u16 vlan_id;
    __u8  action;
    __u8  log;
    __u32 line_no;
};

struct stats_record {
    __u64 passed;
    __u64 dropped;
    __u64 bounced;
    __u64 honeypotted;
    __u64 malformed;
    __u64 other;
    __u64 jailed;
    __u64 default_hits;
    __u64 rule_hits[MAX_RULES];
    __u64 rule_passed[MAX_RULES];
    __u64 rule_dropped[MAX_RULES];
};

struct event_t {
    __u32 line;
    __u32 verdict;
    __u32 src;
    __u32 dst;
    __u16 sport;
    __u16 dport;
    __u8 proto;
};

#endif
