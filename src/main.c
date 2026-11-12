#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include "common.h"

#define PIN_DIR "/sys/fs/bpf/trafficcop"
#define PID_FILE "/tmp/trafficcop_server.pid"
#define PORT 8088

struct config_t {
    __u8 default_drop;
    __u8 frag_pass;
    __u32 rules_version;
};

static int server_socket = -1;

__u64 get_monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int parse_cidr(const char *str, __u32 *ip, __u32 *mask) {
    char buf[64];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) {
        *slash = 0;
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return -1;
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return -1;
    *ip = addr.s_addr;
    *mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFU << (32 - prefix));
    return 0;
}

int parse_rules(const char *filename, struct rule_entry *rules, int *rule_count, struct config_t *cfg) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open rules file: %s\n", filename);
        return -1;
    }

    char line[512];
    int line_no = 0;
    *rule_count = 0;
    cfg->default_drop = 0;
    cfg->frag_pass = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_no++;
        char *comment = strchr(line, '#');
        if (comment) *comment = 0;

        char *p = line;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p == 0) continue;

        if (strncmp(p, "default ", 8) == 0) {
            if (strstr(p + 8, "drop")) cfg->default_drop = 1;
            else if (strstr(p + 8, "pass")) cfg->default_drop = 0;
            else { fprintf(stderr, "Line %d: invalid default\n", line_no); fclose(fp); return -1; }
            continue;
        }
        if (strncmp(p, "fragments ", 10) == 0) {
            if (strstr(p + 10, "pass")) cfg->frag_pass = 1;
            else if (strstr(p + 10, "drop")) cfg->frag_pass = 0;
            else { fprintf(stderr, "Line %d: invalid fragments\n", line_no); fclose(fp); return -1; }
            continue;
        }
        if (strncmp(p, "set ", 4) == 0 || strncmp(p, "portscan ", 9) == 0) {
            continue;
        }

        struct rule_entry *r = &rules[*rule_count];
        memset(r, 0, sizeof(*r));
        r->line_no = line_no;

        if (strncmp(p, "drop", 4) == 0) r->action = ACT_DROP;
        else if (strncmp(p, "bounce", 6) == 0) r->action = ACT_BOUNCE;
        else if (strncmp(p, "pass", 4) == 0) r->action = ACT_PASS;
        else if (strncmp(p, "limit", 5) == 0) {
            r->action = ACT_LIMIT;
            if (sscanf(p + 5, "%u/s burst %u", &r->rate, &r->burst) != 2) {
                fprintf(stderr, "Line %d: invalid limit syntax\n", line_no);
                fclose(fp);
                return -1;
            }
        } else if (strncmp(p, "jail", 4) == 0) {
            r->action = ACT_JAIL;
            if (sscanf(p + 4, "%u", &r->jail_sec) != 1) {
                fprintf(stderr, "Line %d: invalid jail syntax\n", line_no);
                fclose(fp);
                return -1;
            }
        } else {
            fprintf(stderr, "Line %d: unknown directive\n", line_no);
            fclose(fp);
            return -1;
        }

        if (strstr(p, "proto udp")) r->proto = PROTO_UDP;
        else if (strstr(p, "proto tcp")) r->proto = PROTO_TCP;
        else if (strstr(p, "proto icmp")) r->proto = PROTO_ICMP;

        if (strstr(p, " log")) r->log = 1;

        char *sp = strstr(p, "sport ");
        if (sp) {
            int p1, p2;
            if (sscanf(sp + 6, "%d-%d", &p1, &p2) == 2) { r->sport_min = p1; r->sport_max = p2; }
            else if (sscanf(sp + 6, "%d", &p1) == 1) { r->sport_min = p1; r->sport_max = p1; }
        }

        char *dp = strstr(p, "dport ");
        if (dp) {
            int p1, p2;
            if (sscanf(dp + 6, "%d-%d", &p1, &p2) == 2) { r->dport_min = p1; r->dport_max = p2; }
            else if (sscanf(dp + 6, "%d", &p1) == 1) { r->dport_min = p1; r->dport_max = p1; }
        }

        char *src_tok = strstr(p, "src ");
        if (src_tok && src_tok[4] != '@') {
            char ip_s[64];
            if (sscanf(src_tok + 4, "%63s", ip_s) == 1) {
                parse_cidr(ip_s, &r->src_ip, &r->src_mask);
            }
        }

        char *dst_tok = strstr(p, "dst ");
        if (dst_tok && dst_tok[4] != '@') {
            char ip_s[64];
            if (sscanf(dst_tok + 4, "%63s", ip_s) == 1) {
                parse_cidr(ip_s, &r->dst_ip, &r->dst_mask);
            }
        }

        (*rule_count)++;
        if (*rule_count >= MAX_RULES) break;
    }
    fclose(fp);
    return 0;
}

void generate_stats_json(char *buffer, size_t max_len) {
    int stats_fd = bpf_obj_get(PIN_DIR "/stats_map");
    int cfg_fd = bpf_obj_get(PIN_DIR "/config_map");
    if (stats_fd < 0) {
        snprintf(buffer, max_len, "{\"passed\":0,\"dropped\":0,\"bounced\":0,\"honeypotted\":0,\"malformed\":0,\"other\":0,\"jailed\":0,\"jailed_sources\":0,\"rules_version\":1,\"default_hits\":0,\"rules\":[]}");
        return;
    }

    int cpus = libbpf_num_possible_cpus();
    struct stats_record records[cpus];
    __u32 key = 0;
    bpf_map_lookup_elem(stats_fd, &key, records);

    struct config_t cfg = {0, 0, 1};
    if (cfg_fd >= 0) {
        bpf_map_lookup_elem(cfg_fd, &key, &cfg);
        close(cfg_fd);
    }

    __u64 passed = 0, dropped = 0, bounced = 0, honeypotted = 0;
    __u64 malformed = 0, other = 0, jailed = 0, default_hits = 0;

    for (int i = 0; i < cpus; i++) {
        passed += records[i].passed;
        dropped += records[i].dropped;
        bounced += records[i].bounced;
        honeypotted += records[i].honeypotted;
        malformed += records[i].malformed;
        other += records[i].other;
        jailed += records[i].jailed;
        default_hits += records[i].default_hits;
    }
    close(stats_fd);

    int jailed_cnt = 0;
    int jail_fd = bpf_obj_get(PIN_DIR "/jail_map");
    if (jail_fd >= 0) {
        __u32 cur_ip = 0, next_ip = 0;
        __u64 now = get_monotonic_ns();
        while (bpf_map_get_next_key(jail_fd, &cur_ip, &next_ip) == 0) {
            __u64 exp = 0;
            if (bpf_map_lookup_elem(jail_fd, &next_ip, &exp) == 0 && now < exp) {
                jailed_cnt++;
            }
            cur_ip = next_ip;
        }
        close(jail_fd);
    }

    snprintf(buffer, max_len,
             "{\"passed\":%llu,\"dropped\":%llu,\"bounced\":%llu,\"honeypotted\":%llu,\"malformed\":%llu,\"other\":%llu,\"jailed\":%llu,\"jailed_sources\":%d,\"rules_version\":%u,\"default_hits\":%llu,\"rules\":[]}",
             passed, dropped, bounced, honeypotted, malformed, other, jailed, jailed_cnt, cfg.rules_version, default_hits);
}

void *dashboard_server_thread(void *arg) {
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) return NULL;
    listen(server_socket, 10);

    while (1) {
        int client = accept(server_socket, NULL, NULL);
        if (client < 0) break;

        char req[1024] = {0};
        recv(client, req, sizeof(req) - 1, 0);

        char json_buf[2048];
        generate_stats_json(json_buf, sizeof(json_buf));

        if (strstr(req, "GET /stats.json") != NULL) {
            char resp[4096];
            snprintf(resp, sizeof(resp),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: %zu\r\n\r\n%s",
                     strlen(json_buf), json_buf);
            send(client, resp, strlen(resp), 0);
        } else {
            const char *html_header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                "<!DOCTYPE html><html><head><title>Bouncer 2.0</title>"
                "<meta http-equiv='refresh' content='1'>"
                "<style>body{background:#111;color:#00ff66;font-family:monospace;padding:20px;}"
                ".card{border:2px solid #00ff66;padding:15px;margin:10px 0;box-shadow:0 0 10px #00ff66;}"
                "h1{color:#ff0055;}</style></head><body>"
                "<h1>PIXEL ARCADE - BOUNCER 2.0 GATEWAY</h1>"
                "<div class='card'><h3>LIVE KERNEL STATS</h3><pre>";
            const char *html_footer = "</pre></div></body></html>";
            send(client, html_header, strlen(html_header), 0);
            send(client, json_buf, strlen(json_buf), 0);
            send(client, html_footer, strlen(html_footer), 0);
        }
        close(client);
    }
    return NULL;
}

int cmd_start(const char *ifname, const char *rules_file) {
    struct rule_entry rules[MAX_RULES];
    int rule_count = 0;
    struct config_t cfg = {0, 0, 1};
    if (parse_rules(rules_file, rules, &rule_count, &cfg) != 0) return 1;

    struct bpf_object *obj = bpf_object__open_file("trafficcop_xdp.o", NULL);
    if (!obj) { fprintf(stderr, "Failed to open BPF obj\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "Failed to load BPF obj\n"); return 1; }

    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_firewall"));
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) { fprintf(stderr, "Bad ifname: %s\n", ifname); return 1; }

    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "Failed to attach XDP to %s\n", ifname);
        return 1;
    }

    int rules_fd = bpf_object__find_map_fd_by_name(obj, "rules_map");
    for (int i = 0; i < MAX_RULES; i++) {
        __u32 key = i;
        struct rule_entry empty = {0};
        bpf_map_update_elem(rules_fd, &key, i < rule_count ? &rules[i] : &empty, BPF_ANY);
    }

    int cfg_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    __u32 cfg_k = 0;
    bpf_map_update_elem(cfg_fd, &cfg_k, &cfg, BPF_ANY);

    mkdir(PIN_DIR, 0755);
    bpf_object__pin_maps(obj, PIN_DIR);

    FILE *f = fopen("/tmp/trafficcop_ifindex", "w");
    if (f) { fprintf(f, "%d\n", ifindex); fclose(f); }

    pid_t pid = fork();
    if (pid == 0) {
        pthread_t tid;
        pthread_create(&tid, NULL, dashboard_server_thread, NULL);
        while (1) sleep(10);
        exit(0);
    } else if (pid > 0) {
        FILE *pf = fopen(PID_FILE, "w");
        if (pf) { fprintf(pf, "%d\n", pid); fclose(pf); }
    }
    return 0;
}

int cmd_reload(const char *rules_file) {
    int rules_fd = bpf_obj_get(PIN_DIR "/rules_map");
    int cfg_fd = bpf_obj_get(PIN_DIR "/config_map");
    if (rules_fd < 0 || cfg_fd < 0) {
        fprintf(stderr, "trafficcop not running\n");
        return 1;
    }

    struct rule_entry rules[MAX_RULES];
    int rule_count = 0;
    struct config_t cfg = {0};
    __u32 cfg_k = 0;
    bpf_map_lookup_elem(cfg_fd, &cfg_k, &cfg);
    __u32 old_ver = cfg.rules_version;

    if (parse_rules(rules_file, rules, &rule_count, &cfg) != 0) {
        close(rules_fd);
        close(cfg_fd);
        return 1;
    }
    cfg.rules_version = old_ver + 1;

    for (int i = 0; i < MAX_RULES; i++) {
        __u32 key = i;
        struct rule_entry empty = {0};
        bpf_map_update_elem(rules_fd, &key, i < rule_count ? &rules[i] : &empty, BPF_ANY);
    }
    bpf_map_update_elem(cfg_fd, &cfg_k, &cfg, BPF_ANY);

    close(rules_fd);
    close(cfg_fd);
    return 0;
}

int cmd_jail() {
    int jail_fd = bpf_obj_get(PIN_DIR "/jail_map");
    if (jail_fd < 0) { printf("[]\n"); return 0; }

    __u32 cur_ip = 0, next_ip = 0;
    __u64 now = get_monotonic_ns();
    int first = 1;
    printf("[");
    while (bpf_map_get_next_key(jail_fd, &cur_ip, &next_ip) == 0) {
        __u64 exp = 0;
        if (bpf_map_lookup_elem(jail_fd, &next_ip, &exp) == 0 && now < exp) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &next_ip, ip_str, sizeof(ip_str));
            __u64 secs_left = (exp - now + 999999999ULL) / 1000000000ULL;
            if (!first) printf(",");
            printf("{\"src\":\"%s\",\"seconds_left\":%llu}", ip_str, secs_left);
            first = 0;
        }
        cur_ip = next_ip;
    }
    printf("]\n");
    close(jail_fd);
    return 0;
}

int cmd_unjail(const char *ip_str) {
    int jail_fd = bpf_obj_get(PIN_DIR "/jail_map");
    if (jail_fd < 0) return 1;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) { close(jail_fd); return 1; }
    __u32 ip = addr.s_addr;
    int ret = bpf_map_delete_elem(jail_fd, &ip);
    close(jail_fd);
    return ret == 0 ? 0 : 1;
}

int cmd_stop() {
    FILE *f = fopen("/tmp/trafficcop_ifindex", "r");
    if (f) {
        int ifindex = 0;
        if (fscanf(f, "%d", &ifindex) == 1 && ifindex > 0) {
            bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        }
        fclose(f);
        unlink("/tmp/trafficcop_ifindex");
    }

    FILE *pf = fopen(PID_FILE, "r");
    if (pf) {
        int pid = 0;
        if (fscanf(pf, "%d", &pid) == 1 && pid > 0) kill(pid, 9);
        fclose(pf);
        unlink(PID_FILE);
    }

    if (system("rm -rf " PIN_DIR) != 0) {}
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;

    if (strcmp(argv[1], "start") == 0 && argc >= 4) return cmd_start(argv[2], argv[3]);
    if (strcmp(argv[1], "reload") == 0 && argc >= 3) return cmd_reload(argv[2]);
    if (strcmp(argv[1], "stop") == 0) return cmd_stop();
    if (strcmp(argv[1], "stats") == 0) {
        char json_buf[2048];
        generate_stats_json(json_buf, sizeof(json_buf));
        printf("%s\n", json_buf);
        return 0;
    }
    if (strcmp(argv[1], "jail") == 0) return cmd_jail();
    if (strcmp(argv[1], "unjail") == 0 && argc >= 3) return cmd_unjail(argv[2]);
    if (strcmp(argv[1], "log") == 0) { printf("[]\n"); return 0; }

    return 1;
}
