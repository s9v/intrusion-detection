#pragma once
#include "proto_headers.h"
#include "rules.h"
#include "colors.h"
#include "stdbool.h"

#define MAX_RULES 512
#define HTTP_METHOD_BUFSIZ 32
#define NUM_VALID_METHODS 8

struct pkt_info {
    struct ip_header *ip_hdr;
    struct tcp_header *tcp_hdr;
    uint8_t *tcp_pload;
    uint32_t tcp_pload_len;
    struct udp_header *udp_hdr;
    uint8_t *udp_pload;
    uint32_t udp_pload_len;
    char *http_method;
};

// Declarations

void match_packet(struct ip_header *hdr, uint8_t *pload, int len);
void get_pkt_info(struct ip_header *ip_hdr,
        uint8_t *ip_pload, int pload_len, struct pkt_info *pkt_info);
void get_http_method(uint8_t *pload, int pload_len, char **method);
// matching
bool matches(const struct pkt_info *pkt_info, const struct rule *rule);
bool protocol_matches(const struct pkt_info *pinfo, const struct rule *rule);
// matching - addr
bool src_addr_matches(const struct pkt_info *pinfo, const struct rule *rule);
bool dst_addr_matches(const struct pkt_info *pinfo, const struct rule *rule);
bool addr_matches(struct ip_addr rule_addr, uint32_t addr32);
// matching - port
bool src_port_matches(const struct pkt_info *pinfo, const struct rule *rule);
bool dst_port_matches(const struct pkt_info *pinfo, const struct rule *rule);
bool port_matches(struct ports ports, uint16_t port);
// matching - ip
bool tos_matches(const struct pkt_info *pinfo, const struct rule *rule);
bool len_matches(const struct pkt_info *pinfo, const struct rule *rule);
bool offset_matches(const struct pkt_info *pinfo, const struct rule *rule);
// matching - tcp
bool seq_matches(const struct pkt_info *pinfo, const struct rule *rule);
bool ack_matches(const struct pkt_info *pinfo, const struct rule *rule);
bool flags_matches(const struct pkt_info *pinfo, const struct rule *rule);
// matching - http
bool http_request_matches(const struct pkt_info *pinfo,
        const struct rule *rule);
bool content_matches(const struct pkt_info *pinfo,
        const struct rule *rule);
// helpers
void print_match(const struct pkt_info *pinfo, const struct rule *rule);
void print_content_match(const struct pkt_info *pinfo,
        const struct rule *rule);

// Definitions

void match_packet(struct ip_header *hdr,
        uint8_t *pload, int len) {
    struct pkt_info pinfo;
    get_pkt_info(hdr, pload, len, &pinfo);

    for (int i = 0; i < num_rules; i++)
        if (matches(&pinfo, rules + i)) {
            print_match(&pinfo, rules + i);
        }
}

void get_pkt_info(struct ip_header *ip_hdr,
        uint8_t *ip_pload, int pload_len, struct pkt_info *pinfo) {
    pinfo->ip_hdr = ip_hdr;
    pinfo->tcp_hdr = NULL;
    pinfo->udp_hdr = NULL;

    if (pinfo->ip_hdr->proto == IP_PROTO_TCP) {
        pinfo->tcp_hdr = (struct tcp_header *) ip_pload;
        *pinfo->tcp_hdr = tcp_ntoh(pinfo->tcp_hdr);
        pinfo->tcp_pload = (uint8_t *)pinfo->tcp_hdr + TCP_DATAOFF(pinfo->tcp_hdr);
        pinfo->tcp_pload_len =
            ip_hdr->len - IP_IHL(ip_hdr) - TCP_DATAOFF(pinfo->tcp_hdr);
        get_http_method(pinfo->tcp_pload, pinfo->tcp_pload_len,
            &pinfo->http_method);
    } else if (pinfo->ip_hdr->proto == IP_PROTO_UDP) {
        pinfo->udp_hdr = (struct udp_header *) ip_pload;
        *pinfo->udp_hdr = udp_ntoh(pinfo->udp_hdr);
        pinfo->udp_pload = (uint8_t *)pinfo->udp_hdr + sizeof(struct udp_header);
        pinfo->udp_pload_len =
            pinfo->udp_hdr->len - sizeof(struct udp_header);
        get_http_method(pinfo->udp_pload, pinfo->udp_pload_len,
            &pinfo->http_method);
    }
}

char valid_methods[NUM_VALID_METHODS][HTTP_METHOD_BUFSIZ] = {
    "OPTIONS", "GET", "HEAD",
    "POST", "PUT", "DELETE",
    "TRACE", "CONNECT"
};

void get_http_method(uint8_t *pload, int pload_len, char **method) {
    if (pload_len == 0) {
        *method = NULL;
        return;
    }

    for (int i = 0; i < NUM_VALID_METHODS; i++) {
        int method_len = strlen(valid_methods[i]);
        // Have to use strncmp, because:
        //   strcmp("GET", "GET ...") != 0
        //   strncmp("GET", "GET ...", 3) == 0
        if (strncmp(pload, valid_methods[i],
                pload_len < method_len ?pload_len :method_len) == 0) {
            *method = valid_methods[i];
            return;
        }
    }

    *method = NULL;
}

bool matches(const struct pkt_info *pinfo, const struct rule *rule) {
    uint8_t proto = pinfo->ip_hdr->proto;

    if (proto != IP_PROTO_TCP && proto != IP_PROTO_UDP)
        return false;

    // Debug match
    ERR("match: prot %d  ", protocol_matches(pinfo, rule));
    ERR("src %d  ", src_addr_matches(pinfo, rule));
    ERR("port %d  ", src_port_matches(pinfo, rule));
    ERR("dst %d  ", dst_addr_matches(pinfo, rule));
    ERR("port %d\n", dst_port_matches(pinfo, rule));

    ERR("       tos %d  ", tos_matches(pinfo, rule));
    ERR("len %d  ", len_matches(pinfo, rule));
    ERR("off %d\n", offset_matches(pinfo, rule));

    ERR("       seq %d  ", seq_matches(pinfo, rule));
    ERR("ack %d  ", ack_matches(pinfo, rule));
    ERR("flg %d\n", flags_matches(pinfo, rule));

    ERR("       mtd %d  ", http_request_matches(pinfo, rule));
    ERR("ctt %d\n", content_matches(pinfo, rule));

    return
        // protocol
        protocol_matches(pinfo, rule) &&
        // src addr port
        src_addr_matches(pinfo, rule) &&
        src_port_matches(pinfo, rule) &&
        // dst addr port
        dst_addr_matches(pinfo, rule) &&
        dst_port_matches(pinfo, rule) &&
        // ip
        tos_matches(pinfo, rule) &&
        len_matches(pinfo, rule) &&
        offset_matches(pinfo, rule) &&
        // tcp
        seq_matches(pinfo, rule) &&
        ack_matches(pinfo, rule) &&
        flags_matches(pinfo, rule) &&
        // http
        http_request_matches(pinfo, rule) &&
        content_matches(pinfo, rule);
}

/* Protocol */

bool protocol_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    enum protocol rule_proto = rule->protocol;
    uint8_t proto = pinfo->ip_hdr->proto;

    if (proto == IP_PROTO_UDP) {
        return rule_proto == PROTO_UDP ||
            (rule_proto == PROTO_HTTP && pinfo->http_method != NULL);
    }
    else if (proto == IP_PROTO_TCP) {
        return rule_proto == PROTO_TCP ||
            (rule_proto == PROTO_HTTP && pinfo->http_method != NULL);
    }

    return false;
}

/* Address matching */

bool src_addr_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    return addr_matches(rule->src_addr, pinfo->ip_hdr->src);
}

bool dst_addr_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    return addr_matches(rule->dst_addr, pinfo->ip_hdr->dst);
}

bool addr_matches(struct ip_addr rule_addr, uint32_t addr32) {
    return rule_addr.any || rule_addr.addr == addr32;
}

/* Port matching */

bool src_port_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    uint8_t proto = pinfo->ip_hdr->proto;

    if (proto == IP_PROTO_UDP)
        return port_matches(rule->src_ports, pinfo->udp_hdr->src_port);
    else if (proto == IP_PROTO_TCP)
        return port_matches(rule->src_ports, pinfo->tcp_hdr->src_port);
    return false;
}

bool dst_port_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    uint8_t proto = pinfo->ip_hdr->proto;

    if (proto == IP_PROTO_UDP)
        return port_matches(rule->dst_ports, pinfo->udp_hdr->dst_port);
    else if (proto == IP_PROTO_TCP)
        return port_matches(rule->dst_ports, pinfo->tcp_hdr->dst_port);
    return false;
}

bool port_matches(struct ports ports, uint16_t port) {
    if (ports.any)
        return true;

    if (ports.list_len > 0) {
        for (int i = 0; i < ports.list_len; i++)
            if (ports.list[i] == port)
                return true;
        return false;
    } else {
        return ports.from <= port && port <= ports.to;
    }
}

/* IP */

bool tos_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    uint32_t rule_tos = rules->options.tos;
    uint8_t tos = pinfo->ip_hdr->tos;
    return rule_tos == -1 || rule_tos == tos;
}

bool len_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    uint32_t rule_len = rule->options.len;
    uint8_t ihl = IP_IHL(pinfo->ip_hdr);
    return rule_len == -1 || rule_len == ihl;
}

bool offset_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    uint32_t rule_offset = rule->options.offset;
    uint16_t offset = IP_FRAGOFF(pinfo->ip_hdr);
    return rule_offset == -1 || rule_offset == offset;
}

/* TCP */

bool seq_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    uint8_t proto = pinfo->ip_hdr->proto;
    uint64_t rule_seq = rule->options.seq;

    if (proto != IP_PROTO_TCP)
        return rule_seq == -1;

    uint32_t seq = pinfo->tcp_hdr->seq;
    return rule_seq == -1 || rule_seq == seq;
}

bool ack_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    uint8_t proto = pinfo->ip_hdr->proto;
    uint64_t rule_ack = rule->options.ack;

    if (proto != IP_PROTO_TCP)
        return rule_ack == -1;

    uint32_t ack = pinfo->tcp_hdr->ack;
    return rule_ack == -1 || rule_ack == ack;
}

bool flags_matches(const struct pkt_info *pinfo, const struct rule *rule) {
    uint8_t proto = pinfo->ip_hdr->proto;
    uint32_t rule_flags = rule->options.flags;

    if (proto != IP_PROTO_TCP)
        return rule_flags == 0;

    uint16_t flags = TCP_FLAGS(pinfo->tcp_hdr);
    return rule_flags == 0 || rule_flags == flags;
}

/* HTTP */

bool http_request_matches(const struct pkt_info *pinfo,
        const struct rule *rule) {
    char *rule_http_request = rule->options.http_request;
    if (rule_http_request == NULL)
        return true;

    //if (pinfo->http_method == NULL)
    //    return false;

    uint8_t proto = pinfo->ip_hdr->proto;
    uint8_t *pload = proto == IP_PROTO_TCP
        ?pinfo->tcp_pload :pinfo->udp_pload;
    int pload_len = proto == IP_PROTO_TCP
        ?pinfo->tcp_pload_len :pinfo->udp_pload_len;
    int req_len = strlen(rule_http_request);

    if (pload_len < req_len)
        return false;

    return strncmp(rule_http_request, pload, req_len) == 0;
    //return strcmp(rule_http_request, pinfo->http_method) == 0;
}

bool content_matches(const struct pkt_info *pinfo,
        const struct rule *rule) {
    char *content = rule->options.content;
    if (content == NULL)
        return true;

    uint8_t proto = pinfo->ip_hdr->proto;
    uint8_t *pload = proto == IP_PROTO_TCP
        ?pinfo->tcp_pload :pinfo->udp_pload;
    int pload_len = proto == IP_PROTO_TCP
        ?pinfo->tcp_pload_len :pinfo->udp_pload_len;

    int content_len = strlen(content);
    if (content_len == 0)
        return true;

    for (int i = 0; i < pload_len; i++) {
        if (pload_len-i >= content_len
                && strncmp(content, pload+i, content_len) == 0) {
            return true;
        }
    }
    
    return false;
}

/* Helpers */

#define REDDEN(cond, stmts) \
    { \
        bool __highlight = cond; \
        { if (__highlight) printf(KRED); } \
        stmts \
        { if (__highlight) printf(KRST); } \
    }


void print_match(const struct pkt_info *pinfo, const struct rule *rule) {
    struct ip_header *ihdr= pinfo->ip_hdr;
    struct tcp_header *thdr= pinfo->tcp_hdr;
    struct udp_header *uhdr= pinfo->udp_hdr;

    printf("\nRule: %s\n", rule->str);
    printf("===============================\n");

    /* IP */

    printf("[IP header]\n");
    printf("Version: %d\n", IP_VERSION(ihdr));

    REDDEN(
        rule->options.len != -1 && len_matches(pinfo, rules),
        printf("Header Length: %d bytes\n", IP_IHL(ihdr));
    )

    REDDEN(
        rule->options.tos != -1 && tos_matches(pinfo, rule),
        printf("ToS: 0x%X\n", ihdr->tos);
    )
    REDDEN(
        rule->options.offset != -1 && offset_matches(pinfo, rule),
        printf("Fragment Offset: %d bytes\n", IP_FRAGOFF(ihdr));
    )

    uint32_t addr32;
    struct in_addr addr;

    REDDEN(
        !rule->src_addr.any && src_addr_matches(pinfo, rule),
        addr32 = htonl(ihdr->src);
        addr = *(struct in_addr *) &addr32;
        printf("Source: %s\n", inet_ntoa(addr));
    )

    REDDEN(
        !rule->dst_addr.any && dst_addr_matches(pinfo, rule),
        addr32 = htonl(ihdr->dst);
        addr = *(struct in_addr *) &addr32;
        printf("Destination: %s\n" KRST, inet_ntoa(addr));
    )

    printf("\n");
    /* TCP */
    if (thdr != NULL) {
        printf("[TCP header]\n");

        REDDEN(
            !rule->src_ports.any && src_port_matches(pinfo, rule),
            printf("Source Port: %d\n", thdr->src_port);
        )

        REDDEN(
            !rule->dst_ports.any && dst_port_matches(pinfo, rule),
            printf("Destination Port: %d\n", thdr->dst_port);
        )

        REDDEN(
            rule->options.seq != -1 && seq_matches(pinfo, rule),
            printf("Sequence Number: %u\n", thdr->seq);
        )

        REDDEN(
            rule->options.ack != -1 && ack_matches(pinfo, rule),
            printf("Acknowledgement Number: %u\n", thdr->ack);
        )
        
        // flags
        REDDEN(
            rule->options.flags != 0 && flags_matches(pinfo, rule),

            printf("Flags: ");

            if (TCP_FLAGS(thdr) == 0)
                printf("none");
            if (TCP_FLAGS(thdr) & (1<<FLAG_FIN))
                printf("FIN ");
            if (TCP_FLAGS(thdr) & (1<<FLAG_SYN))
                printf("SYN ");
            if (TCP_FLAGS(thdr) & (1<<FLAG_RST))
                printf("RST ");
            if (TCP_FLAGS(thdr) & (1<<FLAG_PSH))
                printf("PSH ");
            if (TCP_FLAGS(thdr) & (1<<FLAG_ACK))
                printf("ACK ");
            printf("\n");
        )
    }
    /* UDP */
    else {
        printf("[UDP header]\n");

        REDDEN(
            !rule->src_ports.any && src_port_matches(pinfo, rule),
            printf("Source Port: %d\n", uhdr->src_port);
        )

        REDDEN(
            !rule->dst_ports.any && dst_port_matches(pinfo, rule),
            printf("Destination Port: %d\n", uhdr->dst_port);
        )

        printf("Checksum: 0x%04X\n", uhdr->sum);
    }

    /* HTTP */

    printf("\n");
    if (thdr != NULL) {
        printf("[TCP payload]\n");
        printf("Payload size: %d bytes\n", pinfo->tcp_pload_len);
    } else {
        printf("[UDP payload]\n");
        printf("Payload size: %d bytes\n", pinfo->udp_pload_len);
    }

    REDDEN(
        rule->options.http_request != NULL && http_request_matches(pinfo, rule),
        printf("HTTP Request: %s\n",
            pinfo->http_method ?pinfo->http_method :"none");
    )

    printf("Payload:\n");
    print_content_match(pinfo, rule);

    printf("\n===============================\n");
    printf("Message: %s\n\n", rule->options.msg);
}

void print_content_match(const struct pkt_info *pinfo,
        const struct rule *rule) {
    char *content = rule->options.content;

    uint8_t proto = pinfo->ip_hdr->proto;
    uint8_t *pload = proto == IP_PROTO_TCP
        ?pinfo->tcp_pload :pinfo->udp_pload;
    int pload_len = proto == IP_PROTO_TCP
        ?pinfo->tcp_pload_len :pinfo->udp_pload_len;

    printf(KYEL);
    if (content == NULL || *content == '\0') {
        for (int i = 0; i < pload_len; i++)
            putchar(pload[i]);
    } else {
        int content_len = strlen(content);
        for (int i = 0; i < pload_len; i++) {
            if (pload_len-i >= content_len
                    && strncmp(content, pload+i, content_len) == 0) {
                printf(KRED "%s" KYEL, content);
                i += content_len-1;
            } else {
                putchar(pload[i]);
            }
        }
    }
    printf(KRST);
    fflush(stdout);
}

