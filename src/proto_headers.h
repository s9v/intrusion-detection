#pragma once
#include <stdint.h>
#include <arpa/inet.h>

#define MAX_IP_PKT_SIZE 65536

#define IP_PROTO_TCP 0x06
#define IP_PROTO_UDP 0x11

struct ether_header {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct ip_header {
    uint8_t version_ihl; // version:4  ihl:4
    #define IP_IHL(X) ((uint32_t)((X)->version_ihl & 0x0F) << 2)
    #define IP_VERSION(X) ((uint32_t)((X)->version_ihl) >> 4)  // header len
    uint8_t tos;
    uint16_t len; // header + payload len
    uint16_t id;
    uint16_t flags_fragoff; // flags:3  fragoff:13
    #define IP_FLAGS(X) ((uint32_t)((X)->flags_fragoff) >> 13)
    #define IP_DF(X) ((IP_FLAGS(X) >> 1) & 1)
    #define IP_MF(X) (IP_FLAGS(X) & 1)
    #define IP_FRAGOFF(X) (((uint32_t)((X)->flags_fragoff) & ~(0x7 << 13)) << 3)
    uint8_t ttl;
    uint8_t proto;
    uint16_t sum;
    uint32_t src;
    uint32_t dst;
};

struct ip_header ip_ntoh(const struct ip_header *hdr) {
    struct ip_header new_hdr = *hdr;

    new_hdr.len = ntohs(hdr->len);
    new_hdr.id = ntohs(hdr->id);
    new_hdr.flags_fragoff = ntohs(hdr->flags_fragoff);
    new_hdr.sum = ntohs(hdr->sum);
    new_hdr.src = ntohl(hdr->src);
    new_hdr.dst = ntohl(hdr->dst);

    return new_hdr;
}

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t dataoff_flags; // dataoff:4, reserved:6, flags:6
                            // (URG, ACK, PSH, RST, SYN, FIN)
                            // dataoff = header size
    #define TCP_FLAGS(X) ((X)->dataoff_flags & 0x1F)
    #define TCP_DATAOFF(X) (((X)->dataoff_flags >> 12) << 2)
    uint16_t window;
    uint16_t sum;
    uint16_t urg_ptr;
    uint32_t options;
};

struct tcp_header tcp_ntoh(const struct tcp_header *hdr) {
    struct tcp_header new_hdr = *hdr;

    new_hdr.src_port = ntohs(hdr->src_port);
    new_hdr.dst_port = ntohs(hdr->dst_port);
    new_hdr.seq = ntohl(hdr->seq);
    new_hdr.ack = ntohl(hdr->ack);
    new_hdr.dataoff_flags = ntohs(hdr->dataoff_flags);
    new_hdr.window = ntohs(hdr->window);
    new_hdr.sum = ntohs(hdr->sum);
    new_hdr.urg_ptr = ntohs(hdr->urg_ptr);

    return new_hdr;
}

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len; // header + data
    uint16_t sum;
};

struct udp_header udp_ntoh(const struct udp_header *hdr) {
    struct udp_header new_hdr = *hdr;

    new_hdr.src_port = ntohs(hdr->src_port);
    new_hdr.dst_port = ntohs(hdr->dst_port);
    new_hdr.len = ntohs(hdr->len);
    new_hdr.sum = ntohs(hdr->sum);

    return new_hdr;
}
