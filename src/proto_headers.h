#include <stdint.h>
#include <arpa/inet.h>

struct ether_header {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct ip_header {
    uint8_t version_ihl; // version:4  ihl:4
    #define IP_IHL(X) ((X)->version_idl >> 4) // header len
    #define IP_VERSION(X) ((X)->version_idl & 0x0F)
    uint8_t tos;
    uint16_t len; // header + payload len
    uint16_t id;
    uint16_t flags_fragoff; // flags:3  fragoff:13
    #define IP_FLAGS(X) ((X)->flags_fragoff & 0x7)
    #define IP_DF(X) ((IP_FLAGS(X) >> 1) & 1)
    #define IP_MF(X) ((IP_FLAGS(X) >> 2) & 1)
    #define IP_FRAGOFF(X) ((X)->flags_fragoff >> 3)
    uint8_t ttl;
    uint8_t proto;
    uint16_t sum;
    uint32_t src;
    uint32_t dst;
};

struct ip_pkt_info {
    struct ip_header *hdr;
}

struct ip_header ip_ntoh(const struct ip_header *hdr) {
    struct ip_header new_hdr = *hdr;

    new_hdr->len = htons(hdr->len);
    new_hdr->id = htons(hdr->id);
    new_hdr->flags_fragoff = htons(hdr->flags_fragoff);
    new_hdr->sum = htons(hdr->sum);
    new_hdr->src = htonl(hdr->src);
    new_hdr->dst = htonl(hdr->dst);

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
    uint16_t window;
    uint16_t sum;
    uint16_t urg_ptr;
    uint8_t options[3];
    uint8_t padding;
};

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len; // header + data
    uint16_t sum;
};

