#include <stdio.h>
#include <stdint.h>
#include "packet.h"

#define PKT_SIZE 1024

int main()
{
    /* struct ether *eth_pkt; */
    /* struct ip *ip_pkt; */
    /* struct tcp *tcp_pkt; */
    printf("ether size %lu\n", sizeof(struct ether));
    printf("ether size %lu\n", sizeof(struct ip));
    printf("ether size %lu\n", sizeof(struct tcp));

    uint8_t pkt[PKT_SIZE];
    int pkt_len = 0;

    FILE *f = fopen("tcp_pkt", "rb");

    char c;
    while ((c = fgetc(f)) != EOF)
        pkt[pkt_len++] = c;
    
    for (int i = 0; i < pkt_len; i++) {
        printf("%x ", pkt[i]);
        if (i%16 == 15)
            printf("\n");
    }

    return 0;
}
