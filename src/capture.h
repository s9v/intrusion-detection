// Modified from https://www.tcpdump.org/pcap.html

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include "proto_headers.h"
#include "assemble_ip.h"

void on_packet_arrive(u_char *args, const struct pcap_pkthdr* pkthdr,
    const u_char* packet);
int start_pkt_capture(void);

// Invoked upon new packet capture
// (pcap_loop callback funtion)
void on_packet_arrive(u_char *args, const struct pcap_pkthdr* pkthdr,
    const u_char* packet) {

    // Debugging packet
    // uint8_t *p = (uint8_t *) packet;
    // for (int i = 0; i < 6; i++) ERR("0x%02X ", *p++);
    // ERR("\n");
    // for (int i = 0; i < 6; i++) ERR("0x%02X ", *p++);
    // ERR("\n");
    // for (int i = 0; i < 2; i++) ERR("0x%02X ", *p++);
    // ERR("\n");
    // for (int i = 0; i < 5; i++) {
    //     for (int j = 0; j < 4; j++)
    //         ERR("0x%02X ", *p++);
    //     ERR("\n");
    // }

    uint8_t *new_packet = malloc(pkthdr->caplen);
    memcpy(new_packet, packet, pkthdr->caplen);

    struct ether_header *eth_hdr = (struct ether_header *) new_packet;
    struct ip_header *ip_hdr =
        (struct ip_header *) (new_packet + sizeof(struct ether_header));

    // Network to host order
    *ip_hdr = ip_ntoh(ip_hdr);

    // Patch corresponding partial with this IP fragment,
    // ~*AND*~
    // match against rules if partial is completely patched.
    char *ip_pload = (char *)ip_hdr + IP_IHL(ip_hdr);
    int pload_len = (int)ip_hdr->len - IP_IHL(ip_hdr);
    patch_part(ip_hdr, ip_pload, pload_len);

    free(new_packet);
}

// Start capturing packets using libpcap
int start_pkt_capture(void) { 
    pcap_t *handle;			/* Session handle */
    char *dev;                          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];      /* Error string */
    struct bpf_program fp;              /* The compiled filter */

    /* The filter expression */
    char filter_exp[] = "ip"; // only IP packets please
    // char filter_exp[] = "ip host 81.27.240.126"; // codeforces.com
    // char filter_exp[] = "ip host 123.45.67.89"; // scapy only

    bpf_u_int32 mask;                   /* Our netmask */
    bpf_u_int32 net;                    /* Our IP */
    struct pcap_pkthdr header;          /* The header that pcap gives us */
    const u_char *packet;               /* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return -1;
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, MAX_IP_PKT_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
        return -1;
    }

    /* Loop */
    // cnt < 0 means always capture
    pcap_loop(handle, -1, on_packet_arrive, NULL);

    /* Close the session */
    pcap_close(handle);

    return 0;
}

