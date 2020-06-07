#include <pcap/pcap.h>
#include <stdio.h>
//#include <stdlib.h>
//#include <errno.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <netinet/if_ether.h>
//#include <net/ethernet.h>
//#include <netinet/ether.h>
#include "proto_headers.h"

void on_packet_arrive(u_char *args, const struct pcap_pkthdr* pkthdr,
    const u_char* packet) {

    struct ether_header *eth_hdr = (struct ether_header *) packet;
    struct ip_header *hdr =
        (struct ip_header *) (packet + sizeof(struct ether_header));
    char *pload = (char *)hdr + IP_IHL(hdr);
    int len = hdr->len - IP_IHL(hdr);

    // Network to host order
    *hdr = ip_ntoh(hdr);

    patch_part(hdr, pload, len);
}

int main(int argc, char **argv)
{ 
    pcap_t *handle;			/* Session handle */
    char *dev;                          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];      /* Error string */
    struct bpf_program fp;              /* The compiled filter */

    /* The filter expression */
    char filter_exp[] = "ip host 81.27.240.126";
    //char filter_exp[] = "ether proto \\ip and host 81.27.240.126";

    bpf_u_int32 mask;                   /* Our netmask */
    bpf_u_int32 net;                    /* Our IP */
    struct pcap_pkthdr header;          /* The header that pcap gives us */
    const u_char *packet;               /* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    printf("dev=%s\n", dev);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
        return(2);
    }

    /* Single packet */
    // /* Grab a packet */
    // packet = pcap_next(handle, &header);
    // /* Print its length */
    // printf("Jacked a packet with length of [%d]\n", header.len);

    /* Loop */
    pcap_loop(handle, -1, on_packet_arrive, NULL);
    // cnt < 0 ==> always capture

    /* And close the session */
    pcap_close(handle);
    return(0);
}

