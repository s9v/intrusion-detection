#pragma once
#include <stdbool.h>
#include "proto_headers.h"
#include "hole_list.h"
#include "helpers.h"
#include "match.h"

/*
 * Hole patching algorithm for IP datagram reassembly
 * See: https://tools.ietf.org/html/rfc815
 */

//
// Declarations
//

// Represents IP "partial" -
// partial or full composition of fragmented IP packets
struct ip_part {
    struct ip_header hdr;
    uint8_t pload[MAX_IP_PKT_SIZE];
    int len; // payload len
    struct hnode hlist; // head of hole list
};

void patch_part(struct ip_header *hdr, char *pload, int len);
int part_idx_by_id(uint16_t ip_iden);
int create_part(const struct ip_header *hdr, char *pload, int len);
void free_part(int idx);

//
// Definitions
//

// Partials
#define NUM_PARTS 1024
int ids[NUM_PARTS] = {0};
bool used[NUM_PARTS] = {0};
struct ip_part parts[NUM_PARTS];

// Finds and fills in corresponding IP partial with given IP fragment.
void patch_part(struct ip_header *hdr, char *pload, int len) {
    ///*
    int fff = IP_FRAGOFF(hdr);
    int lll = fff + len - 1;
    ERR("<Pkt   id=%d  fragment=[%d, %d]   MF=%d  proto=0x%X>\n",
        hdr->id, fff, lll, IP_MF(hdr), hdr->proto);
    uint32_t addr32 = htonl(hdr->src);
    struct in_addr addr = *(struct in_addr *) &addr32;
    ERR("src: %s  " KRST, inet_ntoa(addr));
    addr32 = htonl(hdr->dst);
    addr = *(struct in_addr *) &addr32;
    ERR("dst: %s\n" KRST, inet_ntoa(addr));
    //*/

    // unfragmented IP packet, skip assembly.
    if (IP_FRAGOFF(hdr) == 0 && !IP_MF(hdr)) {
        // ERR("[unfragmented]\n");
        match_packet(hdr, pload, len);
        return;
    }

    int idx = part_idx_by_id(hdr->id);

    // Create new partial, if not already created
    if (idx < 0) {
        idx = create_part(hdr, pload, len);

        // No room for this IP packet. Ignoring packet...
        if (idx < 0) return;
    }

    struct ip_part *part = parts + idx;

    /* Patch holes with this fragment */
    
    // fragment range
    int first = IP_FRAGOFF(hdr);
    int last = first + len - 1;

    // Calculate whole payload length, if this is last fragment.
    if (!IP_MF(hdr)) 
        part->len = last+1;

    // Debug hole list
    // ERR("[ ");
    // for (struct hnode *cur = part->hlist.next; cur != NULL; cur = cur->next) {
    //     ERR("%d:%d,", cur->first, cur->last);
    // }
    // ERR(" ]\n");

    // patch holes from hole list
    uint8_t *dst_pload = part->pload;
    struct hnode *cur = parts[idx].hlist.next;
    struct hnode *prev;
    while (cur != NULL) {
        int cfirst = cur->first;
        int clast = cur->last;

        if (first <= clast && cfirst <= last) {
            // copy [from, to]
            int from = first > cfirst ?first :cfirst;
            int to   = last < clast ?last :clast;
            memcpy(dst_pload + from,
                pload + from - first,
                to - from + 1);

            if (last < clast)
                hlist_insert(cur, hlist_new(last+1, clast));

            if (cfirst < first)
                hlist_insert(cur, hlist_new(cfirst, first-1));

            cur = hlist_delete(cur);
        } else {
            cur = cur->next;
        }
    }

    // Debug hole list
    // ERR("[ ");
    // for (struct hnode *cur = part->hlist.next; cur != NULL; cur = cur->next) {
    //     ERR("%d:%d,", cur->first, cur->last);
    // }
    // ERR(" ]\n");

    // match packet to rules, if packet is fully reassembled.
    assert(part->hlist.next != NULL);
    if (part->len != -1 &&
            part->len <= part->hlist.next->first) {
        ERR("[assembled]\n");
        match_packet(&part->hdr, part->pload, part->len);
        free_part(idx);
    }
}

// Finds partial index by IP packet ID
int part_idx_by_id(uint16_t ip_iden) {
    for (int i = 0; i < NUM_PARTS; i++) {
        if (used[i] && ip_iden == ids[i]) {
            return i;
        }
    }

    return -1;
}

int create_part(const struct ip_header *hdr, char *pload, int len) {
    int idx = -1;

    // find empty slot
    for (int i = 0; i < NUM_PARTS; i++)
        if (!used[i])
            idx = i;

    if (idx == -1)
        return -1;

    used[idx] = true;
    ids[idx] = hdr->id;
    struct ip_part *part = parts + idx;
    part->len = -1;
    part->hdr = *hdr;
    part->hdr.flags_fragoff &= 0x7;
    hlist_init(&part->hlist);
    hlist_insert(&part->hlist, hlist_new(0, MAX_IP_PKT_SIZE));

    return idx;
}

void free_part(int idx) {
    used[idx] = false;

    struct hnode *todel = parts[idx].hlist.next;
    while (todel != NULL)
        todel = hlist_delete(todel);
}

