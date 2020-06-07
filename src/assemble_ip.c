#include <stdbool.h>
#define MAX_IP_PKT_SIZE 65536

// Represents IP "partial" -
// partial or full composition of fragmented IP packets
struct ip_part {
    struct ip_header hdr;
    uint8_t pload[MAX_IP_PKT_SIZE];
    int len; // payload len
    struct hlist hlist;
};

const int num_parts = 128;
int ids[num_parts];
bool used[num_parts];
struct ip_part parts[num_parts];

// Find partial index by IP packet ID
int part_idx_by_id(uint16_t ip_iden) {
    for (int i = 0; i < num_ptls; i++) {
        if (used[i] && ip_iden == ids[i]) {
            return i;
        }
    }

    return -1;
}

// Find and fill in corresponding IP partial with given IP fragment.
void patch_part(struct ip_header *hdr, char *pload, int len) {
    int idx = part_idx_by_id(hdr->id);

    if (idx < 0) {
        idx = init_part();

        // No room for this IP fragment. Ignoring packet...
        if (idx < 0) return;

        used[idx] = true;
        ids[idx] = hdr->idx;
        parts[idx].hdr = *hdr;
    } else {
        
    }
}

int init_part(void) {
    int idx = -1;
    for (int i = 0; i < MAX_PARTIALS_NO; i++)
        if (!used[i])
            idx = i;

    if (idx == -1)
        return -1;

    hlist_init(&parts[idx].hlist);
}

int free_part(int idx) {
    used[idx] = false;

    struct hnode *todel = &ptls[idx].hole_list.head.next;
    while (todel != NULL)
        todel = hlist_delete(todel);
}

