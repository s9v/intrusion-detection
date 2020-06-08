#include <stdio.h>
#include <stdlib.h>
#include "rules.h"
#include "colors.h"
#include "capture.h"

#define PKT_SIZE 1024


int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Error: not enough parameters.\n"
            "Usage: %s snort_rules_file\n", argv[0]);
        return EXIT_FAILURE;
    }

    int num_rules_read;
    int num_rules_ignored;
    if (read_rules(argv[1], &num_rules_read, &num_rules_ignored) < 0) {
        fprintf(stderr, "Error: can't open %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    if (num_rules_ignored > 0) {
        printf("Rules:  num valid (%d/%d),  "KRED"num invalid (%d)"KRST"\n",
            num_rules_read - num_rules_ignored,
            num_rules_read, num_rules_ignored);
    } else {
        printf("Rules:  num valid (%d/%d),  num invalid (%d)\n",
            num_rules_read - num_rules_ignored,
            num_rules_read, num_rules_ignored);
    }

    assert(num_rules_read >= num_rules_ignored);
    if (num_rules_read - num_rules_ignored == 0) {
        printf("No valid rules. Exiting...\n");
        return 0;
    }
    
    printf("Waiting for captured packets...\n");
    if (start_pkt_capture() < 0) {
        fprintf(stderr, "Error: can't init packet capture");
        return EXIT_FAILURE;
    }

    return 0;
}
