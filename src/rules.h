#pragma once
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "helpers.h"

#define MAX_PORT_NO 65535
#define RULES_BUFSIZ 128
#define LINE_BUFSIZ 512

enum action { ACTION_ALERT };
enum protocol { PROTO_TCP, PROTO_UDP, PROTO_HTTP };

struct ip_addr {
    uint32_t addr;
    bool any;
} addr_default = { 0x0, false };

struct ports {
    int from; // from:to
    int to;
    int list_len;
    int *list; // port1,port2,port3
    bool any;
} ports_default = {0, 0, 0, NULL, false};

// Note: Order of flags is important. Used to toggle bits using (1<<FLAG_XXX).
enum tcp_flag { FLAG_FIN, FLAG_SYN, FLAG_RST, FLAG_PSH, FLAG_ACK };
struct options {
    char *msg;
    uint32_t tos;
    uint32_t len;
    uint32_t offset;
    uint64_t seq;
    uint64_t ack;
    uint32_t flags; // TODO if this is changed, fix options_default
    char *http_request;
    char *content;
} options_default = {NULL, -1, -1, -1, -1, -1, 0, NULL, NULL};

struct rule {
    char *str; // original rule string
    enum action action;
    enum protocol protocol;
    struct ip_addr src_addr;
    struct ports src_ports;
    struct ip_addr dst_addr;
    struct ports dst_ports;
    struct options options;
};

int num_rules;
struct rule rules[RULES_BUFSIZ];

char *dup_range(const char *src, int start, int end);
int parse_rule(const char *rule_str, struct rule *rule);
int parse_action(const char *s, enum action *action);
int parse_protocol(const char *s, enum protocol *protocol);
int parse_ip(const char *s, struct ip_addr *ip);
int parse_ports(const char *s, struct ports *ports);
int parse_option(const char *s, struct options *options);

/* Utility functions */

int read_rules(const char *rules_filename, int *num_rules_read,
        int *num_rules_ignored) {
    // Init variables
    num_rules = 0;
    *num_rules_read = 0;
    *num_rules_ignored = 0;

    // Open rules file
    FILE *frules;
    if ((frules = fopen(rules_filename, "r")) == NULL) {
        ERR("error: can't open frules\n");
        return -1;
    }

    // Read and parse lines of rules
    size_t buff_len = LINE_BUFSIZ;
    char *line = malloc(buff_len);
    int nread;
    while ((nread = getline(&line, &buff_len, frules)) >= 0) {
        if (nread > 0 && line[nread-1] == '\n')
            line[nread-1] = '\0';

        *num_rules_read += 1;

        ERR("=[ LINE #%03d ]======================\n", *num_rules_read);
        ERR("%s\n\n", line);
        if (parse_rule(line, rules + num_rules) < 0) {
            *num_rules_ignored += 1;
        } else {
            num_rules++;
        }
        ERR("===================================\n");
    }

    return 0;
}

/* Helper functions */

// Creates new string and copies given range [start, end).
char *dup_range(const char *src, int start, int end) {
    int len = end-start;
    char *dst = malloc(len+1);
    memcpy(dst, src + start, len);
    dst[len] = '\0';
    return dst;
}

// Nicer strtol() version, returns -1 on error.
// Parses S and stores the number to N.
int temp_n;
long long temp_nn;

int nicer_strtol(const char *s, int *n) {
    errno = 0;
    *n = strtol(s, NULL, 0);
    return errno < 0 ?-1 :0;
}

int nicer_strtoll(const char *s, long long *n) {
    errno = 0;
    *n = strtol(s, NULL, 0);
    return errno < 0 ?-1 :0;
}

// Strips leading and trailing whitespace from string.
void strip_space(char *s) {
    if (*s == '\0')
        return;

    char *from = s;
    char *to = strchr(s, '\0') - 1;
    while (from <= to && isspace(*from))
        from++;
    while (from <= to && isspace(*to))
        to--;
    while (from <= to) {
        *s = *from;
        s++, from++;
    }
    *s = '\0';
}

/* Actual parsing functions */

// Parses rule struct from given string.
// Returns -1 on invalid syntax.
int parse_rule(const char *rule_str, struct rule *rule) {
    enum state {
        SPACE1, ACTION,
        SPACE2, PROTOCOL,
        SPACE3, SRC_IP,
        SPACE4, SRC_PORT,
        SPACE5,
        ARROW1, ARROW2,
        SPACE6, DST_IP,
        SPACE7, DST_PORT,
        SPACE8,  OPS_START,
        SPACE9, OPTION,
        OPT_DELIM, OPS_END
    };
    enum state state = SPACE1;

    // Copy rule string
    rule->str = malloc(strlen(rule_str) + 1);
    strcpy(rule->str, rule_str);

    // Init rule options
    rule->options = options_default;

    // Parse rule
    int len = strlen(rule_str);
    int last = 0;
    for (int i = 0; i < len; i++) {
        char c = rule_str[i];
        // ERR("%c", c);

        if (state == SPACE1) {
            if (!isspace(c)) {
                // transition
                last = i;
                if (isalpha(c)) {
                    state = ACTION;
                } else {
                    return -1;
                }
            }
        } else if (state == ACTION) {
            if (!isalpha(c)) {
                // parse current range
                char *s = dup_range(rule_str, last, i);
                if (parse_action(s, &rule->action) < 0)
                    return -1;
                free(s);

                // transition
                last = i;
                if (isspace(c)) {
                    state = SPACE2;
                } else {
                    return -1;
                }
            }
        } else if (state == SPACE2) {
            if (!isspace(c)) {
                // transition
                last = i;
                if (isalpha(c)) {
                    state = PROTOCOL;
                } else {
                    return -1;
                }
            }
        } else if (state == PROTOCOL) {
            if (!isalpha(c)) {
                // parse current range
                char *s = dup_range(rule_str, last, i);
                if (parse_protocol(s, &rule->protocol) < 0)
                    return -1;
                free(s);

                // transition
                last = i;
                if (isspace(c)) {
                    state = SPACE3;
                } else {
                    return -1;
                }
            }
        } else if (state == SPACE3) {
            if (!isspace(c)) {
                // transition
                last = i;
                if (isalnum(c)) {
                    state = SRC_IP;
                } else {
                    return -1;
                }
            }
        } else if (state == SRC_IP) {
            if (!isalnum(c) && c != '.') {
                // parse current range
                char *s = dup_range(rule_str, last, i);
                if (parse_ip(s, &rule->src_addr) < 0)
                    return -1;
                free(s);

                // transition
                last = i;
                if (isspace(c)) {
                    state = SPACE4;
                } else {
                    return -1;
                }
            }
        } else if (state == SPACE4) {
            if (!isspace(c)) {
                // transition
                last = i;
                if (isalnum(c) || c == ':') {
                    state = SRC_PORT;
                } else {
                    return -1;
                }
            }
        } else if (state == SRC_PORT) {
            if (!isalnum(c) && c != ':' && c != ',') {
                // parse current range
                char *s = dup_range(rule_str, last, i);
                if (parse_ports(s, &rule->src_ports) < 0)
                    return -1;
                free(s);

                // transition
                last = i;
                if (isspace(c)) {
                    state = SPACE5;
                } else if (c == '-') {
                    state = ARROW1;
                } else {
                    return -1;
                }
            }
        } else if (state == SPACE5) {
            if (!isspace(c)) {
                // transition
                last = i;
                if (c == '-') {
                    state = ARROW1;
                } else {
                    return -1;
                }
            }
        } else if (state == ARROW1) {
            // transition
            last = i;
            if (c == '>') {
                state = ARROW2;
            } else {
                return -1;
            }
        } else if (state == ARROW2) {
            // transition
            last = i;
            if (isspace(c)) {
                state = SPACE6;
            } else if (isalnum(c)) {
                state = DST_IP;
            } else {
                return -1;
            }
        } else if (state == SPACE6) {
            if (!isspace(c)) {
                // transition
                last = i;
                if (isalnum(c)) {
                    state = DST_IP;
                } else {
                    return -1;
                }
            }
        } else if (state == DST_IP) {
            if (!isalnum(c) && c != '.') {
                // parse current range
                char *s = dup_range(rule_str, last, i);
                if (parse_ip(s, &rule->dst_addr) < 0)
                    return -1;
                free(s);

                // transition
                last = i;
                if (isspace(c)) {
                    state = SPACE7;
                } else {
                    return -1;
                }
            }
        } else if (state == SPACE7) {
            if (!isspace(c)) {
                // transition
                last = i;
                if (isalnum(c) || c == ':') {
                    state = DST_PORT;
                } else {
                    return -1;
                }
            }
        } else if (state == DST_PORT) {
            if (!isalnum(c) && c != ':' && c != ',') {
                // parse current range
                char *s = dup_range(rule_str, last, i);
                if (parse_ports(s, &rule->dst_ports) < 0)
                    return -1;
                free(s);

                // transition
                last = i;
                if (isspace(c)) {
                    state = SPACE8;
                } else if (c == '(') {
                    state = OPS_START;
                } else {
                    return -1;
                }
            }
        } else if (state == SPACE8) {
            if (!isspace(c)) {
                // transition
                last = i;
                if (c == '(') {
                    state = OPS_START;
                } else {
                    return -1;
                }
            }
        } else if (state == OPS_START) {
            // transition
            last = i;
            if (isspace(c)) {
                state = SPACE9;
            } else {
                state = OPTION;
            }
        } else if (state == SPACE9) {
            if (!isspace(c)) {
                // transition
                last = i;
                if (c == ')') {
                    state = OPS_END;
                } else {
                    state = OPTION;
                }
            }
        } else if (state == OPTION) {
            if (c == ';' || c == ')') {
                // parse current range
                char *s = dup_range(rule_str, last, i);
                if (parse_option(s, &rule->options) < 0)
                    return -1;
                free(s);

                // transition
                last = i;
                if (c == ';') {
                    state = OPT_DELIM;
                } else if (c == ')') {
                    state = OPS_END;
                }
            }
        } else if (state == OPT_DELIM) {
            // transition
            last = i;
            if (isspace(c)) {
                state = SPACE9;
            } else if (c == ')') {
                state = OPS_END;
            } else {
                state = OPTION;
            }
            
        } else if (state == OPS_END) {
            if (!isspace(c))
                return -1;
        } else {
            ERR("state is invalid, val=<%d>", state);
        }
    }

    return 0;
}

int parse_action(const char *s, enum action *action) {
    ERR("ACTION \t<%s>\n", s);
    if (strcmp(s, "alert") == 0) {
        *action = ACTION_ALERT;
    } else {
        return -1;
    }
    
    return 0;
}

int parse_protocol(const char *s, enum protocol *protocol) {
    ERR("PROTO \t<%s>\n", s);

    if (strcmp(s, "tcp") == 0) {
        *protocol = PROTO_TCP;
    } else if (strcmp(s, "udp") == 0) {
        *protocol = PROTO_UDP;
    } else if (strcmp(s, "http") == 0) {
        *protocol = PROTO_HTTP;
    } else {
        return -1;
    }
    
    return 0;
}

int parse_ip(const char *s, struct ip_addr *ip) {
    ERR("IP \t<%s>\n", s);
    *ip = addr_default;

    if (strcmp(s, "any") == 0) {
        ip->any = true;
    } else {
        // duplicate s
        char *ss = malloc(strlen(s) + 1);
        strcpy(ss, s);
        
        // split on '.'
        bool invalid = true;
        char delim[] = ".";
        char *tok = strtok(ss, delim);
        for (int i = 0; tok != NULL; i++) {
            if (i == 3)
                invalid = false;
            else if (i > 3) {
                invalid = true;
                break;
            }

            errno = 0;
            ip->addr = ip->addr << 8 | (uint8_t)strtol(tok, NULL, 0);
            if (errno < 0) { // strtol returns error
                invalid = true;
                break;
            }
            tok = strtok(NULL, delim);
        }

        free(ss);
        return invalid ?-1 :0;
    }

    return 0;
}

// WARNING: doesn't check for multiple ':' in range syntax
int parse_ports(const char *s, struct ports *ports) {
    ERR("PORT \t<%s>\n", s);
    *ports = ports_default;

    // syntax: any
    if (strcmp(s, "any") == 0) {
        ports->any = true;
        return 0;
    }

    bool is_list = strchr(s, ',') != NULL;
    bool is_range = strchr(s, ':') != NULL;
    if (!is_list && !is_range) { // syntax: single port
        errno = 0;
        ports->from = ports->to = strtol(s, NULL, 0);
        if (errno < 0) { // strtol returns error
            return -1;
        }
    } else { // syntax: list or range

        // duplicate s
        char *ss = malloc(strlen(s) + 1);
        strcpy(ss, s);

        if (is_list) {
            /* Parse as list */

            char delim[] = ",";

            // count number of ports in the list
            ports->list_len = 0;
            char *tok = strtok(ss, delim);
            while (tok != NULL) {
                errno = 0;
                strtol(tok, NULL, 0);
                if (errno < 0) { // strtol returns error
                    free(ss);
                    return -1;
                }
                ports->list_len++;
                tok = strtok(NULL, delim);
            }

            // allocate list
            ports->list = malloc(sizeof(int) * ports->list_len);

            // tokenize on ',' and fill list
            strcpy(ss, s);
            ports->list_len = 0;
            tok = strtok(ss, delim);
            while (tok != NULL) {
                // no errno check for strol, already done
                ports->list[ports->list_len++] = strtol(tok, NULL, 0);
                tok = strtok(NULL, delim);
            }
        } else if (is_range) {
            /* Parse as range */

            char delim[] = ":";

            // first token => from
            char *tok = strtok(ss, delim);
            if (tok == NULL || nicer_strtol(tok, &temp_n) < 0) {
                free(ss);
                return -1;
            }
            ports->from = temp_n;

            // second token => to
            tok = strtok(NULL, delim);

            if (tok == NULL) { // no second token
                if (s[0] == ':') {
                    // if syntax is ":to"
                    // then
                    //   first token => to
                    //   from => 0
                    ports->to = ports->from;
                    ports->from = 0;
                } else {
                    ports->to = MAX_PORT_NO;
                }
            } else {
                if (nicer_strtol(tok, &temp_n) < 0) {
                    free(ss);
                    return -1;
                }
                ports->to = temp_n;
            }
        }
    }

    return 0;
}


int parse_option(const char *s, struct options *options) {
    ERR("OPTION \t<%s>\n", s);
    // duplicate s
    char *ss = malloc(strlen(s) + 1);
    strcpy(ss, s);
    
    // divide ss ("  name  :  value  ") into option name and value
    char *del_ptr = strchr(ss, ':');
    if (del_ptr == NULL) {
        free(ss);
        return -1;
    }
    *del_ptr = '\0';
    char *optname = ss;
    char *optval = ++del_ptr;
    char *optval_str; // for string values

    // strip space around option name an value
    strip_space(optname);
    strip_space(optval);

    // don't allow empty option values!
    // (empty string ("") values are allowed)
    if (*optval == '\0') {
        free(ss);
        return -1;
    }

    // remove quotes (") from string value
    // and duplicate to optval_str
    if (strcmp(optname, "msg") == 0 ||
            strcmp(optname, "http_request") == 0 ||
            strcmp(optname, "content") == 0) {
        char *end = strchr(optval, '\0');
        if (end - optval < 2 || *optval != '"' || *(end-1) != '"') {
            free(ss);
            return -1;
        }

        optval_str = malloc(end-optval - 2 + 1);
        *(end-1) = '\0';
        strcpy(optval_str, optval+1);
    }

    bool invalid = false;

    // update corresponding attribute of options
    if (strcmp(optname, "msg") == 0) {
        options->msg = optval_str;
    } else if (strcmp(optname, "tos") == 0) {
        if (nicer_strtol(optval, &temp_n) < 0)
            invalid = true;
        options->tos = temp_n;
    } else if (strcmp(optname, "len") == 0) {
        if (nicer_strtol(optval, &temp_n) < 0)
            invalid = true;
        options->len = temp_n;
    } else if (strcmp(optname, "offset") == 0) {
        if (nicer_strtol(optval, &temp_n) < 0)
            invalid = true;
        options->offset = temp_n;
    } else if (strcmp(optname, "seq") == 0) {
        if (nicer_strtoll(optval, &temp_nn) < 0)
            invalid = true;
        options->seq = temp_nn;
    } else if (strcmp(optname, "ack") == 0) {
        if (nicer_strtoll(optval, &temp_nn) < 0)
            invalid = true;
        options->ack = temp_nn;
    } else if (strcmp(optname, "flags") == 0) {
        options->flags = 0;
        int len = strlen(optval);
        for (int i = 0; i < len; i++) {
            switch (optval[i]) {
            case 'F':
                options->flags |= 1 << FLAG_FIN;
                break;
            case 'S':
                options->flags |= 1 << FLAG_SYN;
                break;
            case 'R':
                options->flags |= 1 << FLAG_RST;
                break;
            case 'P':
                options->flags |= 1 << FLAG_PSH;
                break;
            case 'A':
                options->flags |= 1 << FLAG_ACK;
                break;
            // default:
            //     invalid = false;
            //     break;
            }
        }
    } else if (strcmp(optname, "http_request") == 0) {
        options->http_request = optval_str;
    } else if (strcmp(optname, "content") == 0) {
        options->content = optval_str;
    } else {
        invalid = true;
    }

    free(ss); // frees optval and optname
    return invalid ?-1 :0;
}

