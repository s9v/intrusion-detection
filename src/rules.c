#include "rules.h"
#include "color.h"
#include <stdio.h>

void test_color(void) {
    printf("testing color "KRED"red"KRST" and "KGRN"green"KRST" ...\n");
    printf("\n\n");
    printf("testing multiline "KRED"should be red\n"
           "still red?\n"
           "still red?\n"KRST
           "shouldnt be red\n");
}

void debug_rule(struct rule rule) {
    ERR("action <id=%d>\n", rule.action);
    ERR("protocol <id=%d>\n", rule.protocol);

    ERR("src_addr <any=%d  addr=%08X>\n", rule.src_addr.any, rule.src_addr.addr);
    ERR("dst_addr <any=%d  addr=%08X>\n", rule.dst_addr.any, rule.dst_addr.addr);

    struct ports ports;
    ports = rule.src_ports;
    ERR("src_ports <any=%d  from=%d  to=%d  [%d](",
        ports.any, ports.from, ports.to, ports.list_len);
    if (ports.list != NULL)
    for (int i = 0; i < ports.list_len; i++) {
        ERR("%d", ports.list[i]);
        if (i != ports.list_len - 1)
            ERR(", ");
    }
    ERR(")>\n");

    ports = rule.dst_ports;
    ERR("dst_ports <any=%d  from=%d  to=%d  [%d](",
        ports.any, ports.from, ports.to, ports.list_len);
    if (ports.list != NULL)
    for (int i = 0; i < ports.list_len; i++) {
        ERR("%d", ports.list[i]);
        if (i != ports.list_len - 1)
            ERR(", ");
    }
    ERR(")>\n");

    struct options options = rule.options;

    ERR("options <\n");
    if (options.msg == NULL)
        ERR("  msg=NULL\n");
    else
        ERR("  msg=\"%s\"\n", options.msg);
    ERR("  tos=%d\n", options.tos);
    ERR("  len=%d\n", options.len);
    ERR("  offset=%d\n", options.offset);
    ERR("  seq=%d\n", options.seq);
    ERR("  ack=%d\n", options.ack);
    ERR("  flags=0x%X\n", options.flags);
    if (options.http_request == NULL)
        ERR("  http_request=NULL\n");
    else
        ERR("  http_request=\"%s\"\n", options.http_request);
    if (options.content == NULL)
        ERR("  content=NULL\n");
    else
        ERR("  content=\"%s\"\n", options.content);
    ERR(">\n");
}

void test_rule_parsing(void) {
    char test_strs[][1024] = {
        // 0
        "alert tcp 1.1.1.1 any -> 8.8.8.8 any (msg:\"expect world war 3\";)",
        // 1
        "alert udp any any->any any(msg:\"expect world war 3\";)",
        // 2
        "alert udp any 23,80,8000->any 8000:8888"
            "(msg:\"expect world war 3\";len:100;ack:45)",
        // 3
        "alert udp any 23,80,8000 -> any 8000:8888 "
            "( msg:\"expect world war 3\"; len:100; ack:45 )",
        // 4
        "    alert     udp        192.0.2.235     23,80,8000    ->\n"
            "   any   8000:8888     ("
            "       msg  : \"expect world war 3\" \n\t  ;\n"
            "       \tlen  :  100             ;   \n"
            "       ack  :  45              ; \n"
            "   )     ",
        // 5
        "alert tcp 192.168.1.1 any -> 192.168.1.2 22"
            " (content:\"/bin/sh\";msg:\"Remote shell execution message!\";)",
        // 6
        "alert tcp any any -> 143.248.5.153 80"
            " (msg:\"A packet destined to www.kaist.ac.kr\";)",
        // 7
        "alert udp any any -> 192.168.1.1 1:1024 "
            "(msg:\"udp traffic from any port and"
            " destination ports ranging from 1 to 1024\";)",
        // 8
        "alert tcp any any -> 192.168.1.1 :6000 "
            "(msg:\"tcp traffic from any port going to ports"
            " less than or equal to 6000\";)",
        // 9
        "alert tcp any :1024 -> 192.168.1.1 500: "
            "(msg:\"tcp traffic from privileged ports less than or "
            "equal to 1024 going to ports greater than or equal to 500:\";)",
        // 10
        "alert tcp any any -> any 80,22,21 "
            "(msg: \"tcp traffic from any port going to Web, FTP, "
            "and SSH server ports\";)"
    };

    for (int i = 0; i <= 10; i++) {
        printf("// %d\n%s\n", i, test_strs[i]);
    }
    ERR("===============================\n");

    char *rule_str = test_strs[5];
    
    ERR("rule str:\n  <%s>\n", rule_str);

    struct rule rule;
    ERR("===============================\n");
    if (parse_rule(rule_str, &rule) < 0) {
        ERR("[==ERROR==] parse_rule: invalid rule given\n");
    }
    ERR("===============================\n");

    debug_rule(rule);
}

int main(void) {
    test_rule_parsing();

    return 0;
}
