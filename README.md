# Building and testing

To build and start packet capture:

    # Build project
    make

    # Run executable with rules file to
    # start capturing and rule matching
    sudo ./bin/nids rules/udp_godzilla.txt

Use Scapy scripts inside `scapy/` to send packets:

    sudo python scapy/scapy_godzilla.py

# Hole Patching Algorithm for IP fragment reassembly

See: https://tools.ietf.org/html/rfc815  
It's simple and very efficient -- O(n);

# Project structure

All the source codes are inside `src` directory:

    - bin/
        - nids
    - src/
        - assemble_ip.h         : IP fragment reassembly
        - capture.h             : Capturing IP packets via libpcap
        - colors.h               : Terminal output colors
        - helpers.h             : Generic helper functions
        - hole_list.h           : Linked-list implementation for list of holes
        - main.c                : 
        - match.h               : Matching captured packages to Snort rules
        - proto_headers.h       : IP, TCP, and UDP headers
        - rules.h               : Snort rule parsing
    - rules/
        ...
    - scapy/
        ...
    - Makefile
    - README.md

# Parsing Snort Rules

Superficial DFA (Deterministic Finite Automata) parsing is done first to
break rule into specific parts, like action, ip address, port, option, etc.

Then less formal parsing is done via basic string manipulations.

# Acknowledgements

Some libpcap code is modified from Tim Carstens' [Programming with pcap](https://www.tcpdump.org/pcap.html).

