from scapy.all import *

ip = IP(dst="222.222.222.222")
udp = UDP(sport=18, dport=69)
raw = "aaaaaaa godzilla a aaaaaaa"

pkt = ip/udp/raw
send(pkt)
