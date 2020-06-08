from scapy.all import *

p = IP(dst='123.45.67.89')/TCP()/("GET / HTTP/1.0\r\n\r\n")

send(p)
