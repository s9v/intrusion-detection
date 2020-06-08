"""
    Sends fragmented IP datagrams in random order.
"""
from scapy.all import *
import random

group_id = 7161
das_kapital = 'We started with the supposition that labour-power is bought and sold at its value. Its value, like that of all other commodities, is determined by the working-time necessary to its production. If the production of the average daily means of subsistence of the labourer takes up 6 hours, he must work, on the average, 6 hours every day, to produce his daily labour-power, or to reproduce the value received as the result of its sale. The necessary part of his working-day amounts to 6 hours, and is, therefore, caeteris paribus [other things being equal], a given quantity. But with this, the extent of the working-day itself is not yet given.'
pkt = IP(dst="123.45.67.89", id=group_id)/UDP(sport=420, dport=69)/das_kapital
frags = pkt.fragment(8)
random.shuffle(frags)

send(frags)
