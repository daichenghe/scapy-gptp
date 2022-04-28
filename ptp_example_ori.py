#!/usr/bin/env python
# encoding: utf-8

from gptp.layers import PTPv2
from gptp.utils import MatchedList
from scapy.utils import rdpcap

pcap = rdpcap("example/test.pcapng")

# Create a MatchedList, which will match tuples of (Sync, FollowUp)
# and (PdelayReq, PdelayResp, PdelayRespFollowUp)
matched_list = MatchedList([p for p in pcap if p.haslayer('PTPv2')])

# Show the first tuple
(sync, fup) = matched_list.sync[0]

sync.show()
fup.show()

packet_test = []

for p in pcap:
    if (p.haslayer('PTPv2')) == True:
        packet_test.append(p)
matched_list = MatchedList(packet_test)
print(len(matched_list.sync))
(sync, fup) = matched_list.sync[0]
sync.show()
fup.show()

