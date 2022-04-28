#!/usr/bin/env python
# encoding: utf-8

from gptp.layers import PTPv2
from gptp.utils import MatchedList
from scapy.utils import rdpcap
from scapy.all import Ether, UDP
'''
#pcap = rdpcap("example/ptp_example.pcapng")
pcap = rdpcap("example/test.pcapng")
for p in pcap:
    print(p.haslayer)
    input('')

# Create a MatchedList, which will match tuples of (Sync, FollowUp)
# and (PdelayReq, PdelayResp, PdelayRespFollowUp)
matched_list = MatchedList([p for p in pcap if p.haslayer('PTPv2')])

# Show the first tuple
(sync, fup) = matched_list.sync[0]

sync.show()
fup.show()
'''
from scapy.all import *
from scapy.all import sendp, conf, AsyncSniffer

packet_all = []

SYNC_MESSAGE_TRACE = [
    0x10,                                                        # transport specific + message type
    0x02,                                                        # reserved(0) + PTP version
    0x00, 0x2C,                                                  # message length
    0x00,                                                        # domain number
    0x42,                                                        # reserved(1)
    0x02, 0x08,                                                  # flags
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,              # correction field
    0x12, 0x34, 0x56, 0x78,                                      # reserved(2)
    0x66, 0x55, 0x44, 0xFF, 0xFE, 0x33, 0x22, 0x11, 0x00, 0x01,  # source port id
    0x01, 0xD4,                                                  # sequence id
    0x00,                                                        # control
    0xFE,                                                        # logMessageInterval
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # reserved
]

data = Raw(bytes(SYNC_MESSAGE_TRACE))
print('type=', type(data),SYNC_MESSAGE_TRACE)
arp_req_pkt = Ether(dst="FF:FF:FF:FF:FF:FF", type=0x88f7)/data
print(arp_req_pkt)
arp_rsp_pkt = sendp(arp_req_pkt, iface = '以太网')

def handle_recive_packet(packet):
    #print(packet)
    #(sync, fup) = packet.sync[0]
    global packet_all
    if (packet.haslayer('PTPv2')) == True:
        packet_all.append(packet)
    if len(packet_all) >= 6:
        matched_list = MatchedList(packet_all)
        (sync, fup) = matched_list.sync[0]
        sync.show()
        fup.show()
        packet_all = []

    
while True:
    async_sniffer = AsyncSniffer(
        iface='以太网',
        prn=handle_recive_packet
        )
    async_sniffer.start()
    while True:
        pass
