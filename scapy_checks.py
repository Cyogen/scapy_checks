#!/usr/bin/env python3
from scapy.all import rdpcap, TCP, IP, UDP
import sys
pcap=sys.argv[1]
pkts=rdpcap(pcap)

# 1. Find hosts that send many tiny TCP payloads (possible beacon)
count={}
for p in pkts:
    if IP in p and TCP in p:
        key=(p[IP].src, p[TCP].dport)
        payload_len=len(bytes(p[TCP].payload))
        if payload_len < 50:
            count[key]=count.get(key,0)+1
top=[(k,v) for k,v in count.items() if v>10]
print("Suspect small payload flows (>10 small pkts):")
for k,v in sorted(top, key=lambda x: -x[1])[:50]:
    print(k,v)

# 2. Find DNS qnames with long labels
from scapy.layers.dns import DNSQR
long=[]
for p in pkts:
    if UDP in p and p[UDP].dport==53 and p.haslayer(DNSQR):
        q=p[DNSQR].qname.decode() if isinstance(p[DNSQR].qname, bytes) else p[DNSQR].qname
        if len(q)>80:
            long.append(q)
print("\nLong DNS queries (>80 chars):")
for q in set(long):
    print(q)
