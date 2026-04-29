"""
SCC.439 - Individual Programming Assessment
This class is used to keep track of the network traffic, organizing it and putting it together in useful data structures.
These data structures are continuosly monitored in order to trigger the NIDS' Detection Engine that will send alerts to the SIEM server through the secure channel
"""

from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
import time

class TrafficStateTracker:
    def __init__(self):
        # Initialize dictionary for packet counting (useful for DoS)
        self.pkts_count = defaultdict(int)

        # TCP Scan Tracking
        # Tracks IPs sending Christmas Tree packets (Flags: FIN, PSH, URG)
        self.christmas_flags_sources = defaultdict(int)

        # UDP Scan Tracking
        # Structure: {source_ip: {target_ip: set(ports)}}
        self.udp_ports_accessed = defaultdict(lambda: defaultdict(set))

        # ARP Scan Tracking
        # Structure: {source_mac: set(queried_ips)}
        self.arp_queries = defaultdict(set)

        self.start_time = time.time()

    def update(self, pkt):
        # 1. Handle IP Traffic (TCP/UDP)
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            self.pkts_count[dst] += 1

            # UDP Detection Logic (for Port Scans)
            if UDP in pkt:
                # Track unique ports accessed by src -> dst
                self.udp_ports_accessed[src][dst].add(pkt[UDP].dport)

            # TCP Detection Logic (for Christmas Tree Scans)
            if TCP in pkt:
                # Check for "FPU" flags (FIN, PSH, URG)
                # Scapy flags are 0x29 (1=FIN + 8=PSH + 32=URG)
                if pkt[TCP].flags == 0x29 or pkt[TCP].flags == 'FPU':
                    self.christmas_flags_sources[src] += 1

        # 2. Handle ARP Traffic (for ARP Scans)
        if ARP in pkt and pkt[ARP].op == 1:  # op=1 is 'who-has' (request)
            src_mac = pkt[ARP].hwsrc
            target_ip_query = pkt[ARP].pdst
            self.arp_queries[src_mac].add(target_ip_query)

    def get_stats(self):
        # Return a snapshot of all trackers
        return {
            "pkts_count": dict(self.pkts_count),
            "christmas_sources": dict(self.christmas_flags_sources),
            "udp_access": {k: {tk: list(tv) for tk, tv in v.items()} for k, v in self.udp_ports_accessed.items()},
            "arp_queries": {k: list(v) for k, v in self.arp_queries.items()}
        }