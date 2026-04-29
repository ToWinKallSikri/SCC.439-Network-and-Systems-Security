"""
In this file all the components are put together - this is the core of the NIDS client agent that communicates alerts
to SIEM server through secure channel (Mutual CHAP - encryption - HMAC auth)
"""

# Importing components (classes) of the NIDS
from components.traffic_tracker import TrafficStateTracker
from components.sniffer import PacketSniffer
from components.detection_engine import DetectionEngine
from components.communication_channel import SecureChannel

if __name__ == "__main__":
    # Setting up a secure channel of communication between the NIDS and the SIEM
    channel = SecureChannel()
    # Setting up a tracker object
    tracker = TrafficStateTracker()
    # Setting up a detection engine
    detector = DetectionEngine()
    # The sniffer is injected with the different objects
    sniffer = PacketSniffer(tracker, detector, channel)
    # Note: in dev container, interface might be "eth0" or "lo" (loopback) depending on test
    nwiface = input("Insert network interface to monitor:")
    # Sniffer starts on the selected NW interface - during the test with the "tester" eth0 has been used - test script attacks on 172.20.0.2:9999
    sniffer.start(iface=nwiface)







