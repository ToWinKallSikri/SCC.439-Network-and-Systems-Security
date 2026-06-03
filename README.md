# SCC.439-Network-and-Systems-Security

## SCC.439 NIDS project 

NIDS client (nids.py) and SIEM server (siem_server.py) with mutual CHAP auth and secure PDUs. New components include traffic tracker, packet sniffer, detection engine, communication channel (AES/HMAC/CRC, timestamp/CRC checks), PDU utilities (chap_pdu), and secure operations (secure_ops). Adds secure logging and verifier (secure_logger), a check_logs script, example siem_alerts.log, devcontainer/compose and VSCode configs, tester attack scripts, and documentation/diagram assets.

The NIDS needs to be upgraded with dynamic window thresholds (or ML strategies) to detect attacks, the Diffie-Hellman key exchange mechanism must be implemented and the AES-ECB needs to be changed to a more robust
mode.
## SCC.439 Whitepaper

White paper on maritime sector, from a network security point of view, integrating Cyber Informed Engineering concepts.
