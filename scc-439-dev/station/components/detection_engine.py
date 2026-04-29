"""
SCC.439 - Individual Programming Assessment
This class provides a detection engine that, once retrieved the sniffed and then organized data (by the traffic state tracker), evaluates it to understand wheter or not
an attack is being executed (for this specific scenario, udp DoS attack, tcp-christmas, udp port scan, arp network scan)
"""

import time


class DetectionEngine:
    def __init__(self, thresholds=None, alert_cooldown=10):
        # Configuration of thresholds to trigger an alert from the NIDS
        self.thresholds = thresholds or {
            "dos_pkts_count": 100,
            "udp_scan_ports": 10,
            "arp_scan_ips": 10,
            "christmas_limit": 0
        }

        # Cooldown settings
        self.alert_cooldown = alert_cooldown  # Seconds to wait before re-alerting, set by default to 10 seconds

        # Dictionary to store the last time the NIDS alerted for a specific key
        # Structure: { ("AttackType", "TargetIP"): timestamp }
        self.last_alert_times = {}

    def evaluate(self, tracker):
        alerts = []
        current_time = time.time()

        # 1. DETECT GENERAL DOS
        for target_ip, count in tracker.pkts_count.items():
            if count > self.thresholds.get("dos_pkts_count", 100):
                self._try_add_alert(
                    alerts,
                    "DoS Attack Detected",
                    target_ip,
                    f"High volume: {count} pkts",
                    current_time
                )

        # 2. DETECT TCP CHRISTMAS TREE
        for src_ip, count in tracker.christmas_flags_sources.items():
            if count > self.thresholds.get("christmas_limit", 0):
                self._try_add_alert(
                    alerts,
                    "TCP Christmas Detected",
                    src_ip,
                    f"Sent {count} Xmas pkts",
                    current_time
                )

        # 3. DETECT UDP PORT SCANS
        for src_ip, targets in tracker.udp_ports_accessed.items():
            for dst_ip, ports in targets.items():
                # Config to have always a default threshold
                if len(ports) > self.thresholds.get("udp_scan_ports", 10):
                    # Key can be complex to isolate specific scan pairs
                    self._try_add_alert(
                        alerts,
                        "UDP Port Scan Detected",
                        src_ip,
                        f"Scanned {len(ports)} ports on {dst_ip}",
                        current_time,
                        unique_id=f"{src_ip}->{dst_ip}" # Unique key for this specific scan pair
                    )

        # 4. DETECT ARP SCANS
        for src_mac, requested_ips in tracker.arp_queries.items():
            # Config to have always a default threshold
            if len(requested_ips) > self.thresholds.get("arp_scan_ips", 10):
                self._try_add_alert(
                    alerts,
                    "ARP Scan Detected",
                    src_mac,
                    f"Queried {len(requested_ips)} unique IPs",
                    current_time
                )

        return alerts

    """
        Only adds an alert if enough time has passed since the last one for this target.
    """
    def _try_add_alert(self, alerts_list, attack_type, source, info, timestamp, unique_id=None):
        # Create a unique key for this specific alert scenario
        # If unique_id is not provided, use the source/target as the ID
        identifier = unique_id if unique_id else source
        alert_key = (attack_type, identifier)

        last_time = self.last_alert_times.get(alert_key, 0)

        # CHECK: Has enough time passed?
        if (timestamp - last_time) > self.alert_cooldown:
            # Yes: Generate alert and update the timestamp
            alert = {
                "type": attack_type,
                "source/target": source,
                "info": info,
                "timestamp": timestamp
            }
            alerts_list.append(alert)
            self.last_alert_times[alert_key] = timestamp

        # No: Do nothing (suppress alert)