"""
Rule-Based Detection Engine for SentinelNet.
Implements transparent, deterministic security heuristics for identifying specific network attack patterns:
Port Scanning, Volumetric Traffic Spikes, SYN Floods, Repeated Connections, and Destination Sweeping.
"""

from typing import Any, Dict, List, Optional
import pandas as pd

from src.utils import load_config, setup_logger

logger = setup_logger("rule_engine")


class RuleBasedDetectionEngine:
    """
    Evaluates network traffic records against deterministic cybersecurity heuristics.
    Produces structured, deduplicated security alerts with clear explanations and defensive recommendations.
    """

    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        if config_dict is None:
            full_cfg = load_config()
            self.rules_cfg = full_cfg.get("rules", {})
        else:
            self.rules_cfg = config_dict

        # Rule parameters
        ps_cfg = self.rules_cfg.get("port_scan", {})
        self.port_scan_min_ports = ps_cfg.get("min_unique_ports", 10)
        self.port_scan_severity = ps_cfg.get("severity", "High")

        ts_cfg = self.rules_cfg.get("traffic_spike", {})
        self.spike_pkt_rate = ts_cfg.get("packet_rate_threshold", 40.0)
        self.spike_byte_rate = ts_cfg.get("byte_rate_threshold", 50000.0)
        self.spike_severity = ts_cfg.get("severity", "Medium")

        syn_cfg = self.rules_cfg.get("syn_flood", {})
        self.syn_min_pkts = syn_cfg.get("min_syn_packets", 15)
        self.syn_ratio_thresh = syn_cfg.get("syn_ratio_threshold", 0.70)
        self.syn_severity = syn_cfg.get("severity", "Critical")

        rep_cfg = self.rules_cfg.get("repeated_connections", {})
        self.rep_min_attempts = rep_cfg.get("min_attempts_to_same_dest", 20)
        self.rep_severity = rep_cfg.get("severity", "Medium")

        dst_cfg = self.rules_cfg.get("unusual_destinations", {})
        self.dst_min_ips = dst_cfg.get("min_unique_dst_ips", 15)
        self.dst_severity = dst_cfg.get("severity", "High")

    def evaluate_traffic(self, df_with_features: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Evaluate traffic dataset and generate deduplicated security alerts.
        
        Args:
            df_with_features: DataFrame containing windowed and packet-level features.
            
        Returns:
            List of unique security alert dictionaries.
        """
        if df_with_features.empty:
            return []

        alerts: List[Dict[str, Any]] = []
        # Key for deduplication: (rule_name, src_ip, time_window)
        seen_alerts = set()

        # Iterate over records or grouped windows
        for _, row in df_with_features.iterrows():
            src_ip = str(row.get("src_ip", "Unknown"))
            dst_ip = str(row.get("dst_ip", "Unknown"))
            time_window = row.get("time_window", 0)
            timestamp = str(row.get("datetime", row.get("timestamp", "N/A")))

            # 1. Port Scan Detection Rule
            unique_ports = row.get("unique_dst_ports", 0)
            if unique_ports >= self.port_scan_min_ports:
                alert_key = ("Port Scan", src_ip, time_window)
                if alert_key not in seen_alerts:
                    seen_alerts.add(alert_key)
                    alerts.append({
                        "timestamp": timestamp,
                        "alert_type": "Port Scan Detected",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "severity": self.port_scan_severity,
                        "detection_method": "Rule-Based",
                        "anomaly_score": None,
                        "explanation": (
                            f"Host {src_ip} initiated connections to {unique_ports} distinct "
                            f"destination ports within a 10s window (threshold: {self.port_scan_min_ports})."
                        ),
                        "recommended_action": (
                            "Verify if source IP is an authorized vulnerability scanner or host. "
                            "Inspect endpoint processes for scanning utilities (e.g. Nmap) and block at perimeter."
                        ),
                        "acknowledged": False,
                    })

            # 2. Traffic Spike Rule
            pkt_rate = row.get("packet_rate", 0.0)
            byte_rate = row.get("byte_rate", 0.0)
            if pkt_rate >= self.spike_pkt_rate or byte_rate >= self.spike_byte_rate:
                alert_key = ("Traffic Spike", src_ip, time_window)
                if alert_key not in seen_alerts:
                    seen_alerts.add(alert_key)
                    alerts.append({
                        "timestamp": timestamp,
                        "alert_type": "Volumetric Traffic Spike",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "severity": self.spike_severity,
                        "detection_method": "Rule-Based",
                        "anomaly_score": None,
                        "explanation": (
                            f"Sudden traffic surge from {src_ip}: {pkt_rate:.1f} packets/sec and "
                            f"{byte_rate:.0f} bytes/sec exceeding rate thresholds."
                        ),
                        "recommended_action": (
                            "Check for volumetric denial of service or large unauthorized data transfer/backup. "
                            "Apply rate-limiting if unapproved."
                        ),
                        "acknowledged": False,
                    })

            # 3. SYN Flood / Heavy SYN Activity Rule
            syn_count = row.get("syn_flag_count", 0)
            syn_ratio = row.get("syn_ratio", 0.0)
            if syn_count >= self.syn_min_pkts and syn_ratio >= self.syn_ratio_thresh:
                alert_key = ("SYN Flood", src_ip, time_window)
                if alert_key not in seen_alerts:
                    seen_alerts.add(alert_key)
                    alerts.append({
                        "timestamp": timestamp,
                        "alert_type": "TCP SYN Flood Indicator",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "severity": self.syn_severity,
                        "detection_method": "Rule-Based",
                        "anomaly_score": None,
                        "explanation": (
                            f"High ratio of TCP SYN requests from {src_ip}: {syn_count} SYN packets "
                            f"constituting {syn_ratio*100:.1f}% of observed traffic in window."
                        ),
                        "recommended_action": (
                            "Activate TCP SYN cookies on target host/firewall. "
                            "Verify host connection states and drop half-open connections."
                        ),
                        "acknowledged": False,
                    })

            # 4. Repeated Connection Attempts Rule
            same_dest = row.get("same_dest_attempts", 0)
            if same_dest >= self.rep_min_attempts:
                alert_key = ("Repeated Connections", src_ip, dst_ip, time_window)
                if alert_key not in seen_alerts:
                    seen_alerts.add(alert_key)
                    alerts.append({
                        "timestamp": timestamp,
                        "alert_type": "Repeated Connection Attempts",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "severity": self.rep_severity,
                        "detection_method": "Rule-Based",
                        "anomaly_score": None,
                        "explanation": (
                            f"Host {src_ip} made {same_dest} repetitive connection attempts "
                            f"to target {dst_ip} within the same window."
                        ),
                        "recommended_action": (
                            "Check server authentication logs for credential brute-forcing, "
                            "C2 beaconing, or broken application retry loops."
                        ),
                        "acknowledged": False,
                    })

            # 5. Unusual Destination Activity (Destination sweep)
            unique_ips = row.get("unique_dst_ips", 0)
            if unique_ips >= self.dst_min_ips:
                alert_key = ("Destination Sweep", src_ip, time_window)
                if alert_key not in seen_alerts:
                    seen_alerts.add(alert_key)
                    alerts.append({
                        "timestamp": timestamp,
                        "alert_type": "Unusual Destination Sweep",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "severity": self.dst_severity,
                        "detection_method": "Rule-Based",
                        "anomaly_score": None,
                        "explanation": (
                            f"Single host {src_ip} established contact with {unique_ips} "
                            f"different destination IP addresses in short window."
                        ),
                        "recommended_action": (
                            "Investigate potential worm-like lateral movement or peer-to-peer / botnet discovery."
                        ),
                        "acknowledged": False,
                    })

        logger.info(f"Rule engine evaluated {len(df_with_features)} records and generated {len(alerts)} alerts.")
        return alerts
