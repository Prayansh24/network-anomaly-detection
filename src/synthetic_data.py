"""
Synthetic Data Generation Module for SentinelNet.
Produces realistic, deterministic network traffic metadata representing normal operations
and cybersecurity attack patterns (Port Scans, Traffic Spikes, SYN Floods, Repeated Connections).
"""

import datetime
from pathlib import Path
import random
from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd

from src.utils import get_project_root, setup_logger

logger = setup_logger("synthetic_data")


class SyntheticTrafficGenerator:
    """
    Deterministic generator of synthetic network packet metadata.
    Designed for university demonstration, testing, and offline evaluation.
    Clearly labeled as simulated data.
    """

    def __init__(self, seed: int = 42):
        self.seed = seed
        self._set_seed(seed)

        # Standard network IP baselines
        self.internal_ips = [
            "192.168.1.10",
            "192.168.1.15",
            "192.168.1.20",
            "192.168.1.25",
            "192.168.1.30",
        ]
        self.gateway_ip = "192.168.1.1"
        self.dns_servers = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]
        self.web_servers = ["93.184.216.34", "151.101.1.69", "142.250.190.46", "104.244.42.1"]
        self.internal_server = "192.168.1.100"  # Target server (e.g. local intranet / DB)

        # Attackers
        self.external_attacker = "203.0.113.88"
        self.compromised_host = "192.168.1.45"

    def _set_seed(self, seed: int) -> None:
        random.seed(seed)
        np.random.seed(seed)

    def generate_normal_browsing(
        self, start_time: float, count: int = 350
    ) -> List[Dict]:
        """Simulate typical web browsing traffic (HTTP/HTTPS, realistic packet sizes & flags)."""
        packets = []
        current_time = start_time

        for _ in range(count):
            current_time += random.uniform(0.01, 0.25)
            src = random.choice(self.internal_ips)
            dst = random.choice(self.web_servers)
            sport = random.randint(49152, 65535)
            dport = random.choice([80, 443])

            # Realistic TCP handshake or payload transfer
            stage = random.choice(["SYN", "ACK", "PSH-ACK", "ACK", "FIN-ACK"])
            if stage == "SYN":
                size = random.choice([52, 60, 64])
                flags = "SYN"
            elif stage in ["ACK", "FIN-ACK"]:
                size = random.choice([52, 60, 64])
                flags = stage
            else:  # PSH-ACK (HTTP payload)
                size = random.randint(300, 1460)
                flags = "PSH, ACK"

            packets.append({
                "timestamp": current_time,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": sport,
                "dst_port": dport,
                "protocol": "TCP",
                "packet_size": size,
                "tcp_flags": flags,
                "is_anomaly": 0,
                "attack_type": "Normal (Web Browsing)",
            })
        return packets

    def generate_normal_dns(self, start_time: float, count: int = 120) -> List[Dict]:
        """Simulate DNS resolution lookups (UDP, port 53)."""
        packets = []
        current_time = start_time

        for _ in range(count):
            current_time += random.uniform(0.1, 0.8)
            src = random.choice(self.internal_ips)
            dst = random.choice(self.dns_servers)
            sport = random.randint(49152, 65535)
            size = random.randint(60, 150)

            packets.append({
                "timestamp": current_time,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": sport,
                "dst_port": 53,
                "protocol": "UDP",
                "packet_size": size,
                "tcp_flags": "N/A",
                "is_anomaly": 0,
                "attack_type": "Normal (DNS)",
            })
        return packets

    def generate_port_scan(
        self, start_time: float, target_ip: Optional[str] = None, num_ports: int = 80
    ) -> List[Dict]:
        """Simulate a reconnaissance SYN port scan from an attacker IP."""
        if target_ip is None:
            target_ip = self.internal_server
        attacker = self.external_attacker

        packets = []
        current_time = start_time
        scanned_ports = sorted(random.sample(range(1, 1024), num_ports))

        for port in scanned_ports:
            # Rapid scanning intervals
            current_time += random.uniform(0.005, 0.02)
            packets.append({
                "timestamp": current_time,
                "src_ip": attacker,
                "dst_ip": target_ip,
                "src_port": random.randint(50000, 60000),
                "dst_port": port,
                "protocol": "TCP",
                "packet_size": random.choice([44, 60]),
                "tcp_flags": "SYN",
                "is_anomaly": 1,
                "attack_type": "Port Scan",
            })
        return packets

    def generate_traffic_spike_dos(
        self, start_time: float, target_ip: Optional[str] = None, num_packets: int = 150
    ) -> List[Dict]:
        """Simulate a sudden high-rate volumetric traffic surge / DoS attempt."""
        if target_ip is None:
            target_ip = self.internal_server
        attacker = "198.51.100.42"

        packets = []
        current_time = start_time

        for _ in range(num_packets):
            # Extremely tight intervals (burst of traffic)
            current_time += random.uniform(0.001, 0.004)
            packets.append({
                "timestamp": current_time,
                "src_ip": attacker,
                "dst_ip": target_ip,
                "src_port": random.randint(40000, 65000),
                "dst_port": 80,
                "protocol": "TCP",
                "packet_size": random.randint(1200, 1500),
                "tcp_flags": "ACK",
                "is_anomaly": 1,
                "attack_type": "Traffic Spike / DoS",
            })
        return packets

    def generate_syn_flood(
        self, start_time: float, target_ip: Optional[str] = None, count: int = 100
    ) -> List[Dict]:
        """Simulate a TCP SYN flood against a critical server port."""
        if target_ip is None:
            target_ip = self.internal_server
        attacker = "203.0.113.199"

        packets = []
        current_time = start_time

        for _ in range(count):
            current_time += random.uniform(0.002, 0.008)
            packets.append({
                "timestamp": current_time,
                "src_ip": attacker,
                "dst_ip": target_ip,
                "src_port": random.randint(30000, 65000),
                "dst_port": 443,
                "protocol": "TCP",
                "packet_size": random.choice([52, 60]),
                "tcp_flags": "SYN",
                "is_anomaly": 1,
                "attack_type": "SYN Flood",
            })
        return packets

    def generate_repeated_connection_attempts(
        self, start_time: float, target_ip: Optional[str] = None, attempts: int = 50
    ) -> List[Dict]:
        """Simulate repeated connection attempts / password guessing / service polling."""
        if target_ip is None:
            target_ip = self.internal_server
        source = self.compromised_host

        packets = []
        current_time = start_time

        for _ in range(attempts):
            current_time += random.uniform(0.05, 0.15)
            # Repeatedly targeting SSH or Telnet or SQL port
            packets.append({
                "timestamp": current_time,
                "src_ip": source,
                "dst_ip": target_ip,
                "src_port": random.randint(49152, 65535),
                "dst_port": 22,
                "protocol": "TCP",
                "packet_size": random.randint(70, 110),
                "tcp_flags": "SYN",
                "is_anomaly": 1,
                "attack_type": "Repeated Connections / Brute Force",
            })
        return packets

    def generate_complete_dataset(self, total_duration_sec: float = 60.0) -> pd.DataFrame:
        """
        Assemble a combined synthetic dataset containing normal network operations
        interleaved with realistic attack patterns.
        
        Returns:
            Pandas DataFrame sorted chronologically by timestamp.
        """
        self._set_seed(self.seed)
        base_timestamp = 1700000000.0  # Deterministic reference epoch

        all_packets: List[Dict] = []

        # 1. Normal background browsing & DNS
        all_packets.extend(self.generate_normal_browsing(base_timestamp, count=400))
        all_packets.extend(self.generate_normal_dns(base_timestamp + 2.0, count=150))

        # 2. Port Scan attack occurring at T+15s
        all_packets.extend(self.generate_port_scan(base_timestamp + 15.0, num_ports=75))

        # 3. Interleaved normal traffic continuing
        all_packets.extend(self.generate_normal_browsing(base_timestamp + 18.0, count=250))

        # 4. Traffic Spike / DoS occurring at T+30s
        all_packets.extend(self.generate_traffic_spike_dos(base_timestamp + 30.0, num_packets=120))

        # 5. SYN Flood attack occurring at T+42s
        all_packets.extend(self.generate_syn_flood(base_timestamp + 42.0, count=85))

        # 6. Repeated connection attempt / brute force at T+50s
        all_packets.extend(self.generate_repeated_connection_attempts(base_timestamp + 50.0, attempts=40))

        # Sort chronologically by timestamp
        df = pd.DataFrame(all_packets)
        df = df.sort_values(by="timestamp").reset_index(drop=True)

        # Convert timestamp to human-readable ISO string for presentation
        # while keeping unix timestamp for calculations
        df["datetime"] = pd.to_datetime(df["timestamp"], unit="s").dt.strftime("%Y-%m-%d %H:%M:%S.%f").str[:-3]

        logger.info(
            f"Generated synthetic dataset with {len(df)} records "
            f"({df['is_anomaly'].sum()} anomalies, {len(df) - df['is_anomaly'].sum()} normal)."
        )
        return df

    def save_sample_csv(self, output_path: Optional[str] = None) -> Path:
        """Generate and save the synthetic sample dataset to a CSV file."""
        if output_path is None:
            dest = get_project_root() / "data" / "sample_traffic.csv"
        else:
            dest = Path(output_path)
            if not dest.is_absolute():
                dest = get_project_root() / dest

        dest.parent.mkdir(parents=True, exist_ok=True)
        df = self.generate_complete_dataset()
        df.to_csv(dest, index=False)
        logger.info(f"Sample synthetic dataset saved to {dest}")
        return dest
