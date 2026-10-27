"""
Live Network Packet Capture Module for SentinelNet.
Captures packet metadata safely using Scapy in a background thread.
Does NOT inspect or store sensitive payload contents.
Gracefully handles missing Npcap or elevated privileges on Windows.
"""

import datetime
from queue import Empty, Queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import pandas as pd

from src.utils import protocol_name, setup_logger

logger = setup_logger("capture")


class NetworkCaptureManager:
    """
    Manages live packet sniffing using Scapy in an asynchronous background thread.
    Collects only high-level packet headers and timing metadata.
    """

    def __init__(self):
        self.is_capturing = False
        self.stop_requested = threading.Event()
        self.capture_thread: Optional[threading.Thread] = None
        self.captured_packets: List[Dict[str, Any]] = []
        self.packet_queue: Queue = Queue()
        self.error_message: Optional[str] = None
        self.packets_captured_count = 0

    @staticmethod
    def get_available_interfaces() -> List[Dict[str, str]]:
        """
        List available network interfaces on the host system.
        Returns a list of dicts with 'name' and 'description'.
        """
        interfaces: List[Dict[str, str]] = []
        try:
            from scapy.all import get_if_list
            raw_list = get_if_list()

            # Attempt to get friendly Windows names if available
            try:
                from scapy.arch.windows import get_windows_if_list
                win_list = get_windows_if_list()
                for item in win_list:
                    interfaces.append({
                        "id": item.get("name", ""),
                        "name": item.get("description", item.get("name", "Ethernet")),
                        "ip": item.get("ips", [""])[0] if item.get("ips") else "",
                    })
            except Exception:
                # Standard interface list fallback
                for iface in raw_list:
                    interfaces.append({"id": str(iface), "name": str(iface), "ip": ""})

        except Exception as e:
            logger.warning(f"Could not enumerate interfaces: {e}")

        # Always include a loopback / default fallback entry
        if not interfaces:
            interfaces = [{"id": "default", "name": "Default Network Interface", "ip": "127.0.0.1"}]

        return interfaces

    @staticmethod
    def check_capture_prerequisites() -> Tuple[bool, str]:
        """
        Check whether packet sniffing is supported on the current environment.
        On Windows, Scapy requires Npcap/WinPcap with appropriate rights.
        """
        try:
            import scapy.all as scapy_all
            # Check if conf.use_pcap is true or conf.L2socket is available
            from scapy.config import conf
            if conf.use_pcap:
                return True, "Packet capture driver (Npcap/WinPcap) is installed and active."
            return True, "Scapy socket loaded. Elevated administrator rights may be required for raw capture."
        except Exception as e:
            return False, f"Live capture prerequisite warning: {e}. Use synthetic or CSV mode."

    def _extract_packet_metadata(self, packet: Any) -> Optional[Dict[str, Any]]:
        """Extract only header metadata; never store packet payloads."""
        try:
            import scapy.all as scapy_all

            # Check for IP layer
            if not packet.haslayer(scapy_all.IP):
                return None

            ip_layer = packet[scapy_all.IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto_num = ip_layer.proto
            pkt_len = len(packet)
            pkt_time = float(packet.time) if hasattr(packet, "time") else time.time()

            src_port = 0
            dst_port = 0
            tcp_flags = "N/A"
            proto_str = "OTHER"

            if packet.haslayer(scapy_all.TCP):
                tcp_layer = packet[scapy_all.TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                proto_str = "TCP"
                # Scapy TCP flags string (e.g. 'S', 'SA', 'A', 'FA')
                tcp_flags = str(tcp_layer.flags)
            elif packet.haslayer(scapy_all.UDP):
                udp_layer = packet[scapy_all.UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                if src_port == 53 or dst_port == 53:
                    proto_str = "DNS"
                else:
                    proto_str = "UDP"
            elif packet.haslayer(scapy_all.ICMP):
                proto_str = "ICMP"
            else:
                proto_str = protocol_name(proto_num)

            return {
                "timestamp": pkt_time,
                "datetime": datetime.datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto_str,
                "packet_size": pkt_len,
                "tcp_flags": tcp_flags,
                "ttl": int(ip_layer.ttl),
            }
        except Exception as e:
            return None

    def _capture_worker(
        self,
        interface: Optional[str],
        duration_sec: int,
        packet_limit: int,
        bpf_filter: str,
    ) -> None:
        """Internal capture loop running inside background thread."""
        try:
            import scapy.all as scapy_all

            def packet_callback(pkt: Any) -> None:
                if self.stop_requested.is_set():
                    return
                meta = self._extract_packet_metadata(pkt)
                if meta:
                    self.captured_packets.append(meta)
                    self.packets_captured_count += 1
                    self.packet_queue.put(meta)

            start_t = time.time()

            def stop_filter(pkt: Any) -> bool:
                if self.stop_requested.is_set():
                    return True
                if self.packets_captured_count >= packet_limit:
                    return True
                if (time.time() - start_t) >= duration_sec:
                    return True
                return False

            kwargs: Dict[str, Any] = {
                "prn": packet_callback,
                "stop_filter": stop_filter,
                "store": False,
                "timeout": duration_sec,
            }

            if interface and interface != "default":
                kwargs["iface"] = interface

            if bpf_filter.strip():
                kwargs["filter"] = bpf_filter.strip()

            scapy_all.sniff(**kwargs)

        except PermissionError:
            self.error_message = (
                "Permission Denied: Live packet capture requires Administrator privileges. "
                "Run VS Code / terminal as Administrator, install Npcap with WinPcap compatibility, "
                "or use Dataset Analysis / Synthetic Demo Mode."
            )
            logger.error(self.error_message)
        except Exception as e:
            self.error_message = f"Live capture failed: {str(e)}. Tip: Verify Npcap is installed on Windows."
            logger.error(self.error_message)
        finally:
            self.is_capturing = False

    def start_capture(
        self,
        interface: Optional[str] = None,
        duration_sec: int = 20,
        packet_limit: int = 1000,
        bpf_filter: str = "",
    ) -> bool:
        """Start live packet capture asynchronously."""
        if self.is_capturing:
            logger.warning("Capture session already in progress.")
            return False

        self.is_capturing = True
        self.stop_requested.clear()
        self.captured_packets.clear()
        self.packets_captured_count = 0
        self.error_message = None

        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(interface, duration_sec, packet_limit, bpf_filter),
            daemon=True,
        )
        self.capture_thread.start()
        logger.info(f"Background capture started (duration={duration_sec}s, limit={packet_limit}).")
        return True

    def stop_capture(self) -> None:
        """Signal the capture thread to stop safely."""
        if self.is_capturing:
            self.stop_requested.set()
            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(timeout=2.0)
            self.is_capturing = False
            logger.info("Live capture stopped by user.")

    def get_captured_dataframe(self) -> pd.DataFrame:
        """Return captured packets as a Pandas DataFrame."""
        if not self.captured_packets:
            return pd.DataFrame()
        return pd.DataFrame(self.captured_packets)
