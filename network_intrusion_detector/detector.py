from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from scapy.all import ARP, IP, TCP, UDP, Ether


@dataclass
class PacketRecord:
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    flags: str
    proto: str
    mac: Optional[str] = None


@dataclass
class Alert:
    rule: str
    src_ip: str
    evidence: Dict[str, Any]
    timestamp: Optional[float] = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = time.time()


class NetworkIntrusionDetector:
    def __init__(
        self,
        syn_scan_threshold: int = 5,
        syn_scan_window_seconds: int = 60,
        port_scan_threshold: int = 10,
        log_file: Optional[str] = None,
    ) -> None:
        self.syn_scan_threshold = syn_scan_threshold
        self.syn_scan_window_seconds = syn_scan_window_seconds
        self.port_scan_threshold = port_scan_threshold
        self.log_file = Path(log_file) if log_file else None
        self.syn_scan_history: Dict[str, Deque[float]] = defaultdict(deque)
        self.port_scan_history: Dict[str, Dict[str, Deque[tuple[float, int]]]] = defaultdict(lambda: defaultdict(deque))
        self.arp_bindings: Dict[str, str] = {}
        self.alerts: List[Alert] = []

    def handle_packet(self, packet: PacketRecord) -> List[Alert]:
        alerts: List[Alert] = []
        self._prune_history()

        if packet.proto.upper() == "TCP" and packet.flags.upper() == "S":
            now = time.time()
            history = self.syn_scan_history[packet.src_ip]
            history.append(now)
            self._prune_source_history(packet.src_ip)
            if len(history) >= self.syn_scan_threshold:
                alert = Alert(
                    rule="SYN_SCAN",
                    src_ip=packet.src_ip,
                    evidence={"count": len(history), "dport": packet.dport},
                )
                alerts.append(alert)
                self.log_alert(alert)

            port_history = self.port_scan_history[packet.src_ip][packet.dst_ip]
            port_history.append((now, packet.dport))
            self._prune_port_scan_history(packet.src_ip, packet.dst_ip)
            unique_ports = len({port for _, port in port_history})
            if unique_ports >= self.port_scan_threshold:
                alert = Alert(
                    rule="PORT_SCAN",
                    src_ip=packet.src_ip,
                    evidence={"target": packet.dst_ip, "unique_ports": unique_ports},
                )
                alerts.append(alert)
                self.log_alert(alert)

        if packet.proto.upper() == "ARP":
            existing_mac = self.arp_bindings.get(packet.src_ip)
            if existing_mac and existing_mac != packet.mac:
                alert = Alert(
                    rule="ARP_SPOOF",
                    src_ip=packet.src_ip,
                    evidence={"expected_mac": existing_mac, "observed_mac": packet.mac},
                )
                alerts.append(alert)
                self.log_alert(alert)
            elif packet.mac is not None:
                self.arp_bindings[packet.src_ip] = packet.mac

        self.alerts.extend(alerts)
        return alerts

    def _prune_history(self) -> None:
        cutoff = time.time() - self.syn_scan_window_seconds
        for src_ip in list(self.syn_scan_history):
            queue = self.syn_scan_history[src_ip]
            while queue and queue[0] < cutoff:
                queue.popleft()
            if not queue:
                del self.syn_scan_history[src_ip]

    def _prune_source_history(self, src_ip: str) -> None:
        cutoff = time.time() - self.syn_scan_window_seconds
        queue = self.syn_scan_history[src_ip]
        while queue and queue[0] < cutoff:
            queue.popleft()

    def _prune_port_scan_history(self, src_ip: str, dst_ip: str) -> None:
        cutoff = time.time() - self.syn_scan_window_seconds
        queue = self.port_scan_history[src_ip][dst_ip]
        while queue and queue[0][0] < cutoff:
            queue.popleft()
        if not queue:
            del self.port_scan_history[src_ip][dst_ip]
            if not self.port_scan_history[src_ip]:
                del self.port_scan_history[src_ip]

    def log_alert(self, alert: Alert) -> None:
        if self.log_file is not None:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "timestamp": alert.timestamp,
                            "rule": alert.rule,
                            "src_ip": alert.src_ip,
                            "evidence": alert.evidence,
                        }
                    )
                    + "\n"
                )


def parse_packet(packet: Any) -> PacketRecord:
    if isinstance(packet, PacketRecord):
        return packet
    if isinstance(packet, dict):
        return PacketRecord(**packet)

    if hasattr(packet, "haslayer"):
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            return PacketRecord(
                src_ip=arp_layer.psrc,
                dst_ip=arp_layer.pdst,
                sport=0,
                dport=0,
                flags="ARP",
                proto="ARP",
                mac=getattr(arp_layer, "hwsrc", None),
            )

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            sport = 0
            dport = 0
            flags = ""
            proto = "IP"

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                sport = int(tcp_layer.sport)
                dport = int(tcp_layer.dport)
                flags = str(tcp_layer.flags)
                proto = "TCP"
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                sport = int(udp_layer.sport)
                dport = int(udp_layer.dport)
                flags = ""
                proto = "UDP"

            mac = None
            if packet.haslayer(Ether):
                mac = packet[Ether].src

            return PacketRecord(
                src_ip=src_ip,
                dst_ip=dst_ip,
                sport=sport,
                dport=dport,
                flags=flags,
                proto=proto,
                mac=mac,
            )

    raise TypeError("Unsupported packet type for parsing")
