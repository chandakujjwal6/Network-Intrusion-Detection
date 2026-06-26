from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional


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
    def __init__(self, syn_scan_threshold: int = 5, syn_scan_window_seconds: int = 60) -> None:
        self.syn_scan_threshold = syn_scan_threshold
        self.syn_scan_window_seconds = syn_scan_window_seconds
        self.syn_scan_history: Dict[str, Deque[float]] = defaultdict(deque)
        self.arp_bindings: Dict[str, str] = {}

    def handle_packet(self, packet: PacketRecord) -> List[Alert]:
        alerts: List[Alert] = []
        self._prune_history()

        if packet.proto.upper() == "TCP" and packet.flags.upper() == "S":
            history = self.syn_scan_history[packet.src_ip]
            history.append(time.time())
            self._prune_source_history(packet.src_ip)
            if len(history) >= self.syn_scan_threshold:
                alerts.append(
                    Alert(
                        rule="SYN_SCAN",
                        src_ip=packet.src_ip,
                        evidence={"count": len(history), "dport": packet.dport},
                    )
                )

        if packet.proto.upper() == "ARP":
            existing_mac = self.arp_bindings.get(packet.src_ip)
            if existing_mac and existing_mac != packet.mac:
                alerts.append(
                    Alert(
                        rule="ARP_SPOOF",
                        src_ip=packet.src_ip,
                        evidence={"expected_mac": existing_mac, "observed_mac": packet.mac},
                    )
                )
            elif packet.mac is not None:
                self.arp_bindings[packet.src_ip] = packet.mac

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


def parse_packet(packet: Any) -> PacketRecord:
    if isinstance(packet, PacketRecord):
        return packet
    if isinstance(packet, dict):
        return PacketRecord(**packet)
    raise TypeError("Unsupported packet type for parsing")
