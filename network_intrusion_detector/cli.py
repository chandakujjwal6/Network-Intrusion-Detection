from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from scapy.all import ARP, IP, TCP, UDP, Ether, sniff, rdpcap

from .detector import NetworkIntrusionDetector, parse_packet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Real-time network intrusion detection")
    parser.add_argument("--iface", default=None, help="Network interface to capture from")
    parser.add_argument("--threshold", type=int, default=5, help="SYN-scan threshold")
    parser.add_argument("--window", type=int, default=60, help="Rolling window in seconds")
    parser.add_argument("--log-file", default="alerts.jsonl", help="File for structured alert logs")
    parser.add_argument("--pcap", default=None, help="Replay packets from a pcap file instead of live capture")
    return parser


def process_packet(packet: object, detector: NetworkIntrusionDetector) -> None:
    try:
        record = parse_packet(packet)
    except TypeError:
        return

    alerts = detector.handle_packet(record)
    for alert in alerts:
        print(f"[ALERT] {alert.rule} src={alert.src_ip} evidence={alert.evidence}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    detector = NetworkIntrusionDetector(
        syn_scan_threshold=args.threshold,
        syn_scan_window_seconds=args.window,
        log_file=args.log_file,
    )

    def on_packet(packet: object) -> None:
        try:
            record = parse_packet(packet)
        except TypeError:
            return

        alerts = detector.handle_packet(record)
        for alert in alerts:
            print(f"[ALERT] {alert.rule} src={alert.src_ip} evidence={alert.evidence}")

    if args.pcap:
        packet_path = Path(args.pcap)
        if not packet_path.exists():
            print(f"PCAP file not found: {packet_path}")
            return 1

        packets = rdpcap(str(packet_path))
        for packet in packets:
            process_packet(packet, detector)
        return 0

    print("Starting live capture... Press Ctrl+C to stop.")
    try:
        sniff(iface=args.iface, prn=lambda pkt: process_packet(pkt, detector), store=0)
    except KeyboardInterrupt:
        print("Capture stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
