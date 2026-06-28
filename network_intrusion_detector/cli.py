from __future__ import annotations

import argparse
import sys
from typing import Optional

from scapy.all import sniff

from .detector import NetworkIntrusionDetector, parse_packet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Real-time network intrusion detection")
    parser.add_argument("--iface", default=None, help="Network interface to capture from")
    parser.add_argument("--threshold", type=int, default=5, help="SYN-scan threshold")
    parser.add_argument("--window", type=int, default=60, help="Rolling window in seconds")
    parser.add_argument("--log-file", default="alerts.jsonl", help="File for structured alert logs")
    return parser


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

    print("Starting live capture... Press Ctrl+C to stop.")
    try:
        sniff(iface=args.iface, prn=on_packet, store=0)
    except KeyboardInterrupt:
        print("Capture stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
