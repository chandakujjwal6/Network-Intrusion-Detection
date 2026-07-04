from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from network_intrusion_detector.detector import PacketRecord, NetworkIntrusionDetector, parse_packet


def build_syn_packet(src_ip: str, dst_ip: str, sport: int, dport: int) -> Packet:
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S")


def test_parse_packet_from_scapy_packet():
    packet = build_syn_packet("192.168.1.10", "192.168.1.1", 40000, 22)
    record = parse_packet(packet)

    assert record.src_ip == "192.168.1.10"
    assert record.dst_ip == "192.168.1.1"
    assert record.proto == "TCP"
    assert record.flags == "S"
    assert record.sport == 40000
    assert record.dport == 22


def test_live_detector_handles_scapy_packet():
    detector = NetworkIntrusionDetector(syn_scan_threshold=1, syn_scan_window_seconds=60)
    packet = build_syn_packet("198.51.100.10", "10.0.0.5", 40001, 22)
    record = parse_packet(packet)
    alerts = detector.handle_packet(record)

    assert len(alerts) == 1
    assert alerts[0].rule == "SYN_SCAN"
