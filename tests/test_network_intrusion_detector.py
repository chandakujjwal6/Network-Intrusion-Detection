import pytest

from network_intrusion_detector.detector import PacketRecord, NetworkIntrusionDetector


@pytest.fixture
def detector():
    return NetworkIntrusionDetector(syn_scan_threshold=3, syn_scan_window_seconds=60)


def test_parse_packet_extracts_fields():
    packet = {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.1",
        "sport": 50000,
        "dport": 22,
        "flags": "S",
        "proto": "TCP",
    }

    record = PacketRecord(**packet)

    assert record.src_ip == "192.168.1.10"
    assert record.dport == 22
    assert record.flags == "S"
    assert record.proto == "TCP"


def test_syn_scan_detector_triggers_after_threshold(detector):
    alerts = []
    for idx in range(3):
        packet = PacketRecord(
            src_ip="198.51.100.10",
            dst_ip="10.0.0.5",
            sport=40000 + idx,
            dport=22,
            flags="S",
            proto="TCP",
        )
        alerts.extend(detector.handle_packet(packet))

    assert any(alert.rule == "SYN_SCAN" for alert in alerts)


def test_arp_spoof_detector_triggers_on_conflict(detector):
    first = PacketRecord(
        src_ip="192.168.1.1",
        dst_ip="192.168.1.255",
        sport=0,
        dport=0,
        flags="ARP",
        proto="ARP",
        mac="aa:bb:cc:dd:ee:ff",
    )
    second = PacketRecord(
        src_ip="192.168.1.1",
        dst_ip="192.168.1.255",
        sport=0,
        dport=0,
        flags="ARP",
        proto="ARP",
        mac="11:22:33:44:55:66",
    )

    alerts = []
    alerts.extend(detector.handle_packet(first))
    alerts.extend(detector.handle_packet(second))

    assert any(alert.rule == "ARP_SPOOF" for alert in alerts)
