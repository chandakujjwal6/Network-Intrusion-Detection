import json

from network_intrusion_detector.detector import Alert, NetworkIntrusionDetector, PacketRecord


def test_syn_scan_alert_is_logged(tmp_path):
    log_path = tmp_path / "alerts.jsonl"
    detector = NetworkIntrusionDetector(
        syn_scan_threshold=2,
        syn_scan_window_seconds=60,
        log_file=str(log_path),
    )

    for idx in range(2):
        packet = PacketRecord(
            src_ip="198.51.100.10",
            dst_ip="10.0.0.5",
            sport=40000 + idx,
            dport=22,
            flags="S",
            proto="TCP",
        )
        alerts = detector.handle_packet(packet)

    assert any(alert.rule == "SYN_SCAN" for alert in alerts)

    logged = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(entry["rule"] == "SYN_SCAN" for entry in logged)
