# Network Intrusion Detector

A lightweight real-time packet analysis tool built with Python and Scapy.

## Features

- Live packet capture and parsing
- SYN-scan detection using a rolling per-source-IP time window
- ARP-spoof detection through IP-to-MAC binding tracking
- Structured alert logging to JSON Lines

## Running

Install dependencies:

```bash
python -m pip install pytest scapy
```

Run the detector:

```bash
python -m network_intrusion_detector.cli --iface Wi-Fi --threshold 5 --window 60 --log-file alerts.jsonl
```

Run the tests:

```bash
python -m pytest -q
```
