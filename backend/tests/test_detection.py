import pytest
import time
from app.schemas.packet_schema import PacketRecord, DetectionThresholds
from app.detection.detection_engine import analyze_traffic_for_threats


def test_port_scan_detection():
    now = int(time.time() * 1000)
    packets = []
    # Generate probes across 12 distinct ports
    for port in range(1, 13):
        packets.append(PacketRecord(
            id=f"test-p-{port}",
            timestamp="2026-11-20T22:00:00Z",
            epochMs=now + (port * 100),
            sourceIp="192.168.1.100",
            destinationIp="192.168.1.1",
            sourcePort=40000 + port,
            destinationPort=port,
            protocol="TCP",
            transportProtocol="TCP",
            size=64,
            tcpFlags=["SYN"],
            summary="SYN probe"
        ))

    th = DetectionThresholds(portScanUniquePorts=8, portScanWindowSec=60)
    alerts = analyze_traffic_for_threats(packets, th, [], now_ms=now + 5000)

    assert len(alerts) >= 1
    ps_alert = next((a for a in alerts if a.category == "port_scan"), None)
    assert ps_alert is not None
    assert ps_alert.sourceIp == "192.168.1.100"
    assert ps_alert.riskScore >= 42
    assert "port" in ps_alert.summary.lower()


def test_syn_anomaly_detection():
    now = int(time.time() * 1000)
    packets = []
    # Generate 25 unacknowledged SYN packets
    for i in range(25):
        packets.append(PacketRecord(
            id=f"test-syn-{i}",
            timestamp="2026-11-20T22:00:00Z",
            epochMs=now + (i * 100),
            sourceIp="10.0.0.99",
            destinationIp="10.0.0.1",
            sourcePort=50000 + i,
            destinationPort=80,
            protocol="TCP",
            transportProtocol="TCP",
            size=64,
            tcpFlags=["SYN"],
            summary="SYN burst"
        ))

    th = DetectionThresholds(synSpikeCount=15, synWindowSec=30)
    alerts = analyze_traffic_for_threats(packets, th, [], now_ms=now + 5000)

    syn_alert = next((a for a in alerts if a.category == "syn_anomaly"), None)
    assert syn_alert is not None
    assert syn_alert.sourceIp == "10.0.0.99"
    assert syn_alert.severity in ("High", "Critical")
