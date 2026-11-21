import pytest
from app.capture.packet_parser import parse_tshark_line, parse_tcp_flags
from app.analyzer.protocol_analyzer import is_private_ip, classify_protocol


def test_parse_tcp_flags():
    assert "ACK" in parse_tcp_flags("·······A····")
    assert "ACK" in parse_tcp_flags("·······AP···")
    assert "PSH" in parse_tcp_flags("·······AP···")
    assert "SYN" in parse_tcp_flags("······S·····")
    assert "SYN" in parse_tcp_flags("0x00000002")
    assert "ACK" in parse_tcp_flags("0x00000010")


def test_is_private_ip():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("::1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


def test_classify_protocol():
    proto, transport, stack = classify_protocol(source_port=53, dest_port=54000)
    assert proto == "DNS"

    proto, transport, stack = classify_protocol(source_port=443, dest_port=54000)
    assert proto == "HTTPS/TLS"

    proto, transport, stack = classify_protocol(source_port=80, dest_port=54000)
    assert proto == "HTTP"

    proto, transport, stack = classify_protocol(source_port=45000, dest_port=50000, tshark_proto="TCP")
    assert proto == "TCP"


def test_parse_tshark_line():
    sample_line = "1\t1795195031.754982300\t172.25.221.13\t\t172.188.155.25\t\t50439\t\t443\t\tSSL\t55\t·······A····\t128\t\t\t\t\t\t"
    pkt = parse_tshark_line(sample_line, "Wi-Fi", {"172.25.221.13"})
    assert pkt is not None
    assert pkt.sourceIp == "172.25.221.13"
    assert pkt.destinationIp == "172.188.155.25"
    assert pkt.sourcePort == 50439
    assert pkt.destinationPort == 443
    assert pkt.protocol == "HTTPS/TLS"
    assert pkt.direction == "outbound"
    assert "ACK" in pkt.tcpFlags
