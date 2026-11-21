import time
import uuid
import datetime
from typing import Optional, List, Set
from app.schemas.packet_schema import PacketRecord
from app.analyzer.protocol_analyzer import classify_protocol, is_private_ip


def parse_tcp_flags(flag_str: str) -> List[str]:
    """
    Parses TShark tcp.flags or tcp.flags.str, e.g.:
    '·······A····' -> ['ACK']
    '·······AP···' -> ['ACK', 'PSH']
    '······S·····' -> ['SYN']
    '0x00000012'   -> ['SYN', 'ACK']
    """
    flags = []
    if not flag_str:
        return flags

    clean = flag_str.strip()
    # Check hex format
    if clean.startswith("0x"):
        try:
            val = int(clean, 16)
            if val & 0x01: flags.append("FIN")
            if val & 0x02: flags.append("SYN")
            if val & 0x04: flags.append("RST")
            if val & 0x08: flags.append("PSH")
            if val & 0x10: flags.append("ACK")
            if val & 0x20: flags.append("URG")
            if val & 0x40: flags.append("ECE")
            if val & 0x80: flags.append("CWR")
            return flags
        except ValueError:
            pass

    # Check dot string format from TShark
    if "F" in clean: flags.append("FIN")
    if "S" in clean: flags.append("SYN")
    if "R" in clean: flags.append("RST")
    if "P" in clean: flags.append("PSH")
    if "A" in clean: flags.append("ACK")
    if "U" in clean: flags.append("URG")

    # Word match
    upper = clean.upper()
    for word in ("SYN", "ACK", "FIN", "RST", "PSH", "URG"):
        if word in upper and word not in flags:
            flags.append(word)

    return flags


def parse_tshark_line(line: str, interface_name: str = "", host_ips: Optional[Set[str]] = None) -> Optional[PacketRecord]:
    """
    Parses a tab-separated line from TShark:
    0: frame.number
    1: frame.time_epoch
    2: ip.src
    3: ipv6.src
    4: ip.dst
    5: ipv6.dst
    6: tcp.srcport
    7: udp.srcport
    8: tcp.dstport
    9: udp.dstport
    10: _ws.col.Protocol
    11: frame.len
    12: tcp.flags.str
    13: ip.ttl
    14: dns.qry.name
    15: dns.flags.rcode
    16: http.request.method
    17: http.host
    18: tls.handshake.extensions_server_name
    19: _ws.col.Info
    """
    if not line or line.startswith("Capturing") or line.startswith("tshark:"):
        return None

    cols = line.split("\t")
    if len(cols) < 5:
        return None

    def get_col(idx: int) -> str:
        return cols[idx].strip() if idx < len(cols) else ""

    frame_num = get_col(0)
    time_epoch_raw = get_col(1)

    src_ip = get_col(2) or get_col(3) or "0.0.0.0"
    dst_ip = get_col(4) or get_col(5) or "0.0.0.0"

    src_port_raw = get_col(6) or get_col(7)
    dst_port_raw = get_col(8) or get_col(9)

    src_port: Optional[int] = int(src_port_raw) if src_port_raw.isdigit() else None
    dst_port: Optional[int] = int(dst_port_raw) if dst_port_raw.isdigit() else None

    raw_proto = get_col(10)
    length_raw = get_col(11)
    size = int(length_raw) if length_raw.isdigit() else 64

    flags_raw = get_col(12)
    tcp_flags = parse_tcp_flags(flags_raw)

    ttl_raw = get_col(13)
    ttl = int(ttl_raw) if ttl_raw.isdigit() else None

    dns_query = get_col(14) or None
    dns_rcode = get_col(15) or None
    http_method = get_col(16) or None
    http_host = get_col(17) or None
    tls_sni = get_col(18) or None
    info_col = get_col(19)

    # Calculate timestamps
    try:
        epoch_sec = float(time_epoch_raw)
        epoch_ms = int(epoch_sec * 1000)
        dt = datetime.datetime.fromtimestamp(epoch_sec, tz=datetime.timezone.utc)
        timestamp_str = dt.isoformat()
    except (ValueError, OSError):
        now_ts = time.time()
        epoch_ms = int(now_ts * 1000)
        timestamp_str = datetime.datetime.fromtimestamp(now_ts, tz=datetime.timezone.utc).isoformat()

    # Protocol classification
    protocol, transport_proto, layer_stack = classify_protocol(
        tshark_proto=raw_proto,
        source_port=src_port,
        dest_port=dst_port
    )

    # Determine direction
    direction = "local"
    if host_ips:
        is_src_host = src_ip in host_ips
        is_dst_host = dst_ip in host_ips
        if is_src_host and not is_dst_host:
            direction = "outbound"
        elif is_dst_host and not is_src_host:
            direction = "inbound"
    else:
        # Heuristic fallback based on private / public IP
        src_priv = is_private_ip(src_ip)
        dst_priv = is_private_ip(dst_ip)
        if src_priv and not dst_priv:
            direction = "outbound"
        elif not src_priv and dst_priv:
            direction = "inbound"

    # Construct clean summary
    summary = info_col
    if not summary:
        sp_label = f":{src_port}" if src_port else ""
        dp_label = f":{dst_port}" if dst_port else ""
        flag_label = f" [{', '.join(tcp_flags)}]" if tcp_flags else ""
        summary = f"{protocol} {src_ip}{sp_label} -> {dst_ip}{dp_label}{flag_label} ({size} bytes)"

    pkt_id = f"pkt-{epoch_ms}-{frame_num or uuid.uuid4().hex[:6]}"

    return PacketRecord(
        id=pkt_id,
        timestamp=timestamp_str,
        epochMs=epoch_ms,
        sourceIp=src_ip,
        destinationIp=dst_ip,
        sourcePort=src_port,
        destinationPort=dst_port,
        protocol=protocol,
        transportProtocol=transport_proto,
        size=size,
        tcpFlags=tcp_flags,
        ttl=ttl,
        interfaceName=interface_name,
        direction=direction,
        isSimulated=False,
        summary=summary,
        layerStack=layer_stack,
        dnsQuery=dns_query,
        dnsResponseCode=dns_rcode,
        httpMethod=http_method,
        httpHost=http_host,
        tlsSni=tls_sni
    )
