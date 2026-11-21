from typing import Optional, List, Dict, Tuple
from app.schemas.packet_schema import ProtocolName


WELL_KNOWN_PORT_SERVICES: Dict[int, str] = {
    20: 'FTP-DATA',
    21: 'FTP',
    22: 'SSH',
    23: 'TELNET',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP-S',
    68: 'DHCP-C',
    80: 'HTTP',
    110: 'POP3',
    123: 'NTP',
    143: 'IMAP',
    161: 'SNMP',
    443: 'HTTPS/TLS',
    445: 'SMB',
    587: 'SMTP-SUB',
    993: 'IMAPS',
    1433: 'MSSQL',
    3000: 'APP-HTTP',
    3306: 'MYSQL',
    3389: 'RDP',
    5353: 'mDNS',
    5432: 'POSTGRES',
    6379: 'REDIS',
    8080: 'HTTP-ALT',
    8443: 'HTTPS-ALT',
}


def get_port_service_name(port: Optional[int]) -> str:
    if port is None:
        return 'UNKNOWN'
    return WELL_KNOWN_PORT_SERVICES.get(port, f"PORT-{port}")


def is_private_ip(ip: str) -> bool:
    clean = ip.strip().lower()
    if not clean:
        return True

    if clean in ('::1', 'localhost', '::') or clean.startswith(('fe80:', 'fc', 'fd')):
        return True

    v4 = clean[7:] if clean.startswith('::ffff:') else clean
    parts = v4.split('.')
    if len(parts) != 4:
        return False

    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return True

    if any(n < 0 or n > 255 for n in nums):
        return True

    a, b = nums[0], nums[1]
    if a == 10:
        return True
    if a == 127:
        return True
    if a == 0:
        return True
    if a == 169 and b == 254:
        return True
    if a == 172 and (16 <= b <= 31):
        return True
    if a == 192 and b == 168:
        return True
    if a == 100 and (64 <= b <= 127):
        return True
    if a >= 224:
        return True
    return False


def classify_protocol(
    tshark_proto: Optional[str] = None,
    source_port: Optional[int] = None,
    dest_port: Optional[int] = None,
    ip_proto: Optional[int] = None,
    ether_type: Optional[int] = None
) -> Tuple[ProtocolName, str, List[str]]:
    """
    Classifies protocol honoring application-layer precedence over transport.
    Returns (protocol_name, transport_protocol, layer_stack).
    """
    ts_upper = (tshark_proto or '').upper()

    if ether_type == 0x0806 or 'ARP' in ts_upper:
        return 'ARP', 'ARP', ['Ethernet II', 'ARP']

    ports = [p for p in (source_port, dest_port) if p is not None]

    transport = 'OTHER'
    if 'TCP' in ts_upper or ip_proto == 6 or any(p in (80, 443, 8080, 8443, 22, 21, 25) for p in ports):
        transport = 'TCP'
    elif 'UDP' in ts_upper or ip_proto == 17 or any(p in (53, 5353, 67, 68, 123) for p in ports):
        transport = 'UDP'
    elif 'ICMP' in ts_upper or ip_proto in (1, 58):
        transport = 'ICMP'

    if 'ICMP' in ts_upper or transport == 'ICMP':
        return 'ICMP', 'ICMP', ['Ethernet II', 'IP', 'ICMP']

    if 'DNS' in ts_upper or any(p in (53, 5353) for p in ports):
        return 'DNS', transport if transport != 'OTHER' else 'UDP', ['Ethernet II', 'IP', transport or 'UDP', 'DNS']

    if 'DHCP' in ts_upper or any(p in (67, 68) for p in ports):
        return 'DHCP', 'UDP', ['Ethernet II', 'IP', 'UDP', 'DHCP']

    if 'TLS' in ts_upper or 'SSL' in ts_upper or any(p in (443, 8443) for p in ports):
        return 'HTTPS/TLS', transport, ['Ethernet II', 'IP', transport, 'TLS (Encrypted Metadata)']

    if 'HTTP' in ts_upper or any(p in (80, 8080, 3000) for p in ports):
        return 'HTTP', transport, ['Ethernet II', 'IP', transport, 'HTTP']

    if transport == 'TCP':
        return 'TCP', 'TCP', ['Ethernet II', 'IP', 'TCP']

    if transport == 'UDP':
        return 'UDP', 'UDP', ['Ethernet II', 'IP', 'UDP']

    return 'OTHER', transport, ['Ethernet II', 'IP', transport]
