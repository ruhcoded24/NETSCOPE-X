import time
import datetime
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, Any

from app.schemas.packet_schema import (
    PacketRecord, SecurityAlert, TrafficStats, TimeSeriesPoint,
    IpCountEntry, PortCountEntry, SizeBucket, NetworkDeviceNode, NetworkEdge,
    ProtocolName, SeverityLevel, DeviceCategory
)
from app.analyzer.protocol_analyzer import get_port_service_name, is_private_ip

ALL_PROTOCOLS: List[ProtocolName] = [
    'TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS/TLS', 'ARP', 'DHCP', 'OTHER'
]

SEVERITY_RANK: Dict[SeverityLevel, int] = {
    'Informational': 1,
    'Low': 2,
    'Medium': 3,
    'High': 4,
    'Critical': 5,
}


def compute_traffic_stats(
    packets: List[PacketRecord],
    alerts: List[SecurityAlert],
    window_seconds: int = 300,
    now_ms: Optional[int] = None
) -> TrafficStats:
    now = now_ms or int(time.time() * 1000)
    cutoff = now - (window_seconds * 1000) if window_seconds > 0 else 0

    scoped_packets = [p for p in packets if p.epochMs >= cutoff] if cutoff > 0 else packets
    scoped_alerts = [a for a in alerts if a.epochMs >= cutoff] if cutoff > 0 else alerts

    proto_dist: Dict[str, int] = {p: 0 for p in ALL_PROTOCOLS}
    tcp_flags_dist: Dict[str, int] = defaultdict(int)

    total_bytes = 0
    incoming_packets = 0
    outgoing_packets = 0
    local_packets = 0

    src_counts: Dict[str, List[int]] = defaultdict(lambda: [0, 0])  # [pkts, bytes]
    dst_counts: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    device_counts: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    port_counts: Dict[int, List[int]] = defaultdict(lambda: [0, 0])

    bucket_limits = [
        ("<64 B", lambda s: s < 64),
        ("64-127 B", lambda s: 64 <= s <= 127),
        ("128-511 B", lambda s: 128 <= s <= 511),
        ("512-1023 B", lambda s: 512 <= s <= 1023),
        ("1024-1518 B", lambda s: 1024 <= s <= 1518),
        (">1518 B", lambda s: s > 1518),
    ]
    size_buckets: Dict[str, int] = {b[0]: 0 for b in bucket_limits}

    min_epoch = now
    max_epoch = 0

    for p in scoped_packets:
        total_bytes += p.size
        proto_dist[p.protocol] = proto_dist.get(p.protocol, 0) + 1

        if p.epochMs < min_epoch: min_epoch = p.epochMs
        if p.epochMs > max_epoch: max_epoch = p.epochMs

        if p.direction == "inbound": incoming_packets += 1
        elif p.direction == "outbound": outgoing_packets += 1
        else: local_packets += 1

        src_counts[p.sourceIp][0] += 1
        src_counts[p.sourceIp][1] += p.size

        dst_counts[p.destinationIp][0] += 1
        dst_counts[p.destinationIp][1] += p.size

        device_counts[p.sourceIp][0] += 1
        device_counts[p.sourceIp][1] += p.size
        device_counts[p.destinationIp][0] += 1
        device_counts[p.destinationIp][1] += p.size

        if p.destinationPort is not None:
            port_counts[p.destinationPort][0] += 1
            port_counts[p.destinationPort][1] += p.size

        for flag in p.tcpFlags:
            tcp_flags_dist[flag] += 1

        for label, cond in bucket_limits:
            if cond(p.size):
                size_buckets[label] += 1
                break

    pkt_count = len(scoped_packets)
    duration_sec = max(1.0, (max_epoch - min_epoch) / 1000.0) if pkt_count > 1 else max(1.0, float(window_seconds))

    pps = round(pkt_count / duration_sec, 2)
    bps = round(total_bytes / duration_sec, 2)
    avg_size = round(total_bytes / pkt_count, 1) if pkt_count > 0 else 0.0

    top_src = sorted(
        [IpCountEntry(ip=k, packets=v[0], bytes=v[1]) for k, v in src_counts.items()],
        key=lambda x: x.packets,
        reverse=True
    )[:8]

    top_dst = sorted(
        [IpCountEntry(ip=k, packets=v[0], bytes=v[1]) for k, v in dst_counts.items()],
        key=lambda x: x.packets,
        reverse=True
    )[:8]

    top_dev = sorted(
        [IpCountEntry(ip=k, packets=v[0], bytes=v[1]) for k, v in device_counts.items()],
        key=lambda x: x.bytes,
        reverse=True
    )[:10]

    top_ports = sorted(
        [
            PortCountEntry(
                port=k,
                service=get_port_service_name(k),
                packets=v[0],
                bytes=v[1]
            )
            for k, v in port_counts.items()
        ],
        key=lambda x: x.packets,
        reverse=True
    )[:8]

    buckets_list = [SizeBucket(label=k, count=v) for k, v in size_buckets.items()]

    # Generate Time Series Points (bucketed by e.g. 5 seconds)
    step_sec = max(2, min(30, window_seconds // 30))
    ts_buckets: Dict[int, Dict[str, int]] = defaultdict(lambda: {
        "packets": 0, "bytes": 0, "inboundBytes": 0, "outboundBytes": 0, "alerts": 0
    })

    for p in scoped_packets:
        b_key = (p.epochMs // (step_sec * 1000)) * (step_sec * 1000)
        ts_buckets[b_key]["packets"] += 1
        ts_buckets[b_key]["bytes"] += p.size
        if p.direction == "inbound":
            ts_buckets[b_key]["inboundBytes"] += p.size
        elif p.direction == "outbound":
            ts_buckets[b_key]["outboundBytes"] += p.size

    for a in scoped_alerts:
        b_key = (a.epochMs // (step_sec * 1000)) * (step_sec * 1000)
        ts_buckets[b_key]["alerts"] += 1

    time_series: List[TimeSeriesPoint] = []
    # Fill range from cutoff to now
    start_ts = (cutoff // (step_sec * 1000)) * (step_sec * 1000) if cutoff > 0 else (min_epoch // (step_sec * 1000)) * (step_sec * 1000)
    end_ts = (now // (step_sec * 1000)) * (step_sec * 1000)

    cur = start_ts
    while cur <= end_ts:
        dt = datetime.datetime.fromtimestamp(cur / 1000.0, tz=datetime.timezone.utc)
        b_data = ts_buckets[cur]
        time_series.append(TimeSeriesPoint(
            time=dt.strftime("%H:%M:%S"),
            epochMs=cur,
            packets=b_data["packets"],
            bytes=b_data["bytes"],
            inboundBytes=b_data["inboundBytes"],
            outboundBytes=b_data["outboundBytes"],
            alerts=b_data["alerts"]
        ))
        cur += step_sec * 1000

    return TrafficStats(
        totalPackets=pkt_count,
        totalBytes=total_bytes,
        incomingPackets=incoming_packets,
        outgoingPackets=outgoing_packets,
        localPackets=local_packets,
        packetsPerSecond=pps,
        bytesPerSecond=bps,
        averagePacketSize=avg_size,
        protocolDistribution=proto_dist,
        topSourceIps=top_src,
        topDestinationIps=top_dst,
        topDevices=top_dev,
        topPorts=top_ports,
        tcpFlagDistribution=dict(tcp_flags_dist),
        packetSizeBuckets=buckets_list,
        timeSeries=time_series,
        windowSeconds=window_seconds
    )


def build_network_topology(
    packets: List[PacketRecord],
    alerts: List[SecurityAlert],
    protocol_filter: Optional[str] = "ALL"
) -> Tuple[List[NetworkDeviceNode], List[NetworkEdge]]:
    scoped = packets
    if protocol_filter and protocol_filter != "ALL":
        scoped = [p for p in packets if p.protocol == protocol_filter]

    node_map: Dict[str, Dict[str, Any]] = {}
    edge_map: Dict[str, Dict[str, Any]] = {}

    alert_ip_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "maxSeverity": None})
    for a in alerts:
        st = alert_ip_stats[a.sourceIp]
        st["count"] += 1
        cur_rank = SEVERITY_RANK.get(st["maxSeverity"], 0)
        new_rank = SEVERITY_RANK.get(a.severity, 0)
        if new_rank > cur_rank:
            st["maxSeverity"] = a.severity

        if a.destinationIp:
            dst_st = alert_ip_stats[a.destinationIp]
            dst_st["count"] += 1

    def get_or_create_node(ip: str) -> Dict[str, Any]:
        if ip not in node_map:
            priv = is_private_ip(ip)
            cat: DeviceCategory = "workstation"
            if ip.endswith(".1") or ip.endswith(".254"):
                cat = "gateway"
            elif not priv:
                cat = "server"

            node_map[ip] = {
                "ip": ip,
                "category": cat,
                "isPrivate": priv,
                "packetCount": 0,
                "byteVolume": 0,
                "inboundCount": 0,
                "outboundCount": 0,
                "protocols": set(),
                "lastSeenEpoch": 0,
                "lastSeen": "",
                "alertCount": alert_ip_stats[ip]["count"],
                "maxSeverity": alert_ip_stats[ip]["maxSeverity"],
                "connectedPeers": set()
            }
        return node_map[ip]

    for p in scoped:
        src_node = get_or_create_node(p.sourceIp)
        dst_node = get_or_create_node(p.destinationIp)

        src_node["packetCount"] += 1
        src_node["byteVolume"] += p.size
        src_node["outboundCount"] += 1
        src_node["protocols"].add(p.protocol)
        src_node["connectedPeers"].add(p.destinationIp)
        if p.epochMs > src_node["lastSeenEpoch"]:
            src_node["lastSeenEpoch"] = p.epochMs
            src_node["lastSeen"] = p.timestamp

        dst_node["packetCount"] += 1
        dst_node["byteVolume"] += p.size
        dst_node["inboundCount"] += 1
        dst_node["protocols"].add(p.protocol)
        dst_node["connectedPeers"].add(p.sourceIp)
        if p.epochMs > dst_node["lastSeenEpoch"]:
            dst_node["lastSeenEpoch"] = p.epochMs
            dst_node["lastSeen"] = p.timestamp

        # Service / server detection
        if p.destinationPort and p.destinationPort < 1024 or p.destinationPort in (3000, 5432, 8080):
            dst_node["category"] = "server"

        edge_key = f"{p.sourceIp}->{p.destinationIp}"
        if edge_key not in edge_map:
            edge_map[edge_key] = {
                "id": edge_key,
                "source": p.sourceIp,
                "target": p.destinationIp,
                "packets": 0,
                "bytes": 0,
                "protocols": set(),
                "hasAlert": alert_ip_stats[p.sourceIp]["count"] > 0 or alert_ip_stats[p.destinationIp]["count"] > 0,
                "lastSeenEpochMs": p.epochMs
            }
        edge = edge_map[edge_key]
        edge["packets"] += 1
        edge["bytes"] += p.size
        edge["protocols"].add(p.protocol)
        if p.epochMs > edge["lastSeenEpochMs"]:
            edge["lastSeenEpochMs"] = p.epochMs

    nodes = [
        NetworkDeviceNode(
            ip=n["ip"],
            category=n["category"],
            isPrivate=n["isPrivate"],
            packetCount=n["packetCount"],
            byteVolume=n["byteVolume"],
            inboundCount=n["inboundCount"],
            outboundCount=n["outboundCount"],
            protocols=list(n["protocols"]),
            lastSeen=n["lastSeen"],
            alertCount=n["alertCount"],
            maxSeverity=n["maxSeverity"],
            connectedPeers=list(n["connectedPeers"])[:20]
        )
        for n in node_map.values()
    ]

    edges = [
        NetworkEdge(
            id=e["id"],
            source=e["source"],
            target=e["target"],
            packets=e["packets"],
            bytes=e["bytes"],
            protocols=list(e["protocols"]),
            hasAlert=e["hasAlert"],
            lastSeenEpochMs=e["lastSeenEpochMs"]
        )
        for e in edge_map.values()
    ]

    return nodes, edges
