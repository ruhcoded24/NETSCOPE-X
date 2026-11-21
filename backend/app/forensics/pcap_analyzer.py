import subprocess
import os
import time
import datetime
from pathlib import Path
from typing import List, Optional

from app.config import settings
from app.schemas.packet_schema import (
    ForensicReport, PacketRecord, ForensicTimelineBucket, ForensicPeerEntry
)
from app.capture.packet_parser import parse_tshark_line
from app.analyzer.traffic_analyzer import compute_traffic_stats, build_network_topology
from app.detection.detection_engine import analyze_traffic_for_threats


class PcapAnalyzer:
    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_path = tshark_path or settings.TSHARK_PATH

    def analyze_pcap_file(self, file_path: str, original_filename: str) -> ForensicReport:
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = p.stat().st_size
        lower_name = original_filename.lower()
        fmt: str = "pcapng" if lower_name.endswith(".pcapng") else "pcap"

        # TShark extraction flags
        cmd = [
            self.tshark_path,
            "-r", str(p),
            "-n",
            "-T", "fields",
            "-E", "separator=/t",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "tcp.flags.str",
            "-e", "ip.ttl",
            "-e", "dns.qry.name",
            "-e", "dns.flags.rcode",
            "-e", "http.request.method",
            "-e", "http.host",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "_ws.col.Info"
        ]

        packets: List[PacketRecord] = []
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=60
            )
            for line in res.stdout.splitlines():
                pkt = parse_tshark_line(line, f"forensic:{original_filename}")
                if pkt:
                    packets.append(pkt)
        except Exception as e:
            raise RuntimeError(f"TShark PCAP analysis error: {str(e)}")

        now_ms = int(time.time() * 1000)
        alerts = analyze_traffic_for_threats(packets, now_ms=now_ms)
        stats = compute_traffic_stats(packets, alerts, window_seconds=0)
        nodes, edges = build_network_topology(packets, alerts)

        min_epoch = min([p.epochMs for p in packets], default=now_ms)
        max_epoch = max([p.epochMs for p in packets], default=now_ms)
        duration_sec = max(1, round((max_epoch - min_epoch) / 1000))
        total_bytes = sum(p.size for p in packets)

        timeline: List[ForensicTimelineBucket] = [
            ForensicTimelineBucket(
                time=pt.time,
                packets=pt.packets,
                bytes=pt.bytes,
                suspicious=pt.alerts
            )
            for pt in stats.timeSeries
        ]

        top_peers: List[ForensicPeerEntry] = [
            ForensicPeerEntry(
                pair=f"{e.source} -> {e.target}",
                packets=e.packets,
                bytes=e.bytes,
                protocols=[str(pr) for pr in e.protocols]
            )
            for e in edges[:12]
        ]

        return ForensicReport(
            id=f"FOR-{int(time.time())}",
            fileName=original_filename,
            fileSize=file_size,
            format="pcapng" if fmt == "pcapng" else "pcap",
            analyzedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            packetCount=len(packets),
            totalBytes=total_bytes,
            durationSec=duration_sec,
            packets=packets,
            stats=stats,
            alerts=alerts,
            timeline=timeline,
            topPeers=top_peers
        )


pcap_analyzer = PcapAnalyzer()
