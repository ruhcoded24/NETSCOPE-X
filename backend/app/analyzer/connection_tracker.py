import time
from typing import Dict, Optional, List
from pydantic import BaseModel

from app.schemas.packet_schema import PacketRecord


class ConnectionState(BaseModel):
    key: str
    sourceIp: str
    destinationIp: str
    sourcePort: Optional[int]
    destinationPort: Optional[int]
    protocol: str
    packetCount: int = 0
    byteCount: int = 0
    firstSeenEpochMs: int = 0
    lastSeenEpochMs: int = 0
    state: str = "active"


class ConnectionTracker:
    def __init__(self, max_connections: int = 2000):
        self.connections: Dict[str, ConnectionState] = {}
        self.max_connections = max_connections

    def track_packet(self, packet: PacketRecord):
        if not packet.sourcePort or not packet.destinationPort:
            return

        # Canonical key regardless of direction
        pair = sorted([(packet.sourceIp, packet.sourcePort), (packet.destinationIp, packet.destinationPort)])
        key = f"{pair[0][0]}:{pair[0][1]}-{pair[1][0]}:{pair[1][1]}-{packet.transportProtocol}"

        if key in self.connections:
            conn = self.connections[key]
            conn.packetCount += 1
            conn.byteCount += packet.size
            conn.lastSeenEpochMs = packet.epochMs
            if "FIN" in packet.tcpFlags or "RST" in packet.tcpFlags:
                conn.state = "closing"
        else:
            if len(self.connections) >= self.max_connections:
                # Evict oldest
                oldest_key = min(self.connections.keys(), key=lambda k: self.connections[k].lastSeenEpochMs)
                del self.connections[oldest_key]

            self.connections[key] = ConnectionState(
                key=key,
                sourceIp=packet.sourceIp,
                destinationIp=packet.destinationIp,
                sourcePort=packet.sourcePort,
                destinationPort=packet.destinationPort,
                protocol=packet.protocol,
                packetCount=1,
                byteCount=packet.size,
                firstSeenEpochMs=packet.epochMs,
                lastSeenEpochMs=packet.epochMs,
                state="syn_sent" if "SYN" in packet.tcpFlags else "active"
            )

    def get_active_connections(self) -> List[ConnectionState]:
        return list(self.connections.values())


connection_tracker = ConnectionTracker()
