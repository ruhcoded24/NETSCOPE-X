from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal


ProtocolName = Literal[
    'TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS/TLS', 'ARP', 'DHCP', 'OTHER'
]
SeverityLevel = Literal['Informational', 'Low', 'Medium', 'High', 'Critical']
IncidentStatus = Literal['new', 'investigating', 'resolved']
DetectionCategory = Literal[
    'port_scan', 'syn_anomaly', 'traffic_spike', 'dns_anomaly', 'connection_anomaly'
]
DeviceCategory = Literal['gateway', 'server', 'workstation', 'unknown']


class NetworkInterfaceInfo(BaseModel):
    name: str
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    mac: Optional[str] = None
    internal: bool = False
    rxBytes: int = 0
    txBytes: int = 0
    rxPackets: int = 0
    txPackets: int = 0
    status: Literal['up', 'down'] = 'up'


class PacketRecord(BaseModel):
    id: str
    timestamp: str
    epochMs: int
    sourceIp: str
    destinationIp: str
    sourcePort: Optional[int] = None
    destinationPort: Optional[int] = None
    protocol: ProtocolName = 'OTHER'
    transportProtocol: str = ''
    size: int = 0
    tcpFlags: List[str] = Field(default_factory=list)
    ttl: Optional[int] = None
    interfaceName: str = ''
    direction: Literal['inbound', 'outbound', 'local'] = 'local'
    isSimulated: bool = False
    summary: str = ''
    layerStack: List[str] = Field(default_factory=list)
    dnsQuery: Optional[str] = None
    dnsResponseCode: Optional[str] = None
    httpMethod: Optional[str] = None
    httpHost: Optional[str] = None
    tlsSni: Optional[str] = None


class TimeSeriesPoint(BaseModel):
    time: str
    epochMs: int
    packets: int
    bytes: int
    inboundBytes: int
    outboundBytes: int
    alerts: int


class IpCountEntry(BaseModel):
    ip: str
    packets: int
    bytes: int


class PortCountEntry(BaseModel):
    port: int
    service: str
    packets: int
    bytes: int


class SizeBucket(BaseModel):
    label: str
    count: int


class TrafficStats(BaseModel):
    totalPackets: int = 0
    totalBytes: int = 0
    incomingPackets: int = 0
    outgoingPackets: int = 0
    localPackets: int = 0
    packetsPerSecond: float = 0.0
    bytesPerSecond: float = 0.0
    averagePacketSize: float = 0.0
    protocolDistribution: Dict[str, int] = Field(default_factory=dict)
    topSourceIps: List[IpCountEntry] = Field(default_factory=list)
    topDestinationIps: List[IpCountEntry] = Field(default_factory=list)
    topDevices: List[IpCountEntry] = Field(default_factory=list)
    topPorts: List[PortCountEntry] = Field(default_factory=list)
    tcpFlagDistribution: Dict[str, int] = Field(default_factory=dict)
    packetSizeBuckets: List[SizeBucket] = Field(default_factory=list)
    timeSeries: List[TimeSeriesPoint] = Field(default_factory=list)
    windowSeconds: int = 300


class RiskBreakdown(BaseModel):
    baseScore: int = 0
    volumeFactor: int = 0
    breadthFactor: int = 0
    persistenceFactor: int = 0
    formula: str = ""


class SecurityAlert(BaseModel):
    id: str
    timestamp: str
    epochMs: int
    sourceIp: str
    destinationIp: Optional[str] = None
    category: DetectionCategory
    severity: SeverityLevel
    riskScore: int = 0
    riskBreakdown: RiskBreakdown = Field(default_factory=RiskBreakdown)
    classification: Literal['Heuristic Alert', 'Confirmed Incident'] = 'Heuristic Alert'
    ruleName: str
    summary: str
    evidence: List[str] = Field(default_factory=list)
    recommendedSteps: List[str] = Field(default_factory=list)
    status: IncidentStatus = 'new'
    falsePositive: bool = False
    notes: str = ""
    isSimulated: bool = False
    aiAnalysis: Optional[str] = None


class TerminalEvent(BaseModel):
    id: str
    timestamp: str
    category: Literal[
        'capture', 'packet', 'protocol', 'stats', 'detection',
        'alert', 'forensics', 'ai', 'simulation', 'system'
    ] = 'system'
    severity: Literal['info', 'success', 'warn', 'alert'] = 'info'
    message: str
    isSimulated: bool = False


class CaptureSessionSummary(BaseModel):
    id: str
    interfaceName: str
    mode: str = 'Live TShark'
    startedAt: str
    stoppedAt: Optional[str] = None
    packetCount: int = 0
    byteCount: int = 0
    alertCount: int = 0
    active: bool = False


class CaptureStatusState(BaseModel):
    capturing: bool = False
    activeInterface: str = ""
    captureMode: str = "Stopped"
    activeSession: Optional[CaptureSessionSummary] = None
    packetCount: int = 0
    alertCount: int = 0
    simulationActive: bool = False
    activeScenario: Optional[str] = None


class NetworkDeviceNode(BaseModel):
    ip: str
    category: Literal['gateway', 'server', 'workstation', 'unknown'] = 'unknown'
    isPrivate: bool = False
    packetCount: int = 0
    byteVolume: int = 0
    inboundCount: int = 0
    outboundCount: int = 0
    protocols: List[ProtocolName] = Field(default_factory=list)
    lastSeen: str = ""
    alertCount: int = 0
    maxSeverity: Optional[SeverityLevel] = None
    connectedPeers: List[str] = Field(default_factory=list)


class NetworkEdge(BaseModel):
    id: str
    source: str
    target: str
    packets: int = 0
    bytes: int = 0
    protocols: List[ProtocolName] = Field(default_factory=list)
    hasAlert: bool = False
    lastSeenEpochMs: int = 0


class DetectionThresholds(BaseModel):
    portScanUniquePorts: int = 8
    portScanWindowSec: int = 60
    synSpikeCount: int = 18
    synWindowSec: int = 30
    trafficSpikeMultiplier: float = 3.0
    dnsQueryRateThreshold: int = 15
    connectionFanoutThreshold: int = 12


class AppSettings(BaseModel):
    defaultInterface: str = "Wi-Fi"
    maxPackets: int = 2000
    retentionMinutes: int = 60
    thresholds: DetectionThresholds = Field(default_factory=DetectionThresholds)
    reducedMotion: bool = False
    preferredAiModel: Literal['gemini-3.8-flash', 'gemini-3.1-flash-lite', 'gemini-4-hydrogen', 'gemini-4-neon', 'gemini-4-carbon'] = 'gemini-3.8-flash'
    useHighThinking: bool = True
    geminiApiKey: Optional[str] = None
    hasGeminiApiKey: bool = False


class ForensicTimelineBucket(BaseModel):
    time: str
    packets: int
    bytes: int
    suspicious: int


class ForensicPeerEntry(BaseModel):
    pair: str
    packets: int
    bytes: int
    protocols: List[str]


class ForensicReport(BaseModel):
    id: str
    fileName: str
    fileSize: int
    format: Literal['pcap', 'pcapng']
    analyzedAt: str
    packetCount: int
    totalBytes: int
    durationSec: int
    packets: List[PacketRecord] = Field(default_factory=list)
    stats: TrafficStats
    alerts: List[SecurityAlert] = Field(default_factory=list)
    timeline: List[ForensicTimelineBucket] = Field(default_factory=list)
    topPeers: List[ForensicPeerEntry] = Field(default_factory=list)


class IpIntelResult(BaseModel):
    ip: str
    isPrivate: bool
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    reputationStatus: str = "Unknown"
    reputationNote: str = ""
    sourceLabel: str = "Local Engine"
    cached: bool = False
    lookedUpAt: str
    error: Optional[str] = None


class StartCaptureRequest(BaseModel):
    interfaceName: Optional[str] = None
    interface: Optional[str] = None


class UpdateAlertRequest(BaseModel):
    status: Optional[IncidentStatus] = None
    notes: Optional[str] = None
    falsePositive: Optional[bool] = None
    classification: Optional[Literal['Heuristic Alert', 'Confirmed Incident']] = None
    aiAnalysis: Optional[str] = None


class SimulationRunRequest(BaseModel):
    scenario: Literal[
        'port_scan', 'traffic_spike', 'repeated_connections',
        'dns_anomaly', 'syn_flood_metadata'
    ]


class AiInvestigateRequest(BaseModel):
    alertId: Optional[str] = None
    alert: Optional[SecurityAlert] = None
    model: Optional[str] = 'gemini-4-hydrogen'
    useHighThinking: Optional[bool] = True


class AiVisualRequest(BaseModel):
    alertId: Optional[str] = None
    alert: Optional[SecurityAlert] = None
    imageSize: Optional[Literal['1K', '2K', '4K']] = '1K'


class PcapUploadRequest(BaseModel):
    fileName: str
    base64Data: str
