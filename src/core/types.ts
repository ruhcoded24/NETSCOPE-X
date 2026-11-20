export type ProtocolName =
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'DNS'
  | 'HTTP'
  | 'HTTPS/TLS'
  | 'ARP'
  | 'DHCP'
  | 'OTHER';

export type SeverityLevel = 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';

export type IncidentStatus = 'new' | 'investigating' | 'resolved';

export type DetectionCategory =
  | 'port_scan'
  | 'syn_anomaly'
  | 'traffic_spike'
  | 'dns_anomaly'
  | 'connection_anomaly';

export interface NetworkInterfaceInfo {
  name: string;
  ipv4: string | null;
  ipv6: string | null;
  mac: string | null;
  internal: boolean;
  rxBytes: number;
  txBytes: number;
  rxPackets: number;
  txPackets: number;
  status: 'up' | 'down';
}

export interface PacketRecord {
  id: string;
  timestamp: string;
  epochMs: number;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number | null;
  destinationPort: number | null;
  protocol: ProtocolName;
  transportProtocol: string;
  size: number;
  tcpFlags: string[];
  ttl: number | null;
  interfaceName: string;
  direction: 'inbound' | 'outbound' | 'local';
  isSimulated: boolean;
  summary: string;
  layerStack: string[];
  dnsQuery?: string;
  dnsResponseCode?: string;
  httpMethod?: string;
  httpHost?: string;
  tlsSni?: string;
}

export interface TimeSeriesPoint {
  time: string;
  epochMs: number;
  packets: number;
  bytes: number;
  inboundBytes: number;
  outboundBytes: number;
  alerts: number;
}

export interface IpCountEntry {
  ip: string;
  packets: number;
  bytes: number;
}

export interface PortCountEntry {
  port: number;
  service: string;
  packets: number;
  bytes: number;
}

export interface TrafficStats {
  totalPackets: number;
  totalBytes: number;
  incomingPackets: number;
  outgoingPackets: number;
  localPackets: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  averagePacketSize: number;
  protocolDistribution: Record<ProtocolName, number>;
  topSourceIps: IpCountEntry[];
  topDestinationIps: IpCountEntry[];
  topDevices: IpCountEntry[];
  topPorts: PortCountEntry[];
  tcpFlagDistribution: Record<string, number>;
  packetSizeBuckets: { label: string; count: number }[];
  timeSeries: TimeSeriesPoint[];
  windowSeconds: number;
}

export interface RiskBreakdown {
  baseScore: number;
  volumeFactor: number;
  breadthFactor: number;
  persistenceFactor: number;
  formula: string;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  epochMs: number;
  sourceIp: string;
  destinationIp: string | null;
  category: DetectionCategory;
  severity: SeverityLevel;
  riskScore: number;
  riskBreakdown: RiskBreakdown;
  classification: 'Heuristic Alert' | 'Confirmed Incident';
  ruleName: string;
  summary: string;
  evidence: string[];
  recommendedSteps: string[];
  status: IncidentStatus;
  falsePositive: boolean;
  notes: string;
  isSimulated: boolean;
  aiAnalysis?: string;
}

export interface DetectionThresholds {
  portScanUniquePorts: number;
  portScanWindowSec: number;
  synSpikeCount: number;
  synWindowSec: number;
  trafficSpikeMultiplier: number;
  dnsQueryRateThreshold: number;
  connectionFanoutThreshold: number;
}

export type DeviceCategory = 'gateway' | 'server' | 'workstation' | 'unknown';

export interface NetworkDeviceNode {
  ip: string;
  category: DeviceCategory;
  isPrivate: boolean;
  packetCount: number;
  byteVolume: number;
  inboundCount: number;
  outboundCount: number;
  protocols: ProtocolName[];
  lastSeen: string;
  alertCount: number;
  maxSeverity: SeverityLevel | null;
  connectedPeers: string[];
}

export interface NetworkEdge {
  id: string;
  source: string;
  target: string;
  packets: number;
  bytes: number;
  protocols: ProtocolName[];
  hasAlert: boolean;
  lastSeenEpochMs: number;
}

export interface TerminalEvent {
  id: string;
  timestamp: string;
  category:
    | 'capture'
    | 'packet'
    | 'protocol'
    | 'stats'
    | 'detection'
    | 'alert'
    | 'forensics'
    | 'ai'
    | 'simulation'
    | 'system';
  severity: 'info' | 'success' | 'warn' | 'alert';
  message: string;
  isSimulated: boolean;
}

export interface CaptureSessionSummary {
  id: string;
  interfaceName: string;
  mode: string;
  startedAt: string;
  stoppedAt: string | null;
  packetCount: number;
  byteCount: number;
  alertCount: number;
  active: boolean;
}

export interface ForensicTimelineBucket {
  time: string;
  packets: number;
  bytes: number;
  suspicious: number;
}

export interface ForensicReport {
  id: string;
  fileName: string;
  fileSize: number;
  format: 'pcap' | 'pcapng';
  analyzedAt: string;
  packetCount: number;
  totalBytes: number;
  durationSec: number;
  packets: PacketRecord[];
  stats: TrafficStats;
  alerts: SecurityAlert[];
  timeline: ForensicTimelineBucket[];
  topPeers: { pair: string; packets: number; bytes: number; protocols: string[] }[];
}

export interface IpIntelResult {
  ip: string;
  isPrivate: boolean;
  country: string | null;
  region: string | null;
  city: string | null;
  asn: string | null;
  org: string | null;
  reputationStatus: string;
  reputationNote: string;
  sourceLabel: string;
  cached: boolean;
  lookedUpAt: string;
  error?: string;
}

export interface AppSettings {
  defaultInterface: string;
  maxPackets: number;
  retentionMinutes: number;
  thresholds: DetectionThresholds;
  reducedMotion: boolean;
  preferredAiModel: 'gemini-4-hydrogen' | 'gemini-4-neon' | 'gemini-4-carbon' | 'gemini-3.1-flash-lite';
  useHighThinking: boolean;
}

export type SimulationScenarioId =
  | 'port_scan'
  | 'traffic_spike'
  | 'repeated_connections'
  | 'dns_anomaly'
  | 'syn_flood_metadata';

export interface PacketFilterQuery {
  search?: string;
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: string;
  destinationPort?: string;
  protocol?: ProtocolName | 'ALL';
  minSize?: number;
  maxSize?: number;
  tcpFlag?: string;
  includeSimulated?: boolean;
  onlySimulated?: boolean;
  sortBy?: 'timestamp' | 'size' | 'protocol' | 'sourceIp' | 'destinationIp';
  sortDir?: 'asc' | 'desc';
  page?: number;
  pageSize?: number;
}
