import { getPortServiceName, isPrivateIp } from './protocolClassifier';
import type {
  DeviceCategory,
  IpCountEntry,
  NetworkDeviceNode,
  NetworkEdge,
  PacketFilterQuery,
  PacketRecord,
  PortCountEntry,
  ProtocolName,
  SecurityAlert,
  SeverityLevel,
  TimeSeriesPoint,
  TrafficStats,
} from './types';

const ALL_PROTOCOLS: ProtocolName[] = [
  'TCP',
  'UDP',
  'ICMP',
  'DNS',
  'HTTP',
  'HTTPS/TLS',
  'ARP',
  'DHCP',
  'OTHER',
];

const SEVERITY_RANK: Record<SeverityLevel, number> = {
  Informational: 1,
  Low: 2,
  Medium: 3,
  High: 4,
  Critical: 5,
};

export function computeTrafficStats(
  packets: PacketRecord[],
  alerts: SecurityAlert[],
  windowSeconds = 300,
  nowMs = Date.now(),
): TrafficStats {
  const cutoff = windowSeconds > 0 ? nowMs - windowSeconds * 1000 : 0;
  const scoped = cutoff > 0 ? packets.filter((p) => p.epochMs >= cutoff) : packets;
  const scopedAlerts = cutoff > 0 ? alerts.filter((a) => a.epochMs >= cutoff) : alerts;

  const protocolDistribution: Record<ProtocolName, number> = {
    TCP: 0,
    UDP: 0,
    ICMP: 0,
    DNS: 0,
    HTTP: 0,
    'HTTPS/TLS': 0,
    ARP: 0,
    DHCP: 0,
    OTHER: 0,
  };

  let totalBytes = 0;
  let incomingPackets = 0;
  let outgoingPackets = 0;
  let localPackets = 0;

  const srcMap = new Map<string, { packets: number; bytes: number }>();
  const dstMap = new Map<string, { packets: number; bytes: number }>();
  const devMap = new Map<string, { packets: number; bytes: number }>();
  const portMap = new Map<number, { packets: number; bytes: number }>();
  const tcpFlagDistribution: Record<string, number> = {};

  const sizeBuckets = [
    { label: '0-127 B', min: 0, max: 127, count: 0 },
    { label: '128-511 B', min: 128, max: 511, count: 0 },
    { label: '512-1023 B', min: 512, max: 1023, count: 0 },
    { label: '1024-1500 B', min: 1024, max: 1500, count: 0 },
    { label: '1500+ B', min: 1501, max: Number.MAX_SAFE_INTEGER, count: 0 },
  ];

  let minEpoch = Number.MAX_SAFE_INTEGER;
  let maxEpoch = 0;

  for (const pkt of scoped) {
    totalBytes += pkt.size;
    if (pkt.epochMs < minEpoch) minEpoch = pkt.epochMs;
    if (pkt.epochMs > maxEpoch) maxEpoch = pkt.epochMs;

    protocolDistribution[pkt.protocol] = (protocolDistribution[pkt.protocol] ?? 0) + 1;

    if (pkt.direction === 'inbound') incomingPackets++;
    else if (pkt.direction === 'outbound') outgoingPackets++;
    else localPackets++;

    const srcCur = srcMap.get(pkt.sourceIp) ?? { packets: 0, bytes: 0 };
    srcCur.packets += 1;
    srcCur.bytes += pkt.size;
    srcMap.set(pkt.sourceIp, srcCur);

    const dstCur = dstMap.get(pkt.destinationIp) ?? { packets: 0, bytes: 0 };
    dstCur.packets += 1;
    dstCur.bytes += pkt.size;
    dstMap.set(pkt.destinationIp, dstCur);

    for (const ip of [pkt.sourceIp, pkt.destinationIp]) {
      const devCur = devMap.get(ip) ?? { packets: 0, bytes: 0 };
      devCur.packets += 1;
      devCur.bytes += pkt.size;
      devMap.set(ip, devCur);
    }

    if (pkt.destinationPort !== null && pkt.destinationPort > 0) {
      const pCur = portMap.get(pkt.destinationPort) ?? { packets: 0, bytes: 0 };
      pCur.packets += 1;
      pCur.bytes += pkt.size;
      portMap.set(pkt.destinationPort, pCur);
    }

    for (const flag of pkt.tcpFlags) {
      tcpFlagDistribution[flag] = (tcpFlagDistribution[flag] ?? 0) + 1;
    }

    for (const bucket of sizeBuckets) {
      if (pkt.size >= bucket.min && pkt.size <= bucket.max) {
        bucket.count += 1;
        break;
      }
    }
  }

  const totalPackets = scoped.length;
  const elapsedSec =
    totalPackets > 1 && maxEpoch > minEpoch
      ? Math.max(1, (maxEpoch - minEpoch) / 1000)
      : Math.max(1, Math.min(windowSeconds || 60, 60));

  const sortIpEntries = (m: Map<string, { packets: number; bytes: number }>): IpCountEntry[] =>
    Array.from(m.entries())
      .map(([ip, v]) => ({ ip, packets: v.packets, bytes: v.bytes }))
      .sort((a, b) => b.packets - a.packets)
      .slice(0, 10);

  const topPorts: PortCountEntry[] = Array.from(portMap.entries())
    .map(([port, v]) => ({
      port,
      service: getPortServiceName(port),
      packets: v.packets,
      bytes: v.bytes,
    }))
    .sort((a, b) => b.packets - a.packets)
    .slice(0, 10);

  // Build 16-slot time series over observed span or last 60 seconds
  const bucketCount = 16;
  const spanMs =
    totalPackets > 1 && maxEpoch > minEpoch
      ? Math.max(16000, maxEpoch - minEpoch)
      : (windowSeconds > 0 ? Math.min(windowSeconds, 120) : 60) * 1000;
  const endMs = totalPackets > 0 ? Math.max(maxEpoch, nowMs) : nowMs;
  const startMs = endMs - spanMs;
  const stepMs = spanMs / bucketCount;

  const series: TimeSeriesPoint[] = Array.from({ length: bucketCount }, (_, i) => {
    const slotEpoch = Math.round(startMs + (i + 1) * stepMs);
    const d = new Date(slotEpoch);
    const label = d.toISOString().slice(11, 19);
    return {
      time: label,
      epochMs: slotEpoch,
      packets: 0,
      bytes: 0,
      inboundBytes: 0,
      outboundBytes: 0,
      alerts: 0,
    };
  });

  for (const pkt of scoped) {
    const idx = Math.min(
      bucketCount - 1,
      Math.max(0, Math.floor((pkt.epochMs - startMs) / stepMs)),
    );
    const slot = series[idx];
    slot.packets += 1;
    slot.bytes += pkt.size;
    if (pkt.direction === 'inbound') slot.inboundBytes += pkt.size;
    else slot.outboundBytes += pkt.size;
  }

  for (const alert of scopedAlerts) {
    const idx = Math.min(
      bucketCount - 1,
      Math.max(0, Math.floor((alert.epochMs - startMs) / stepMs)),
    );
    series[idx].alerts += 1;
  }

  return {
    totalPackets,
    totalBytes,
    incomingPackets,
    outgoingPackets,
    localPackets,
    packetsPerSecond: Number((totalPackets / elapsedSec).toFixed(2)),
    bytesPerSecond: Number((totalBytes / elapsedSec).toFixed(1)),
    averagePacketSize: totalPackets > 0 ? Math.round(totalBytes / totalPackets) : 0,
    protocolDistribution,
    topSourceIps: sortIpEntries(srcMap),
    topDestinationIps: sortIpEntries(dstMap),
    topDevices: sortIpEntries(devMap),
    topPorts,
    tcpFlagDistribution,
    packetSizeBuckets: sizeBuckets.map(({ label, count }) => ({ label, count })),
    timeSeries: series,
    windowSeconds,
  };
}

function inferDeviceCategory(ip: string, protocols: Set<ProtocolName>, portsSeen: Set<number>): DeviceCategory {
  if (ip === '127.0.0.1' || ip === '::1') return 'workstation';
  if (ip.endsWith('.1') || ip.endsWith('.254')) return 'gateway';
  if (
    portsSeen.has(53) ||
    portsSeen.has(80) ||
    portsSeen.has(443) ||
    portsSeen.has(3000) ||
    portsSeen.has(5432) ||
    protocols.has('DNS')
  ) {
    return isPrivateIp(ip) ? 'server' : 'server';
  }
  if (isPrivateIp(ip)) return 'workstation';
  return 'unknown';
}

export function buildNetworkTopology(
  packets: PacketRecord[],
  alerts: SecurityAlert[],
  protocolFilter: ProtocolName | 'ALL' = 'ALL',
): { nodes: NetworkDeviceNode[]; edges: NetworkEdge[] } {
  const filtered =
    protocolFilter === 'ALL' ? packets : packets.filter((p) => p.protocol === protocolFilter);

  const nodeMap = new Map<
    string,
    {
      packetCount: number;
      byteVolume: number;
      inboundCount: number;
      outboundCount: number;
      protocols: Set<ProtocolName>;
      ports: Set<number>;
      lastEpoch: number;
      lastSeen: string;
      peers: Set<string>;
    }
  >();

  const edgeMap = new Map<
    string,
    {
      source: string;
      target: string;
      packets: number;
      bytes: number;
      protocols: Set<ProtocolName>;
      lastSeenEpochMs: number;
    }
  >();

  for (const pkt of filtered) {
    const ensure = (ip: string) => {
      let entry = nodeMap.get(ip);
      if (!entry) {
        entry = {
          packetCount: 0,
          byteVolume: 0,
          inboundCount: 0,
          outboundCount: 0,
          protocols: new Set<ProtocolName>(),
          ports: new Set<number>(),
          lastEpoch: 0,
          lastSeen: pkt.timestamp,
          peers: new Set<string>(),
        };
        nodeMap.set(ip, entry);
      }
      return entry;
    };

    const src = ensure(pkt.sourceIp);
    src.packetCount += 1;
    src.byteVolume += pkt.size;
    src.outboundCount += 1;
    src.protocols.add(pkt.protocol);
    if (pkt.sourcePort) src.ports.add(pkt.sourcePort);
    src.peers.add(pkt.destinationIp);
    if (pkt.epochMs >= src.lastEpoch) {
      src.lastEpoch = pkt.epochMs;
      src.lastSeen = pkt.timestamp;
    }

    const dst = ensure(pkt.destinationIp);
    dst.packetCount += 1;
    dst.byteVolume += pkt.size;
    dst.inboundCount += 1;
    dst.protocols.add(pkt.protocol);
    if (pkt.destinationPort) dst.ports.add(pkt.destinationPort);
    dst.peers.add(pkt.sourceIp);
    if (pkt.epochMs >= dst.lastEpoch) {
      dst.lastEpoch = pkt.epochMs;
      dst.lastSeen = pkt.timestamp;
    }

    if (pkt.sourceIp !== pkt.destinationIp) {
      const key = `${pkt.sourceIp}->${pkt.destinationIp}`;
      let edge = edgeMap.get(key);
      if (!edge) {
        edge = {
          source: pkt.sourceIp,
          target: pkt.destinationIp,
          packets: 0,
          bytes: 0,
          protocols: new Set<ProtocolName>(),
          lastSeenEpochMs: pkt.epochMs,
        };
        edgeMap.set(key, edge);
      }
      edge.packets += 1;
      edge.bytes += pkt.size;
      edge.protocols.add(pkt.protocol);
      if (pkt.epochMs > edge.lastSeenEpochMs) edge.lastSeenEpochMs = pkt.epochMs;
    }
  }

  const alertsByIp = new Map<string, { count: number; maxSeverity: SeverityLevel | null }>();
  for (const alert of alerts) {
    for (const ip of [alert.sourceIp, alert.destinationIp]) {
      if (!ip) continue;
      const cur = alertsByIp.get(ip) ?? { count: 0, maxSeverity: null };
      cur.count += 1;
      if (!cur.maxSeverity || SEVERITY_RANK[alert.severity] > SEVERITY_RANK[cur.maxSeverity]) {
        cur.maxSeverity = alert.severity;
      }
      alertsByIp.set(ip, cur);
    }
  }

  const nodes: NetworkDeviceNode[] = Array.from(nodeMap.entries())
    .map(([ip, data]) => {
      const alertInfo = alertsByIp.get(ip);
      return {
        ip,
        category: inferDeviceCategory(ip, data.protocols, data.ports),
        isPrivate: isPrivateIp(ip),
        packetCount: data.packetCount,
        byteVolume: data.byteVolume,
        inboundCount: data.inboundCount,
        outboundCount: data.outboundCount,
        protocols: ALL_PROTOCOLS.filter((p) => data.protocols.has(p)),
        lastSeen: data.lastSeen,
        alertCount: alertInfo?.count ?? 0,
        maxSeverity: alertInfo?.maxSeverity ?? null,
        connectedPeers: Array.from(data.peers),
      };
    })
    .sort((a, b) => b.packetCount - a.packetCount)
    .slice(0, 60);

  const allowedIps = new Set(nodes.map((n) => n.ip));
  const edges: NetworkEdge[] = Array.from(edgeMap.entries())
    .filter(([, e]) => allowedIps.has(e.source) && allowedIps.has(e.target))
    .map(([id, e]) => ({
      id,
      source: e.source,
      target: e.target,
      packets: e.packets,
      bytes: e.bytes,
      protocols: ALL_PROTOCOLS.filter((p) => e.protocols.has(p)),
      hasAlert: (alertsByIp.get(e.source)?.count ?? 0) > 0 || (alertsByIp.get(e.target)?.count ?? 0) > 0,
      lastSeenEpochMs: e.lastSeenEpochMs,
    }))
    .sort((a, b) => b.packets - a.packets)
    .slice(0, 120);

  return { nodes, edges };
}

export function filterAndSortPackets(
  packets: PacketRecord[],
  query: PacketFilterQuery,
): { items: PacketRecord[]; total: number } {
  let result = packets;

  if (query.onlySimulated) {
    result = result.filter((p) => p.isSimulated);
  } else if (query.includeSimulated === false) {
    result = result.filter((p) => !p.isSimulated);
  }

  if (query.protocol && query.protocol !== 'ALL') {
    result = result.filter((p) => p.protocol === query.protocol);
  }

  if (query.sourceIp) {
    const s = query.sourceIp.trim().toLowerCase();
    result = result.filter((p) => p.sourceIp.toLowerCase().includes(s));
  }

  if (query.destinationIp) {
    const d = query.destinationIp.trim().toLowerCase();
    result = result.filter((p) => p.destinationIp.toLowerCase().includes(d));
  }

  if (query.sourcePort) {
    const sp = Number(query.sourcePort);
    if (!Number.isNaN(sp)) result = result.filter((p) => p.sourcePort === sp);
  }

  if (query.destinationPort) {
    const dp = Number(query.destinationPort);
    if (!Number.isNaN(dp)) result = result.filter((p) => p.destinationPort === dp);
  }

  if (query.tcpFlag && query.tcpFlag !== 'ALL') {
    const f = query.tcpFlag.toUpperCase();
    result = result.filter((p) => p.tcpFlags.includes(f));
  }

  if (typeof query.minSize === 'number' && !Number.isNaN(query.minSize)) {
    result = result.filter((p) => p.size >= query.minSize!);
  }

  if (typeof query.maxSize === 'number' && !Number.isNaN(query.maxSize)) {
    result = result.filter((p) => p.size <= query.maxSize!);
  }

  if (query.search) {
    const q = query.search.trim().toLowerCase();
    if (q) {
      result = result.filter(
        (p) =>
          p.sourceIp.toLowerCase().includes(q) ||
          p.destinationIp.toLowerCase().includes(q) ||
          p.protocol.toLowerCase().includes(q) ||
          p.summary.toLowerCase().includes(q) ||
          String(p.sourcePort ?? '').includes(q) ||
          String(p.destinationPort ?? '').includes(q) ||
          (p.dnsQuery ?? '').toLowerCase().includes(q),
      );
    }
  }

  const sortBy = query.sortBy ?? 'timestamp';
  const dir = query.sortDir === 'asc' ? 1 : -1;

  const sorted = [...result].sort((a, b) => {
    if (sortBy === 'size') return (a.size - b.size) * dir;
    if (sortBy === 'protocol') return a.protocol.localeCompare(b.protocol) * dir;
    if (sortBy === 'sourceIp') return a.sourceIp.localeCompare(b.sourceIp) * dir;
    if (sortBy === 'destinationIp') return a.destinationIp.localeCompare(b.destinationIp) * dir;
    return (a.epochMs - b.epochMs) * dir;
  });

  const page = Math.max(1, query.page ?? 1);
  const pageSize = Math.min(200, Math.max(1, query.pageSize ?? 50));
  const offset = (page - 1) * pageSize;

  return {
    items: sorted.slice(offset, offset + pageSize),
    total: sorted.length,
  };
}

export function packetsToCsv(packets: PacketRecord[]): string {
  const header = [
    'id',
    'timestamp',
    'source_ip',
    'source_port',
    'destination_ip',
    'destination_port',
    'protocol',
    'size_bytes',
    'tcp_flags',
    'ttl',
    'interface',
    'direction',
    'simulated',
    'summary',
  ].join(',');

  const escape = (val: string | number | boolean | null | undefined) => {
    const s = val === null || val === undefined ? '' : String(val);
    return `"${s.replace(/"/g, '""')}"`;
  };

  const rows = packets.map((p) =>
    [
      p.id,
      p.timestamp,
      p.sourceIp,
      p.sourcePort ?? '',
      p.destinationIp,
      p.destinationPort ?? '',
      p.protocol,
      p.size,
      p.tcpFlags.join('|'),
      p.ttl ?? '',
      p.interfaceName,
      p.direction,
      p.isSimulated,
      p.summary,
    ]
      .map(escape)
      .join(','),
  );

  return [header, ...rows].join('\n');
}
