import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyProtocol, isPrivateIp } from './protocolClassifier';
import { analyzeTrafficForThreats, calculateRiskScore, DEFAULT_THRESHOLDS } from './detectionEngine';
import { computeTrafficStats, buildNetworkTopology, filterAndSortPackets, packetsToCsv } from './statisticsEngine';
import { generateSamplePcapBuffer, parsePcapBuffer, packetsToPcapBuffer } from './pcapParser';
import type { PacketRecord } from './types';

function makePacket(overrides: Partial<PacketRecord> = {}): PacketRecord {
  const now = 1_760_000_000_000;
  return {
    id: 'pkt-1',
    timestamp: new Date(now).toISOString(),
    epochMs: now,
    sourceIp: '192.168.1.50',
    destinationIp: '10.0.0.10',
    sourcePort: 50001,
    destinationPort: 443,
    protocol: 'HTTPS/TLS',
    transportProtocol: 'TCP',
    size: 512,
    tcpFlags: ['ACK'],
    ttl: 64,
    interfaceName: 'eth1',
    direction: 'outbound',
    isSimulated: false,
    summary: 'HTTPS/TLS packet',
    layerStack: ['Ethernet II', 'IP', 'TCP', 'TLS'],
    ...overrides,
  };
}

test('protocol layering identifies DNS over UDP/53 instead of generic UDP', () => {
  const dns = classifyProtocol({ ipProto: 17, sourcePort: 54122, destinationPort: 53 });
  assert.equal(dns.protocol, 'DNS');
  assert.equal(dns.transportProtocol, 'UDP');
  assert.ok(dns.layerStack.includes('DNS'));

  const https = classifyProtocol({ ipProto: 6, sourcePort: 49200, destinationPort: 443 });
  assert.equal(https.protocol, 'HTTPS/TLS');
  assert.equal(https.transportProtocol, 'TCP');

  const arp = classifyProtocol({ etherType: 0x0806 });
  assert.equal(arp.protocol, 'ARP');
});

test('private IP guard prevents RFC1918 and loopback addresses from geolocation', () => {
  assert.equal(isPrivateIp('10.0.0.1'), true);
  assert.equal(isPrivateIp('192.168.1.15'), true);
  assert.equal(isPrivateIp('172.16.5.9'), true);
  assert.equal(isPrivateIp('127.0.0.1'), true);
  assert.equal(isPrivateIp('::1'), true);
  assert.equal(isPrivateIp('8.8.8.8'), false);
  assert.equal(isPrivateIp('1.1.1.1'), false);
});

test('documented risk score formula produces bounded scores and severities', () => {
  const res = calculateRiskScore('port_scan', 2.0, 14, 12);
  assert.ok(res.score >= 0 && res.score <= 100);
  assert.equal(res.score, 42 + 20 + 18 + 3); // 83
  assert.equal(res.severity, 'High');
  assert.ok(res.breakdown.formula.includes('83/100'));
});

test('detection engine flags port scan and keeps real vs simulated traffic isolated', () => {
  const base = 1_760_000_000_000;
  const ports = [22, 23, 25, 80, 110, 143, 443, 445, 3306, 8080];
  const simPackets: PacketRecord[] = ports.map((dp, i) =>
    makePacket({
      id: `sim-${i}`,
      epochMs: base + i * 500,
      sourceIp: '10.99.0.5',
      destinationIp: '10.99.0.20',
      destinationPort: dp,
      tcpFlags: ['SYN'],
      isSimulated: true,
    }),
  );

  const realPackets: PacketRecord[] = [
    makePacket({ id: 'real-1', epochMs: base + 100, sourceIp: '192.168.1.2', destinationIp: '8.8.8.8', destinationPort: 443, isSimulated: false }),
  ];

  const alerts = analyzeTrafficForThreats([...realPackets, ...simPackets], DEFAULT_THRESHOLDS, [], base + 6000);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].category, 'port_scan');
  assert.equal(alerts[0].isSimulated, true);
  assert.ok(alerts[0].summary.startsWith('[SIMULATED]'));
});

test('statistics engine aggregates protocol counts, topology nodes, filtering, and CSV export', () => {
  const base = 1_760_000_000_000;
  const pkts = [
    makePacket({ id: '1', epochMs: base, protocol: 'DNS', destinationPort: 53, size: 90, direction: 'outbound' }),
    makePacket({ id: '2', epochMs: base + 1000, protocol: 'HTTPS/TLS', destinationPort: 443, size: 1200, direction: 'inbound' }),
    makePacket({ id: '3', epochMs: base + 2000, protocol: 'HTTP', destinationPort: 80, size: 300, direction: 'outbound' }),
  ];

  const stats = computeTrafficStats(pkts, [], 300, base + 3000);
  assert.equal(stats.totalPackets, 3);
  assert.equal(stats.totalBytes, 1590);
  assert.equal(stats.protocolDistribution.DNS, 1);
  assert.equal(stats.protocolDistribution['HTTPS/TLS'], 1);

  const topo = buildNetworkTopology(pkts, []);
  assert.equal(topo.nodes.length, 2);
  assert.equal(topo.edges.length, 1);

  const filtered = filterAndSortPackets(pkts, { protocol: 'DNS' });
  assert.equal(filtered.total, 1);
  assert.equal(filtered.items[0].id, '1');

  const csv = packetsToCsv(pkts);
  assert.ok(csv.includes('source_ip,source_port,destination_ip'));
  assert.ok(csv.includes('192.168.1.50'));
});

test('PCAP binary encoder and parser round-trip packets and detect sample scan', () => {
  const sampleBuf = generateSamplePcapBuffer(1_760_000_000_000);
  const parsed = parsePcapBuffer(sampleBuf, 'lab-pcap');
  assert.equal(parsed.format, 'pcap');
  assert.equal(parsed.packets.length, 26);

  const alerts = analyzeTrafficForThreats(parsed.packets, DEFAULT_THRESHOLDS, [], 1_760_000_030_000);
  assert.ok(alerts.some((a) => a.category === 'port_scan' && a.sourceIp === '172.16.40.99'));

  const reEncoded = packetsToPcapBuffer(parsed.packets.slice(0, 5));
  const reParsed = parsePcapBuffer(reEncoded, 'roundtrip');
  assert.equal(reParsed.packets.length, 5);
  assert.equal(reParsed.packets[0].sourceIp, '192.168.10.24');
});
