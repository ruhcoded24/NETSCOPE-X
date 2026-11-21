import os from 'node:os';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';
import { spawn, type ChildProcess } from 'node:child_process';
import { classifyProtocol, getPortServiceName } from '../core/protocolClassifier.ts';
import { analyzeTrafficForThreats, DEFAULT_THRESHOLDS } from '../core/detectionEngine.ts';
import { buildNetworkTopology, computeTrafficStats } from '../core/statisticsEngine.ts';
import type {
  AppSettings,
  CaptureSessionSummary,
  NetworkInterfaceInfo,
  PacketRecord,
  SecurityAlert,
  SimulationScenarioId,
  TerminalEvent,
} from '../core/types.ts';

function parseHexIpv4(hexIp: string): string {
  if (hexIp.length !== 8) return hexIp;
  const b4 = parseInt(hexIp.slice(0, 2), 16);
  const b3 = parseInt(hexIp.slice(2, 4), 16);
  const b2 = parseInt(hexIp.slice(4, 6), 16);
  const b1 = parseInt(hexIp.slice(6, 8), 16);
  return `${b1}.${b2}.${b3}.${b4}`;
}

function parseHexIpv6(hexIp: string): string {
  if (hexIp.length !== 32) return hexIp;
  if (hexIp === '00000000000000000000000000000000') return '::';
  if (hexIp === '00000000000000000000000000000001') return '::1';
  if (hexIp.startsWith('0000000000000000FFFF0000')) {
    return parseHexIpv4(hexIp.slice(24));
  }
  const groups: string[] = [];
  for (let w = 0; w < 32; w += 8) {
    const word = hexIp.slice(w, w + 8);
    // /proc/net/tcp6 stores each 32-bit word in host (little-endian) byte order
    const be = word.slice(6, 8) + word.slice(4, 6) + word.slice(2, 4) + word.slice(0, 2);
    groups.push(parseInt(be.slice(0, 4), 16).toString(16));
    groups.push(parseInt(be.slice(4, 8), 16).toString(16));
  }
  const joined = groups.join(':');
  return joined.replace(/(^|:)(0:){2,}/, '::');
}

const TCP_STATE_FLAGS: Record<string, string[]> = {
  '01': ['ACK', 'PSH'], // ESTABLISHED
  '02': ['SYN'],        // SYN_SENT
  '03': ['SYN', 'ACK'], // SYN_RECV
  '04': ['FIN', 'ACK'], // FIN_WAIT1
  '05': ['FIN', 'ACK'], // FIN_WAIT2
  '06': ['ACK'],        // TIME_WAIT
  '07': ['RST'],        // CLOSE
  '08': ['FIN'],        // CLOSE_WAIT
  '09': ['FIN', 'ACK'], // LAST_ACK
  '0A': ['SYN'],        // LISTEN
  '0B': ['FIN', 'ACK'], // CLOSING
};

interface ProcNetCounters {
  rxBytes: number;
  txBytes: number;
  rxPackets: number;
  txPackets: number;
}

function readProcNetDev(): Map<string, ProcNetCounters> {
  const map = new Map<string, ProcNetCounters>();
  try {
    const raw = fs.readFileSync('/proc/net/dev', 'utf8');
    const lines = raw.split('\n').slice(2);
    for (const line of lines) {
      const colonIdx = line.indexOf(':');
      if (colonIdx === -1) continue;
      const iface = line.slice(0, colonIdx).trim();
      const nums = line
        .slice(colonIdx + 1)
        .trim()
        .split(/\s+/)
        .map((n) => Number(n));
      if (nums.length >= 10) {
        map.set(iface, {
          rxBytes: nums[0] || 0,
          rxPackets: nums[1] || 0,
          txBytes: nums[8] || 0,
          txPackets: nums[9] || 0,
        });
      }
    }
  } catch {
    // Non-Linux fallback
  }
  return map;
}

export class CaptureService extends EventEmitter {
  private packets: PacketRecord[] = [];
  private alerts: SecurityAlert[] = [];
  private events: TerminalEvent[] = [];
  private sessions: CaptureSessionSummary[] = [];

  private capturing = false;
  private activeInterface = 'eth1';
  private captureMode: 'Raw Socket Probe' | 'ProcNet Kernel Observer' | 'Stopped' = 'Stopped';
  private activeSession: CaptureSessionSummary | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private rawChild: ChildProcess | null = null;
  private prevDevCounters = new Map<string, ProcNetCounters>();
  private seenSocketSnapshots = new Map<string, number>();
  private simTimers: NodeJS.Timeout[] = [];
  private simulationActive = false;
  private activeScenario: string | null = null;
  private seqCounter = 0;

  private settings: AppSettings = {
    defaultInterface: 'eth1',
    maxPackets: 2000,
    retentionMinutes: 60,
    thresholds: { ...DEFAULT_THRESHOLDS },
    reducedMotion: false,
    preferredAiModel: 'gemini-4-hydrogen',
    useHighThinking: true,
  };

  constructor() {
    super();
    const ifaces = this.listInterfaces();
    const preferred = ifaces.find((i) => !i.internal && i.ipv4) ?? ifaces[0];
    if (preferred) {
      this.activeInterface = preferred.name;
      this.settings.defaultInterface = preferred.name;
    }
    this.addEvent('system', 'info', `NETSCOPE X capture engine initialized (${ifaces.length} interfaces discovered).`);
    // Perform an initial passive observation so dashboards start with real host socket state
    this.sampleHostSockets(this.activeInterface, true);
  }

  public listInterfaces(): NetworkInterfaceInfo[] {
    const netMap = os.networkInterfaces();
    const procMap = readProcNetDev();
    const results: NetworkInterfaceInfo[] = [];

    for (const [name, addrs] of Object.entries(netMap)) {
      if (!addrs || addrs.length === 0) continue;
      const v4 = addrs.find((a) => a.family === 'IPv4');
      const v6 = addrs.find((a) => a.family === 'IPv6');
      const counters = procMap.get(name) ?? { rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0 };
      results.push({
        name,
        ipv4: v4?.address ?? null,
        ipv6: v6?.address ?? null,
        mac: v4?.mac ?? v6?.mac ?? null,
        internal: Boolean(v4?.internal ?? v6?.internal),
        rxBytes: counters.rxBytes,
        txBytes: counters.txBytes,
        rxPackets: counters.rxPackets,
        txPackets: counters.txPackets,
        status: 'up',
      });
    }

    return results.sort((a, b) => Number(a.internal) - Number(b.internal));
  }

  public getStatus() {
    return {
      capturing: this.capturing,
      activeInterface: this.activeInterface,
      captureMode: this.captureMode,
      activeSession: this.activeSession,
      packetCount: this.packets.length,
      alertCount: this.alerts.length,
      simulationActive: this.simulationActive,
      activeScenario: this.activeScenario,
    };
  }

  public getSettings(): AppSettings {
    return this.settings;
  }

  public updateSettings(partial: Partial<AppSettings>): AppSettings {
    this.settings = {
      ...this.settings,
      ...partial,
      thresholds: {
        ...this.settings.thresholds,
        ...(partial.thresholds ?? {}),
      },
    };
    this.addEvent('system', 'info', 'Engine configuration and detection thresholds updated.');
    return this.settings;
  }

  public startCapture(interfaceName?: string) {
    const available = this.listInterfaces();
    const targetName = interfaceName || this.activeInterface;
    const found = available.find((i) => i.name === targetName);
    if (!found) {
      throw new Error(`Interface "${targetName}" is unavailable or unauthorized.`);
    }

    if (this.capturing) {
      this.stopCapture();
    }

    this.activeInterface = found.name;
    this.capturing = true;
    this.prevDevCounters = readProcNetDev();

    const now = new Date().toISOString();
    this.activeSession = {
      id: `SES-${Date.now()}`,
      interfaceName: this.activeInterface,
      mode: 'ProcNet Kernel Observer',
      startedAt: now,
      stoppedAt: null,
      packetCount: 0,
      byteCount: 0,
      alertCount: 0,
      active: true,
    };

    // Attempt raw socket probe via Python (non-blocking). If sandbox lacks CAP_NET_RAW, fallback gracefully.
    this.tryStartRawSocketProbe(this.activeInterface);

    this.captureMode = 'ProcNet Kernel Observer';
    this.activeSession.mode = this.captureMode;

    this.addEvent(
      'capture',
      'success',
      `Started live capture on interface ${this.activeInterface} (${found.ipv4 ?? 'no IPv4'}) using ${this.captureMode}.`,
    );

    this.sampleHostSockets(this.activeInterface, false);
    this.pollTimer = setInterval(() => {
      if (this.capturing) {
        this.sampleHostSockets(this.activeInterface, false);
      }
    }, 1500);

    this.emit('status', this.getStatus());
    return this.getStatus();
  }

  private tryStartRawSocketProbe(iface: string) {
    try {
      const pyScript = [
        'import socket, struct, sys',
        's = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))',
        `s.bind((${JSON.stringify(iface)}, 0))`,
        'print("RAW_OK", flush=True)',
        'while True:',
        '  raw, _ = s.recvfrom(65535)',
        '  if len(raw) >= 34:',
        '    eth_proto = struct.unpack("!H", raw[12:14])[0]',
        '    if eth_proto == 0x0800:',
        '      ihl = (raw[14] & 0x0F) * 4',
        '      ttl, proto = raw[22], raw[23]',
        '      src = ".".join(map(str, raw[26:30]))',
        '      dst = ".".join(map(str, raw[30:34]))',
        '      sp, dp, flags = 0, 0, 0',
        '      if proto in (6, 17) and len(raw) >= 14 + ihl + 4:',
        '        sp, dp = struct.unpack("!HH", raw[14+ihl:18+ihl])',
        '      if proto == 6 and len(raw) >= 14 + ihl + 14:',
        '        flags = raw[14+ihl+13]',
        '      print(f"{src}|{dst}|{sp}|{dp}|{proto}|{len(raw)}|{ttl}|{flags}", flush=True)',
      ].join('\n');

      const child = spawn('python3', ['-c', pyScript], { stdio: ['ignore', 'pipe', 'pipe'] });
      this.rawChild = child;

      child.stdout.on('data', (chunk: Buffer) => {
        const lines = chunk.toString('utf8').split('\n').filter(Boolean);
        for (const line of lines) {
          if (line === 'RAW_OK') {
            this.captureMode = 'Raw Socket Probe';
            if (this.activeSession) this.activeSession.mode = 'Raw Socket Probe';
            this.addEvent('capture', 'success', `Elevated AF_PACKET raw socket attached on ${iface}.`);
            this.emit('status', this.getStatus());
            continue;
          }
          const [src, dst, spStr, dpStr, protoStr, lenStr, ttlStr, flagsStr] = line.split('|');
          if (!src || !dst) continue;
          const sp = Number(spStr) || null;
          const dp = Number(dpStr) || null;
          const ipProto = Number(protoStr) || 6;
          const size = Number(lenStr) || 64;
          const ttl = Number(ttlStr) || 64;
          const flagNum = Number(flagsStr) || 0;
          const tcpFlags: string[] = [];
          if (flagNum & 0x01) tcpFlags.push('FIN');
          if (flagNum & 0x02) tcpFlags.push('SYN');
          if (flagNum & 0x04) tcpFlags.push('RST');
          if (flagNum & 0x08) tcpFlags.push('PSH');
          if (flagNum & 0x10) tcpFlags.push('ACK');
          this.ingestObservedPacket({
            sourceIp: src,
            destinationIp: dst,
            sourcePort: sp,
            destinationPort: dp,
            ipProto,
            size,
            ttl,
            tcpFlags,
            interfaceName: iface,
            isSimulated: false,
          });
        }
      });

      child.on('error', () => {
        this.rawChild = null;
      });
      child.on('exit', () => {
        this.rawChild = null;
      });
    } catch {
      this.rawChild = null;
    }
  }

  public stopCapture() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    if (this.rawChild) {
      try {
        this.rawChild.kill('SIGTERM');
      } catch {
        // ignore
      }
      this.rawChild = null;
    }
    const wasCapturing = this.capturing;
    this.capturing = false;
    this.captureMode = 'Stopped';
    if (this.activeSession) {
      this.activeSession.active = false;
      this.activeSession.stoppedAt = new Date().toISOString();
      this.sessions.unshift({ ...this.activeSession });
      if (this.sessions.length > 50) this.sessions.pop();
      this.activeSession = null;
    }
    if (wasCapturing) {
      this.addEvent('capture', 'info', `Stopped capture on interface ${this.activeInterface}.`);
    }
    this.emit('status', this.getStatus());
    return this.getStatus();
  }

  /**
   * Observes real host HTTP/API socket exchanges passing through the Express server
   * so actual dashboard & API traffic appears in the live analyzer stream.
   */
  public recordHttpExchange(remoteIp: string, localIp: string, remotePort: number, localPort: number, bytes: number) {
    if (!this.capturing && this.packets.length > 25) return;
    const cleanRemote = remoteIp.replace(/^::ffff:/, '') || '127.0.0.1';
    const cleanLocal = localIp.replace(/^::ffff:/, '') || '127.0.0.1';
    this.ingestObservedPacket({
      sourceIp: cleanRemote,
      destinationIp: cleanLocal,
      sourcePort: remotePort || 52100,
      destinationPort: localPort || 3000,
      ipProto: 6,
      size: Math.max(64, bytes),
      ttl: 64,
      tcpFlags: ['ACK', 'PSH'],
      interfaceName: this.activeInterface,
      isSimulated: false,
    });
  }

  private sampleHostSockets(ifaceName: string, initialPassive: boolean) {
    const devNow = readProcNetDev();
    const prev = this.prevDevCounters.get(ifaceName);
    const cur = devNow.get(ifaceName);
    const deltaBytes =
      prev && cur ? Math.max(0, cur.rxBytes - prev.rxBytes + (cur.txBytes - prev.txBytes)) : 0;
    this.prevDevCounters = devNow;

    const ifaces = this.listInterfaces();
    const activeIfaceObj = ifaces.find((i) => i.name === ifaceName);
    const hostIp = activeIfaceObj?.ipv4 ?? '127.0.0.1';

    const parseProcTable = (path: string, ipProto: number, isV6: boolean) => {
      try {
        const content = fs.readFileSync(path, 'utf8');
        const lines = content.split('\n').slice(1);
        let emitted = 0;
        for (const line of lines) {
          if (emitted >= (initialPassive ? 10 : 8)) break;
          const parts = line.trim().split(/\s+/);
          if (parts.length < 4) continue;
          const [localHex, remHex, stateHex] = [parts[1], parts[2], parts[3]];
          const [lIpHex, lPortHex] = localHex.split(':');
          const [rIpHex, rPortHex] = remHex.split(':');
          if (!lIpHex || !rIpHex) continue;

          const srcIp = isV6 ? parseHexIpv6(lIpHex) : parseHexIpv4(lIpHex);
          const dstIp = isV6 ? parseHexIpv6(rIpHex) : parseHexIpv4(rIpHex);
          const srcPort = parseInt(lPortHex, 16) || null;
          const dstPort = parseInt(rPortHex, 16) || null;

          // Skip unbound 0.0.0.0:0 listener entries unless active peer
          if (dstIp === '0.0.0.0' || dstIp === '::') continue;

          const snapKey = `${srcIp}:${srcPort}->${dstIp}:${dstPort}:${stateHex}`;
          const lastSeen = this.seenSocketSnapshots.get(snapKey) ?? 0;
          const now = Date.now();
          if (!initialPassive && now - lastSeen < 2500 && deltaBytes === 0) continue;
          this.seenSocketSnapshots.set(snapKey, now);

          const flags = ipProto === 6 ? (TCP_STATE_FLAGS[stateHex] ?? ['ACK']) : [];
          const estSize = deltaBytes > 0 ? Math.min(1480, Math.max(68, Math.round(deltaBytes / 4))) : 128;

          this.ingestObservedPacket({
            sourceIp: srcIp === '0.0.0.0' ? hostIp : srcIp,
            destinationIp: dstIp,
            sourcePort: srcPort,
            destinationPort: dstPort,
            ipProto,
            size: estSize,
            ttl: 64,
            tcpFlags: flags,
            interfaceName: ifaceName,
            isSimulated: false,
          });
          emitted++;
        }
      } catch {
        // Ignore if proc file not present
      }
    };

    parseProcTable('/proc/net/tcp', 6, false);
    parseProcTable('/proc/net/tcp6', 6, true);
    parseProcTable('/proc/net/udp', 17, false);

    // Also inspect ARP neighbors
    try {
      const arpRaw = fs.readFileSync('/proc/net/arp', 'utf8');
      const arpLines = arpRaw.split('\n').slice(1);
      for (const line of arpLines) {
        const cols = line.trim().split(/\s+/);
        if (cols.length >= 6 && cols[0] && cols[5] === ifaceName) {
          const peerIp = cols[0];
          const snapKey = `ARP:${peerIp}`;
          const now = Date.now();
          if (now - (this.seenSocketSnapshots.get(snapKey) ?? 0) > 15_000) {
            this.seenSocketSnapshots.set(snapKey, now);
            this.ingestObservedPacket({
              sourceIp: hostIp,
              destinationIp: peerIp,
              sourcePort: null,
              destinationPort: null,
              etherType: 0x0806,
              size: 42,
              ttl: null,
              tcpFlags: [],
              interfaceName: ifaceName,
              isSimulated: false,
            });
          }
        }
      }
    } catch {
      // Ignore
    }
  }

  public ingestObservedPacket(input: {
    sourceIp: string;
    destinationIp: string;
    sourcePort: number | null;
    destinationPort: number | null;
    ipProto?: number;
    etherType?: number;
    size: number;
    ttl: number | null;
    tcpFlags: string[];
    interfaceName: string;
    isSimulated: boolean;
    dnsQuery?: string;
    dnsResponseCode?: string;
  }): PacketRecord {
    const epochMs = Date.now();
    this.seqCounter += 1;
    const classified = classifyProtocol({
      ipProto: input.ipProto,
      etherType: input.etherType,
      sourcePort: input.sourcePort,
      destinationPort: input.destinationPort,
    });

    const localIps = new Set(
      this.listInterfaces()
        .flatMap((i) => [i.ipv4, i.ipv6])
        .filter((x): x is string => Boolean(x)),
    );
    const srcLocal = localIps.has(input.sourceIp) || input.sourceIp === '127.0.0.1';
    const dstLocal = localIps.has(input.destinationIp) || input.destinationIp === '127.0.0.1';
    const direction: PacketRecord['direction'] =
      srcLocal && dstLocal ? 'local' : srcLocal ? 'outbound' : 'inbound';

    const serviceNote =
      input.destinationPort !== null ? ` (${getPortServiceName(input.destinationPort)})` : '';
    const flagNote = input.tcpFlags.length > 0 ? ` [${input.tcpFlags.join(',')}]` : '';
    const simPrefix = input.isSimulated ? '[SIMULATED] ' : '';

    const pkt: PacketRecord = {
      id: `${input.isSimulated ? 'SIM' : 'PKT'}-${this.seqCounter}-${epochMs}`,
      timestamp: new Date(epochMs).toISOString(),
      epochMs,
      sourceIp: input.sourceIp,
      destinationIp: input.destinationIp,
      sourcePort: input.sourcePort,
      destinationPort: input.destinationPort,
      protocol: classified.protocol,
      transportProtocol: classified.transportProtocol,
      size: input.size,
      tcpFlags: input.tcpFlags,
      ttl: input.ttl,
      interfaceName: input.interfaceName,
      direction,
      isSimulated: input.isSimulated,
      summary: `${simPrefix}${classified.protocol} ${input.sourceIp}${input.sourcePort ? `:${input.sourcePort}` : ''} -> ${input.destinationIp}${input.destinationPort ? `:${input.destinationPort}` : ''}${serviceNote}${flagNote}`,
      layerStack: classified.layerStack,
      dnsQuery: input.dnsQuery,
      dnsResponseCode: input.dnsResponseCode,
    };

    this.packets.push(pkt);
    const maxLen = Math.max(100, this.settings.maxPackets);
    if (this.packets.length > maxLen) {
      this.packets.splice(0, this.packets.length - maxLen);
    }

    if (this.activeSession && !input.isSimulated) {
      this.activeSession.packetCount += 1;
      this.activeSession.byteCount += pkt.size;
    }

    // Run incremental threat detection
    const newAlerts = analyzeTrafficForThreats(
      this.packets,
      this.settings.thresholds,
      this.alerts,
      epochMs,
    );

    for (const alert of newAlerts) {
      this.alerts.unshift(alert);
      if (this.alerts.length > 300) this.alerts.pop();
      if (this.activeSession && !alert.isSimulated) {
        this.activeSession.alertCount += 1;
      }
      this.addEvent(
        'alert',
        alert.severity === 'Critical' || alert.severity === 'High' ? 'alert' : 'warn',
        `${alert.isSimulated ? '[SIMULATED] ' : ''}${alert.ruleName} triggered: ${alert.summary}`,
        alert.isSimulated,
      );
      this.emit('alert', alert);
    }

    this.emit('packet', pkt);
    return pkt;
  }

  public addEvent(
    category: TerminalEvent['category'],
    severity: TerminalEvent['severity'],
    message: string,
    isSimulated = false,
  ): TerminalEvent {
    const evt: TerminalEvent = {
      id: `EVT-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
      category,
      severity,
      message,
      isSimulated,
    };
    this.events.unshift(evt);
    if (this.events.length > 500) this.events.pop();
    this.emit('event', evt);
    return evt;
  }

  public getPackets(includeSimulated = true) {
    return includeSimulated ? this.packets : this.packets.filter((p) => !p.isSimulated);
  }

  public getAlerts(includeSimulated = true) {
    return includeSimulated ? this.alerts : this.alerts.filter((a) => !a.isSimulated);
  }

  public updateAlert(
    id: string,
    patch: Partial<Pick<SecurityAlert, 'status' | 'notes' | 'falsePositive' | 'aiAnalysis' | 'classification'>>,
  ): SecurityAlert | null {
    const target = this.alerts.find((a) => a.id === id);
    if (!target) return null;
    if (patch.status) target.status = patch.status;
    if (typeof patch.notes === 'string') target.notes = patch.notes;
    if (typeof patch.falsePositive === 'boolean') target.falsePositive = patch.falsePositive;
    if (typeof patch.aiAnalysis === 'string') target.aiAnalysis = patch.aiAnalysis;
    if (patch.classification) target.classification = patch.classification;
    this.addEvent('system', 'info', `Incident ${id} updated (status: ${target.status}${target.falsePositive ? ', marked false positive' : ''}).`);
    return target;
  }

  public getStats(windowSeconds = 300, includeSimulated = false) {
    return computeTrafficStats(
      this.getPackets(includeSimulated),
      this.getAlerts(includeSimulated),
      windowSeconds,
    );
  }

  public getTopology(protocolFilter: 'ALL' | PacketRecord['protocol'] = 'ALL', includeSimulated = true) {
    return buildNetworkTopology(
      this.getPackets(includeSimulated),
      this.getAlerts(includeSimulated),
      protocolFilter,
    );
  }

  public getEvents() {
    return this.events;
  }

  public getSessions() {
    return this.activeSession ? [this.activeSession, ...this.sessions] : this.sessions;
  }

  /**
   * Controlled educational simulation lab: generates strictly labeled [SIMULATED] metadata events
   * inside the sandboxed memory stream without transmitting destructive traffic or scanning external hosts.
   */
  public startSimulation(scenario: SimulationScenarioId) {
    this.stopSimulation();
    this.simulationActive = true;
    this.activeScenario = scenario;

    const scenarioLabels: Record<SimulationScenarioId, string> = {
      port_scan: 'Port Scan Pattern Simulation',
      traffic_spike: 'Traffic Volume Spike Simulation',
      repeated_connections: 'Repeated Connection Fanout Simulation',
      dns_anomaly: 'DNS Query Anomaly Simulation',
      syn_flood_metadata: 'SYN Flood-Like Metadata Simulation',
    };

    this.addEvent('simulation', 'warn', `[SIMULATED] Started isolated scenario: ${scenarioLabels[scenario]}.`, true);
    this.emit('status', this.getStatus());

    const labSrc = '10.240.0.99';
    const labDst = '10.240.0.10';

    if (scenario === 'port_scan') {
      const ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080];
      ports.forEach((port, idx) => {
        const t = setTimeout(() => {
          this.ingestObservedPacket({
            sourceIp: labSrc,
            destinationIp: labDst,
            sourcePort: 48000 + idx,
            destinationPort: port,
            ipProto: 6,
            size: 64,
            ttl: 60,
            tcpFlags: ['SYN'],
            interfaceName: 'sim-lab0',
            isSimulated: true,
          });
          if (idx === ports.length - 1) this.finishSimulation(scenarioLabels[scenario]);
        }, idx * 140);
        this.simTimers.push(t);
      });
    } else if (scenario === 'syn_flood_metadata') {
      const count = 24;
      for (let i = 0; i < count; i++) {
        const t = setTimeout(() => {
          this.ingestObservedPacket({
            sourceIp: '10.240.0.88',
            destinationIp: labDst,
            sourcePort: 32000 + i,
            destinationPort: 443,
            ipProto: 6,
            size: 60,
            ttl: 52,
            tcpFlags: ['SYN'],
            interfaceName: 'sim-lab0',
            isSimulated: true,
          });
          if (i === count - 1) this.finishSimulation(scenarioLabels[scenario]);
        }, i * 80);
        this.simTimers.push(t);
      }
    } else if (scenario === 'dns_anomaly') {
      const domains = [
        'a9f3x2k.telemetry-lab.local',
        'b8d1q9z.telemetry-lab.local',
        'c4m7p2w.telemetry-lab.local',
        'd1n8v5r.telemetry-lab.local',
      ];
      const count = 18;
      for (let i = 0; i < count; i++) {
        const t = setTimeout(() => {
          this.ingestObservedPacket({
            sourceIp: '10.240.0.77',
            destinationIp: '10.240.0.2',
            sourcePort: 53000 + i,
            destinationPort: 53,
            ipProto: 17,
            size: 98,
            ttl: 64,
            tcpFlags: [],
            interfaceName: 'sim-lab0',
            isSimulated: true,
            dnsQuery: domains[i % domains.length],
            dnsResponseCode: i % 2 === 0 ? 'NXDOMAIN' : 'NOERROR',
          });
          if (i === count - 1) this.finishSimulation(scenarioLabels[scenario]);
        }, i * 100);
        this.simTimers.push(t);
      }
    } else if (scenario === 'traffic_spike') {
      // Seed light baseline first if needed, then burst
      const count = 32;
      for (let i = 0; i < count; i++) {
        const t = setTimeout(() => {
          this.ingestObservedPacket({
            sourceIp: '10.240.0.66',
            destinationIp: labDst,
            sourcePort: 55000 + i,
            destinationPort: 8080,
            ipProto: 6,
            size: 1460,
            ttl: 64,
            tcpFlags: ['ACK', 'PSH'],
            interfaceName: 'sim-lab0',
            isSimulated: true,
          });
          if (i === count - 1) this.finishSimulation(scenarioLabels[scenario]);
        }, i * 60);
        this.simTimers.push(t);
      }
    } else {
      // repeated_connections
      const count = 16;
      for (let i = 0; i < count; i++) {
        const t = setTimeout(() => {
          this.ingestObservedPacket({
            sourceIp: '10.240.0.55',
            destinationIp: `10.240.1.${10 + i}`,
            sourcePort: 49100 + i,
            destinationPort: 445,
            ipProto: 6,
            size: 148,
            ttl: 64,
            tcpFlags: ['SYN'],
            interfaceName: 'sim-lab0',
            isSimulated: true,
          });
          if (i === count - 1) this.finishSimulation(scenarioLabels[scenario]);
        }, i * 110);
        this.simTimers.push(t);
      }
    }

    return this.getStatus();
  }

  private finishSimulation(label: string) {
    this.simulationActive = false;
    this.activeScenario = null;
    this.addEvent('simulation', 'info', `[SIMULATED] Completed scenario: ${label}.`, true);
    this.emit('status', this.getStatus());
  }

  public stopSimulation() {
    for (const t of this.simTimers) clearTimeout(t);
    this.simTimers = [];
    if (this.simulationActive) {
      this.simulationActive = false;
      this.activeScenario = null;
      this.emit('status', this.getStatus());
    }
  }

  public clearSimulationData() {
    this.stopSimulation();
    this.packets = this.packets.filter((p) => !p.isSimulated);
    this.alerts = this.alerts.filter((a) => !a.isSimulated);
    this.addEvent('simulation', 'info', 'Cleared all [SIMULATED] packets and simulation alerts from workspace.');
    return this.getStatus();
  }

  public shutdown() {
    this.stopCapture();
    this.stopSimulation();
  }
}
