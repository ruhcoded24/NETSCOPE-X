import type {
  DetectionCategory,
  DetectionThresholds,
  PacketRecord,
  RiskBreakdown,
  SecurityAlert,
  SeverityLevel,
} from './types';

export const DEFAULT_THRESHOLDS: DetectionThresholds = {
  portScanUniquePorts: 8,
  portScanWindowSec: 60,
  synSpikeCount: 18,
  synWindowSec: 30,
  trafficSpikeMultiplier: 3.0,
  dnsQueryRateThreshold: 15,
  connectionFanoutThreshold: 12,
};

const CATEGORY_BASE_WEIGHT: Record<DetectionCategory, number> = {
  port_scan: 42,
  syn_anomaly: 45,
  traffic_spike: 34,
  dns_anomaly: 38,
  connection_anomaly: 36,
};

/**
 * Computes a documented, deterministic risk score (0-100):
 * RiskScore = min(100, round(BaseCategoryWeight + VolumeFactor + BreadthFactor + PersistenceFactor))
 */
export function calculateRiskScore(
  category: DetectionCategory,
  volumeRatio: number,
  breadthCount: number,
  persistenceSec: number,
): { score: number; severity: SeverityLevel; breakdown: RiskBreakdown } {
  const baseScore = CATEGORY_BASE_WEIGHT[category];
  const volumeFactor = Math.min(25, Math.round(Math.max(0, volumeRatio) * 10));
  const breadthFactor = Math.min(20, Math.round(Math.max(0, breadthCount) * 1.25));
  const persistenceFactor = Math.min(13, Math.round(Math.max(0, persistenceSec) / 4));

  const raw = baseScore + volumeFactor + breadthFactor + persistenceFactor;
  const score = Math.max(5, Math.min(100, raw));

  let severity: SeverityLevel = 'Informational';
  if (score >= 85) severity = 'Critical';
  else if (score >= 68) severity = 'High';
  else if (score >= 48) severity = 'Medium';
  else if (score >= 25) severity = 'Low';

  const formula = `${baseScore} (category base) + ${volumeFactor} (volume) + ${breadthFactor} (breadth) + ${persistenceFactor} (persistence) = ${score}/100`;

  return {
    score,
    severity,
    breakdown: {
      baseScore,
      volumeFactor,
      breadthFactor,
      persistenceFactor,
      formula,
    },
  };
}

export function analyzeTrafficForThreats(
  packets: PacketRecord[],
  thresholds: DetectionThresholds = DEFAULT_THRESHOLDS,
  existingAlerts: SecurityAlert[] = [],
  nowMs = Date.now(),
): SecurityAlert[] {
  if (packets.length === 0) return [];

  const generated: SecurityAlert[] = [];
  const existingKeys = new Set(
    existingAlerts.map((a) => `${a.category}|${a.sourceIp}|${a.isSimulated}`),
  );

  // Separate real and simulated traffic so simulated packets never taint real alerts
  const groups: { isSimulated: boolean; items: PacketRecord[] }[] = [
    { isSimulated: false, items: packets.filter((p) => !p.isSimulated) },
    { isSimulated: true, items: packets.filter((p) => p.isSimulated) },
  ];

  for (const group of groups) {
    const items = group.items;
    if (items.length === 0) continue;

    const latestEpoch = items.reduce((m, p) => Math.max(m, p.epochMs), 0) || nowMs;
    const tag = group.isSimulated ? '[SIMULATED] ' : '';

    // 1. Port Scan Detection
    const portWindowStart = latestEpoch - thresholds.portScanWindowSec * 1000;
    const bySourcePorts = new Map<
      string,
      { ports: Set<number>; targets: Set<string>; count: number; minTs: number; maxTs: number }
    >();
    for (const p of items) {
      if (p.epochMs < portWindowStart || p.destinationPort === null) continue;
      let entry = bySourcePorts.get(p.sourceIp);
      if (!entry) {
        entry = {
          ports: new Set<number>(),
          targets: new Set<string>(),
          count: 0,
          minTs: p.epochMs,
          maxTs: p.epochMs,
        };
        bySourcePorts.set(p.sourceIp, entry);
      }
      entry.ports.add(p.destinationPort);
      entry.targets.add(p.destinationIp);
      entry.count += 1;
      entry.minTs = Math.min(entry.minTs, p.epochMs);
      entry.maxTs = Math.max(entry.maxTs, p.epochMs);
    }

    for (const [srcIp, info] of bySourcePorts.entries()) {
      if (info.ports.size >= thresholds.portScanUniquePorts) {
        const dedupeKey = `port_scan|${srcIp}|${group.isSimulated}`;
        if (!existingKeys.has(dedupeKey)) {
          existingKeys.add(dedupeKey);
          const spanSec = Math.max(1, (info.maxTs - info.minTs) / 1000);
          const { score, severity, breakdown } = calculateRiskScore(
            'port_scan',
            info.count / Math.max(1, thresholds.portScanUniquePorts),
            info.ports.size,
            spanSec,
          );
          const samplePorts = Array.from(info.ports)
            .sort((a, b) => a - b)
            .slice(0, 12)
            .join(', ');
          const targetIp = info.targets.size === 1 ? Array.from(info.targets)[0] : null;
          generated.push({
            id: `ALT-PS-${srcIp.replace(/[^a-zA-Z0-9]/g, '')}-${latestEpoch}`,
            timestamp: new Date(info.maxTs).toISOString(),
            epochMs: info.maxTs,
            sourceIp: srcIp,
            destinationIp: targetIp,
            category: 'port_scan',
            severity,
            riskScore: score,
            riskBreakdown: breakdown,
            classification: info.ports.size >= thresholds.portScanUniquePorts * 2 ? 'Confirmed Incident' : 'Heuristic Alert',
            ruleName: 'Multi-Port Enumeration Rule (PS-01)',
            summary: `${tag}Source ${srcIp} probed ${info.ports.size} distinct destination ports within ${thresholds.portScanWindowSec}s.`,
            evidence: [
              `Unique destination ports contacted: ${info.ports.size} (threshold: ${thresholds.portScanUniquePorts})`,
              `Total probe packets observed: ${info.count}`,
              `Sample target ports: ${samplePorts}`,
              `Target hosts contacted: ${Array.from(info.targets).slice(0, 5).join(', ')}`,
            ],
            recommendedSteps: [
              `Verify whether ${srcIp} is an authorized vulnerability scanner or monitoring service.`,
              `Inspect firewall and host logs on target endpoint(s) for accepted vs. refused connections.`,
              `Review if sequential or service-specific ports (22, 80, 443, 3389, 5432) were targeted.`,
            ],
            status: 'new',
            falsePositive: false,
            notes: '',
            isSimulated: group.isSimulated,
          });
        }
      }
    }

    // 2. SYN Flood-Like Behavior Detection
    const synWindowStart = latestEpoch - thresholds.synWindowSec * 1000;
    const synBySource = new Map<string, { synCount: number; synAckCount: number; targets: Set<string>; maxTs: number; minTs: number }>();
    for (const p of items) {
      if (p.epochMs < synWindowStart) continue;
      const hasSyn = p.tcpFlags.includes('SYN');
      const hasAck = p.tcpFlags.includes('ACK');
      if (hasSyn && !hasAck) {
        const cur = synBySource.get(p.sourceIp) ?? { synCount: 0, synAckCount: 0, targets: new Set<string>(), maxTs: p.epochMs, minTs: p.epochMs };
        cur.synCount += 1;
        cur.targets.add(p.destinationIp);
        cur.maxTs = Math.max(cur.maxTs, p.epochMs);
        cur.minTs = Math.min(cur.minTs, p.epochMs);
        synBySource.set(p.sourceIp, cur);
      } else if (hasSyn && hasAck) {
        // Track SYN-ACK completions targeting or returning
        const cur = synBySource.get(p.destinationIp);
        if (cur) cur.synAckCount += 1;
      }
    }

    for (const [srcIp, info] of synBySource.entries()) {
      if (info.synCount >= thresholds.synSpikeCount) {
        const dedupeKey = `syn_anomaly|${srcIp}|${group.isSimulated}`;
        if (!existingKeys.has(dedupeKey)) {
          existingKeys.add(dedupeKey);
          const completionRatio = info.synAckCount / Math.max(1, info.synCount);
          const spanSec = Math.max(1, (info.maxTs - info.minTs) / 1000);
          const { score, severity, breakdown } = calculateRiskScore(
            'syn_anomaly',
            info.synCount / Math.max(1, thresholds.synSpikeCount),
            info.targets.size + (completionRatio < 0.25 ? 8 : 2),
            spanSec,
          );
          generated.push({
            id: `ALT-SYN-${srcIp.replace(/[^a-zA-Z0-9]/g, '')}-${latestEpoch}`,
            timestamp: new Date(info.maxTs).toISOString(),
            epochMs: info.maxTs,
            sourceIp: srcIp,
            destinationIp: Array.from(info.targets)[0] ?? null,
            category: 'syn_anomaly',
            severity,
            riskScore: score,
            riskBreakdown: breakdown,
            classification: 'Heuristic Alert',
            ruleName: 'Half-Open SYN Burst Heuristic (SYN-02)',
            summary: `${tag}Elevated unacknowledged TCP SYN burst (${info.synCount} SYNs in ${thresholds.synWindowSec}s) from ${srcIp}.`,
            evidence: [
              `SYN packets without ACK: ${info.synCount} (threshold: ${thresholds.synSpikeCount})`,
              `Observed SYN-ACK responses: ${info.synAckCount} (completion ratio: ${(completionRatio * 100).toFixed(1)}%)`,
              `Target IP(s): ${Array.from(info.targets).slice(0, 4).join(', ')}`,
            ],
            recommendedSteps: [
              `Check target server SYN backlog queue (` + '`ss -s` or `netstat -an | grep SYN_RECV`' + `) before concluding an attack.`,
              `Verify whether application retry storms or firewall packet drops explain missing SYN-ACKs.`,
              `Inspect SYN cookies and rate-limiting status on the edge gateway.`,
            ],
            status: 'new',
            falsePositive: false,
            notes: '',
            isSimulated: group.isSimulated,
          });
        }
      }
    }

    // 3. Traffic Spike Detection (comparing recent 5s rate vs prior baseline)
    const recentWindowMs = 5000;
    const recentPackets = items.filter((p) => p.epochMs >= latestEpoch - recentWindowMs);
    const baselinePackets = items.filter((p) => p.epochMs < latestEpoch - recentWindowMs);
    if (baselinePackets.length >= 10 && recentPackets.length >= 15) {
      const baselineMin = baselinePackets.reduce((m, p) => Math.min(m, p.epochMs), Number.MAX_SAFE_INTEGER);
      const baselineSpanSec = Math.max(5, (latestEpoch - recentWindowMs - baselineMin) / 1000);
      const baselinePps = baselinePackets.length / baselineSpanSec;
      const recentPps = recentPackets.length / 5;
      const ratio = recentPps / Math.max(0.5, baselinePps);

      if (ratio >= thresholds.trafficSpikeMultiplier) {
        const topSrc = recentPackets.reduce((acc, p) => {
          acc.set(p.sourceIp, (acc.get(p.sourceIp) ?? 0) + 1);
          return acc;
        }, new Map<string, number>());
        const primaryIp = Array.from(topSrc.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '0.0.0.0';
        const dedupeKey = `traffic_spike|${primaryIp}|${group.isSimulated}`;
        if (!existingKeys.has(dedupeKey)) {
          existingKeys.add(dedupeKey);
          const recentBytes = recentPackets.reduce((s, p) => s + p.size, 0);
          const { score, severity, breakdown } = calculateRiskScore(
            'traffic_spike',
            ratio,
            topSrc.size,
            5,
          );
          generated.push({
            id: `ALT-SPK-${primaryIp.replace(/[^a-zA-Z0-9]/g, '')}-${latestEpoch}`,
            timestamp: new Date(latestEpoch).toISOString(),
            epochMs: latestEpoch,
            sourceIp: primaryIp,
            destinationIp: null,
            category: 'traffic_spike',
            severity,
            riskScore: score,
            riskBreakdown: breakdown,
            classification: 'Heuristic Alert',
            ruleName: 'Bandwidth & Packet-Rate Surge Rule (VOL-03)',
            summary: `${tag}Packet rate spiked ${ratio.toFixed(1)}x above baseline (${recentPps.toFixed(1)} pkt/s vs ${baselinePps.toFixed(1)} pkt/s), led by ${primaryIp}.`,
            evidence: [
              `Recent 5s rate: ${recentPps.toFixed(1)} pkt/s (${recentPackets.length} packets, ${recentBytes} bytes)`,
              `Baseline rate: ${baselinePps.toFixed(1)} pkt/s (multiplier threshold: ${thresholds.trafficSpikeMultiplier}x)`,
              `Primary contributor: ${primaryIp}`,
            ],
            recommendedSteps: [
              `Check whether scheduled backups, software updates, or large file transfers account for the burst.`,
              `Inspect protocol breakdown during the spike window in Protocol Intelligence.`,
            ],
            status: 'new',
            falsePositive: false,
            notes: '',
            isSimulated: group.isSimulated,
          });
        }
      }
    }

    // 4. DNS Anomaly Detection
    const dnsBySource = new Map<string, { count: number; queries: Map<string, number>; nxdomain: number; maxTs: number; minTs: number }>();
    for (const p of items) {
      if (p.protocol !== 'DNS') continue;
      const cur = dnsBySource.get(p.sourceIp) ?? {
        count: 0,
        queries: new Map<string, number>(),
        nxdomain: 0,
        maxTs: p.epochMs,
        minTs: p.epochMs,
      };
      cur.count += 1;
      if (p.dnsQuery) cur.queries.set(p.dnsQuery, (cur.queries.get(p.dnsQuery) ?? 0) + 1);
      if (p.dnsResponseCode === 'NXDOMAIN') cur.nxdomain += 1;
      cur.maxTs = Math.max(cur.maxTs, p.epochMs);
      cur.minTs = Math.min(cur.minTs, p.epochMs);
      dnsBySource.set(p.sourceIp, cur);
    }

    for (const [srcIp, info] of dnsBySource.entries()) {
      if (info.count >= thresholds.dnsQueryRateThreshold || info.nxdomain >= 5) {
        const dedupeKey = `dns_anomaly|${srcIp}|${group.isSimulated}`;
        if (!existingKeys.has(dedupeKey)) {
          existingKeys.add(dedupeKey);
          const spanSec = Math.max(1, (info.maxTs - info.minTs) / 1000);
          const uniqueDomains = info.queries.size;
          const topDomains = Array.from(info.queries.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 4)
            .map(([d, c]) => `${d} (${c}x)`)
            .join(', ');
          const { score, severity, breakdown } = calculateRiskScore(
            'dns_anomaly',
            info.count / Math.max(1, thresholds.dnsQueryRateThreshold),
            uniqueDomains + info.nxdomain,
            spanSec,
          );
          generated.push({
            id: `ALT-DNS-${srcIp.replace(/[^a-zA-Z0-9]/g, '')}-${latestEpoch}`,
            timestamp: new Date(info.maxTs).toISOString(),
            epochMs: info.maxTs,
            sourceIp: srcIp,
            destinationIp: null,
            category: 'dns_anomaly',
            severity,
            riskScore: score,
            riskBreakdown: breakdown,
            classification: 'Heuristic Alert',
            ruleName: 'DNS Query Burst & NXDOMAIN Rule (DNS-04)',
            summary: `${tag}High DNS query frequency (${info.count} queries, ${info.nxdomain} NXDOMAIN) from ${srcIp}.`,
            evidence: [
              `DNS packets observed: ${info.count} (threshold: ${thresholds.dnsQueryRateThreshold})`,
              `NXDOMAIN responses: ${info.nxdomain}`,
              `Unique domains queried: ${uniqueDomains}${topDomains ? ` · Top: ${topDomains}` : ''}`,
            ],
            recommendedSteps: [
              `Examine domain names for high-entropy DGA strings or long subdomain labels (possible DNS tunneling).`,
              `Confirm whether a misconfigured service is polling an expired internal hostname.`,
            ],
            status: 'new',
            falsePositive: false,
            notes: '',
            isSimulated: group.isSimulated,
          });
        }
      }
    }

    // 5. Connection Anomaly Detection (excessive peer fanout)
    const fanoutMap = new Map<string, { peers: Set<string>; ports: Set<number>; count: number; maxTs: number; minTs: number }>();
    for (const p of items) {
      const cur = fanoutMap.get(p.sourceIp) ?? {
        peers: new Set<string>(),
        ports: new Set<number>(),
        count: 0,
        maxTs: p.epochMs,
        minTs: p.epochMs,
      };
      cur.peers.add(p.destinationIp);
      if (p.destinationPort !== null) cur.ports.add(p.destinationPort);
      cur.count += 1;
      cur.maxTs = Math.max(cur.maxTs, p.epochMs);
      cur.minTs = Math.min(cur.minTs, p.epochMs);
      fanoutMap.set(p.sourceIp, cur);
    }

    for (const [srcIp, info] of fanoutMap.entries()) {
      if (info.peers.size >= thresholds.connectionFanoutThreshold) {
        const dedupeKey = `connection_anomaly|${srcIp}|${group.isSimulated}`;
        if (!existingKeys.has(dedupeKey)) {
          existingKeys.add(dedupeKey);
          const spanSec = Math.max(1, (info.maxTs - info.minTs) / 1000);
          const { score, severity, breakdown } = calculateRiskScore(
            'connection_anomaly',
            info.count / Math.max(1, thresholds.connectionFanoutThreshold),
            info.peers.size,
            spanSec,
          );
          generated.push({
            id: `ALT-CON-${srcIp.replace(/[^a-zA-Z0-9]/g, '')}-${latestEpoch}`,
            timestamp: new Date(info.maxTs).toISOString(),
            epochMs: info.maxTs,
            sourceIp: srcIp,
            destinationIp: null,
            category: 'connection_anomaly',
            severity,
            riskScore: score,
            riskBreakdown: breakdown,
            classification: 'Heuristic Alert',
            ruleName: 'Lateral Peer Fanout Anomaly (CON-05)',
            summary: `${tag}Endpoint ${srcIp} initiated connections to ${info.peers.size} unique destination peers across ${info.ports.size} ports.`,
            evidence: [
              `Unique peer IPs contacted: ${info.peers.size} (threshold: ${thresholds.connectionFanoutThreshold})`,
              `Distinct destination ports: ${info.ports.size}`,
              `Sample peers: ${Array.from(info.peers).slice(0, 6).join(', ')}`,
            ],
            recommendedSteps: [
              `Verify whether ${srcIp} is an orchestrator, load balancer, or proxy expected to fan out across subnets.`,
              `Check for unauthorized lateral discovery or peer-to-peer beacon activity.`,
            ],
            status: 'new',
            falsePositive: false,
            notes: '',
            isSimulated: group.isSimulated,
          });
        }
      }
    }
  }

  return generated;
}

/**
 * Deterministic rule-based forensic investigation generator used when Gemini AI
 * is unavailable or not configured, ensuring full offline resilience.
 */
export function buildRuleBasedInvestigation(alert: SecurityAlert): string {
  return [
    `1. What Was Observed`,
    `${alert.summary} Classification: ${alert.classification} (${alert.severity}, Risk Score ${alert.riskScore}/100).`,
    ``,
    `2. Why the Detection Engine Flagged It`,
    `Triggered rule "${alert.ruleName}" under category "${alert.category}". Deterministic score breakdown: ${alert.riskBreakdown.formula}.`,
    ``,
    `3. Supporting Evidence`,
    ...alert.evidence.map((e) => `- ${e}`),
    ``,
    `4. Involved Endpoints`,
    `- Source IP: ${alert.sourceIp}`,
    `- Target IP: ${alert.destinationIp ?? 'Multiple / Broadcast'}`,
    ``,
    `5. Possible Explanations & False-Positive Context`,
    alert.category === 'port_scan'
      ? `Could indicate automated service discovery, Nmap/vulnerability scanning, or legitimate health-check probing across ports.`
      : alert.category === 'syn_anomaly'
      ? `Could reflect half-open connection stress, aggressive client retries against a filtered port, or asymmetric routing where SYN-ACKs bypass this interface.`
      : alert.category === 'dns_anomaly'
      ? `Could indicate a misconfigured service polling a non-existent domain (NXDOMAIN loop), CDN lookup burst, or scripted DNS enumeration.`
      : alert.category === 'traffic_spike'
      ? `Could result from scheduled bulk transfers, CI/CD artifact downloads, or an unusual traffic burst from a single peer.`
      : `Could represent normal orchestrator/mesh peer discovery or unauthorized horizontal scanning across adjacent hosts.`,
    ``,
    `6. Recommended Next Steps (Read-Only Triage)`,
    ...alert.recommendedSteps.map((s, idx) => `${idx + 1}. ${s}`),
  ].join('\n');
}
