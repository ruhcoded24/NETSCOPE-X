from collections import defaultdict
from typing import List
import datetime

from app.schemas.packet_schema import (
    PacketRecord, SecurityAlert, DetectionThresholds, RiskBreakdown, SeverityLevel
)


def detect_dns_anomalies(
    packets: List[PacketRecord],
    thresholds: DetectionThresholds,
    now_ms: int
) -> List[SecurityAlert]:
    alerts: List[SecurityAlert] = []
    window_start = now_ms - 60000

    dns_clients = defaultdict(lambda: {
        "queries": set(),
        "query_count": 0,
        "nxdomain_count": 0,
        "maxTs": 0,
        "isSim": False
    })

    for p in packets:
        if p.epochMs < window_start or p.protocol != "DNS":
            continue

        entry = dns_clients[(p.sourceIp, p.isSimulated)]
        if p.epochMs > entry["maxTs"]: entry["maxTs"] = p.epochMs
        entry["isSim"] = p.isSimulated

        if p.dnsQuery:
            entry["queries"].add(p.dnsQuery)
            entry["query_count"] += 1

        if p.dnsResponseCode and p.dnsResponseCode in ("3", "NXDOMAIN"):
            entry["nxdomain_count"] += 1

    for (src_ip, is_sim), data in dns_clients.items():
        if data["query_count"] >= thresholds.dnsQueryRateThreshold:
            base_score = 38
            rate_factor = min(25, round((data["query_count"] / thresholds.dnsQueryRateThreshold) * 12))
            nx_factor = min(15, round((data["nxdomain_count"] / max(1, data["query_count"])) * 20))
            score = min(100, base_score + rate_factor + nx_factor)
            severity: SeverityLevel = 'High' if score >= 68 else 'Medium'

            breakdown = RiskBreakdown(
                baseScore=base_score,
                volumeFactor=rate_factor,
                breadthFactor=len(data["queries"]),
                persistenceFactor=4,
                formula=f"{base_score} (base) + {rate_factor} (query rate {data['query_count']}/min) + {nx_factor} (nxdomain) = {score}/100"
            )

            tag = "[SIMULATED] " if is_sim else ""
            sample_domains = list(data["queries"])[:5]

            alerts.append(SecurityAlert(
                id=f"alt-dns-{data['maxTs']}-{src_ip.replace(':', '_')}",
                timestamp=datetime.datetime.fromtimestamp(data["maxTs"] / 1000.0, tz=datetime.timezone.utc).isoformat(),
                epochMs=data["maxTs"],
                sourceIp=src_ip,
                destinationIp="DNS Server",
                category="dns_anomaly",
                severity=severity,
                riskScore=score,
                riskBreakdown=breakdown,
                classification="Heuristic Alert",
                ruleName=f"{tag}DNS Query Surge & Tunneling Anomaly (DNS-04)",
                summary=f"{tag}Abnormal DNS request frequency: {data['query_count']} queries in 60s from {src_ip} ({data['nxdomain_count']} NXDOMAIN errors).",
                evidence=[
                    f"DNS query count: {data['query_count']} (Threshold: {thresholds.dnsQueryRateThreshold} per min)",
                    f"NXDOMAIN failures: {data['nxdomain_count']}",
                    f"Sample queried domains: {', '.join(sample_domains)}"
                ],
                recommendedSteps=[
                    f"Inspect DNS query entropy on {src_ip} for DNS tunneling or DGA (domain generation algorithms).",
                    "Verify if client machine is infected with beaconing C2 malware.",
                    "Check local DNS resolver logs for client query source identification."
                ],
                status="new",
                falsePositive=False,
                notes="",
                isSimulated=is_sim
            ))

    return alerts


def detect_connection_fanout(
    packets: List[PacketRecord],
    thresholds: DetectionThresholds,
    now_ms: int
) -> List[SecurityAlert]:
    alerts: List[SecurityAlert] = []
    window_start = now_ms - 60000

    fanout = defaultdict(lambda: {"peers": set(), "maxTs": 0, "count": 0, "isSim": False})

    for p in packets:
        if p.epochMs < window_start:
            continue
        entry = fanout[(p.sourceIp, p.isSimulated)]
        if p.epochMs > entry["maxTs"]: entry["maxTs"] = p.epochMs
        entry["isSim"] = p.isSimulated
        entry["peers"].add(p.destinationIp)
        entry["count"] += 1

    for (src_ip, is_sim), data in fanout.items():
        if len(data["peers"]) >= thresholds.connectionFanoutThreshold:
            base_score = 36
            breadth_factor = min(20, round(len(data["peers"]) * 1.5))
            score = min(100, base_score + breadth_factor + 10)
            severity: SeverityLevel = 'High' if score >= 68 else 'Medium'

            breakdown = RiskBreakdown(
                baseScore=base_score,
                volumeFactor=10,
                breadthFactor=breadth_factor,
                persistenceFactor=4,
                formula=f"{base_score} (base) + 10 (volume) + {breadth_factor} (peer breadth {len(data['peers'])}) = {score}/100"
            )

            tag = "[SIMULATED] " if is_sim else ""

            alerts.append(SecurityAlert(
                id=f"alt-fanout-{data['maxTs']}-{src_ip.replace(':', '_')}",
                timestamp=datetime.datetime.fromtimestamp(data["maxTs"] / 1000.0, tz=datetime.timezone.utc).isoformat(),
                epochMs=data["maxTs"],
                sourceIp=src_ip,
                destinationIp=None,
                category="connection_anomaly",
                severity=severity,
                riskScore=score,
                riskBreakdown=breakdown,
                classification="Heuristic Alert",
                ruleName=f"{tag}Lateral Peer Connection Fanout (CON-05)",
                summary=f"{tag}Host {src_ip} initiated connections to {len(data['peers'])} distinct internal endpoints within 60s.",
                evidence=[
                    f"Distinct peers contacted: {len(data['peers'])} (Threshold: {thresholds.connectionFanoutThreshold})",
                    f"Total packets during window: {data['count']}",
                    f"Sample contacted peers: {', '.join(list(data['peers'])[:6])}"
                ],
                recommendedSteps=[
                    f"Examine process list on host {src_ip} for lateral movement tools (psexec, wmic, ssh automation).",
                    "Segment host from sensitive subnets until identity is verified.",
                    "Review authentication logs on target systems for credential spraying."
                ],
                status="new",
                falsePositive=False,
                notes="",
                isSimulated=is_sim
            ))

    return alerts
