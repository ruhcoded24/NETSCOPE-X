from collections import defaultdict
from typing import List, Optional
import datetime

from app.schemas.packet_schema import (
    PacketRecord, SecurityAlert, DetectionThresholds, RiskBreakdown, SeverityLevel
)

CATEGORY_BASE_WEIGHT = 42


def calculate_port_scan_risk(volume_ratio: float, breadth_count: int, persistence_sec: float):
    base_score = CATEGORY_BASE_WEIGHT
    volume_factor = min(25, round(max(0.0, volume_ratio) * 10))
    breadth_factor = min(20, round(max(0, breadth_count) * 1.25))
    persistence_factor = min(13, round(max(0.0, persistence_sec) / 4))

    raw = base_score + volume_factor + breadth_factor + persistence_factor
    score = max(5, min(100, raw))

    if score >= 85: severity: SeverityLevel = 'Critical'
    elif score >= 68: severity = 'High'
    elif score >= 48: severity = 'Medium'
    elif score >= 25: severity = 'Low'
    else: severity = 'Informational'

    formula = f"{base_score} (category base) + {volume_factor} (volume) + {breadth_factor} (breadth) + {persistence_factor} (persistence) = {score}/100"

    return score, severity, RiskBreakdown(
        baseScore=base_score,
        volumeFactor=volume_factor,
        breadthFactor=breadth_factor,
        persistenceFactor=persistence_factor,
        formula=formula
    )


def detect_port_scans(
    packets: List[PacketRecord],
    thresholds: DetectionThresholds,
    now_ms: int
) -> List[SecurityAlert]:
    alerts: List[SecurityAlert] = []
    window_start = now_ms - (thresholds.portScanWindowSec * 1000)

    # Group by (sourceIp, destinationIp, isSimulated)
    scanners = defaultdict(lambda: {
        "ports": set(),
        "targets": set(),
        "count": 0,
        "minTs": now_ms,
        "maxTs": 0,
        "isSim": False,
        "lastPkt": None
    })

    for p in packets:
        if p.epochMs < window_start or p.destinationPort is None:
            continue
        # Focus on SYN or unestablished probe packets
        is_syn = "SYN" in p.tcpFlags and "ACK" not in p.tcpFlags
        is_udp_probe = p.transportProtocol == "UDP" and p.size <= 128

        if not (is_syn or is_udp_probe or p.isSimulated):
            continue

        entry = scanners[(p.sourceIp, p.isSimulated)]
        entry["ports"].add(p.destinationPort)
        entry["targets"].add(p.destinationIp)
        entry["count"] += 1
        entry["isSim"] = p.isSimulated
        entry["lastPkt"] = p
        if p.epochMs < entry["minTs"]: entry["minTs"] = p.epochMs
        if p.epochMs > entry["maxTs"]: entry["maxTs"] = p.epochMs

    for (src_ip, is_sim), data in scanners.items():
        unique_ports = len(data["ports"])
        if unique_ports >= thresholds.portScanUniquePorts:
            duration_sec = max(1.0, (data["maxTs"] - data["minTs"]) / 1000.0)
            vol_ratio = data["count"] / max(1, thresholds.portScanUniquePorts)
            score, severity, breakdown = calculate_port_scan_risk(vol_ratio, unique_ports, duration_sec)

            tag = "[SIMULATED] " if is_sim else ""
            classification = "Confirmed Incident" if score >= 75 and len(data["targets"]) > 1 else "Heuristic Alert"

            sample_ports = sorted(list(data["ports"]))[:12]
            ports_str = ", ".join(map(str, sample_ports))
            if len(data["ports"]) > 12:
                ports_str += f"... (+{len(data['ports']) - 12} more)"

            alerts.append(SecurityAlert(
                id=f"alt-ps-{data['maxTs']}-{src_ip.replace(':', '_')}",
                timestamp=datetime.datetime.fromtimestamp(data["maxTs"] / 1000.0, tz=datetime.timezone.utc).isoformat(),
                epochMs=data["maxTs"],
                sourceIp=src_ip,
                destinationIp=next(iter(data["targets"])) if len(data["targets"]) == 1 else "Multiple Hosts",
                category="port_scan",
                severity=severity,
                riskScore=score,
                riskBreakdown=breakdown,
                classification=classification,
                ruleName=f"{tag}Sequential Port Scan Enumeration (PS-01)",
                summary=f"{tag}Host {src_ip} probed {unique_ports} unique ports across {len(data['targets'])} target(s) in {round(duration_sec, 1)}s.",
                evidence=[
                    f"Unique ports contacted: {unique_ports} (Threshold: {thresholds.portScanUniquePorts})",
                    f"Sample probed ports: {ports_str}",
                    f"Observation duration: {round(duration_sec, 1)} seconds",
                    f"Probed targets: {', '.join(list(data['targets'])[:5])}"
                ],
                recommendedSteps=[
                    f"Inspect host {src_ip} for unauthorized port-scanning processes or recon scripts.",
                    "Verify if source IP is an authorized vulnerability scanner or external attacker.",
                    "Apply network ingress filtering or temporary firewall drop rule for scanning source."
                ],
                status="new",
                falsePositive=False,
                notes="",
                isSimulated=is_sim
            ))

    return alerts
