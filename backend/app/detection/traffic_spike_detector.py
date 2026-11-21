from collections import defaultdict
from typing import List
import datetime

from app.schemas.packet_schema import (
    PacketRecord, SecurityAlert, DetectionThresholds, RiskBreakdown, SeverityLevel
)


def detect_traffic_spikes(
    packets: List[PacketRecord],
    thresholds: DetectionThresholds,
    now_ms: int
) -> List[SecurityAlert]:
    alerts: List[SecurityAlert] = []
    if len(packets) < 30:
        return alerts

    # Divide recent traffic into baseline (prior 60s) vs surge (last 10s)
    surge_start = now_ms - 10000
    baseline_start = now_ms - 70000

    surge_packets = [p for p in packets if p.epochMs >= surge_start]
    baseline_packets = [p for p in packets if baseline_start <= p.epochMs < surge_start]

    surge_bytes = sum(p.size for p in surge_packets)
    baseline_bytes = sum(p.size for p in baseline_packets)

    baseline_rate = (baseline_bytes / 60.0) if baseline_bytes > 0 else 1000.0
    surge_rate = surge_bytes / 10.0

    multiplier = surge_rate / max(1.0, baseline_rate)

    if multiplier >= thresholds.trafficSpikeMultiplier and surge_bytes > 50000:
        base_score = 34
        vol_factor = min(25, round(multiplier * 3.5))
        score = min(100, base_score + vol_factor + 12)
        severity: SeverityLevel = 'High' if score >= 68 else 'Medium'

        breakdown = RiskBreakdown(
            baseScore=base_score,
            volumeFactor=vol_factor,
            breadthFactor=12,
            persistenceFactor=4,
            formula=f"{base_score} (base) + {vol_factor} (rate multiplier {round(multiplier, 1)}x) + 16 (impact) = {score}/100"
        )

        top_src = defaultdict(int)
        for p in surge_packets:
            top_src[p.sourceIp] += p.size
        hottest_src = max(top_src.keys(), key=lambda k: top_src[k]) if top_src else "Unknown"

        is_sim = any(p.isSimulated for p in surge_packets)
        tag = "[SIMULATED] " if is_sim else ""

        alerts.append(SecurityAlert(
            id=f"alt-spike-{now_ms}",
            timestamp=datetime.datetime.fromtimestamp(now_ms / 1000.0, tz=datetime.timezone.utc).isoformat(),
            epochMs=now_ms,
            sourceIp=hottest_src,
            destinationIp=None,
            category="traffic_spike",
            severity=severity,
            riskScore=score,
            riskBreakdown=breakdown,
            classification="Heuristic Alert",
            ruleName=f"{tag}Bandwidth & Packet-Rate Surge (VOL-03)",
            summary=f"{tag}Sudden traffic surge detected: {round(multiplier, 1)}x baseline bandwidth ({round(surge_rate / 1024, 1)} KB/s).",
            evidence=[
                f"Surge rate: {round(surge_rate / 1024, 1)} KB/s (Baseline: {round(baseline_rate / 1024, 1)} KB/s)",
                f"Spike multiplier: {round(multiplier, 2)}x (Threshold: {thresholds.trafficSpikeMultiplier}x)",
                f"Dominant sender during burst: {hottest_src}"
            ],
            recommendedSteps=[
                "Check for high-bandwidth file transfer, data exfiltration, or streaming services.",
                f"Investigate active connections on dominant sender {hottest_src}.",
                "Monitor interface queue drops and bandwidth utilization."
            ],
            status="new",
            falsePositive=False,
            notes="",
            isSimulated=is_sim
        ))

    return alerts


def detect_syn_anomalies(
    packets: List[PacketRecord],
    thresholds: DetectionThresholds,
    now_ms: int
) -> List[SecurityAlert]:
    alerts: List[SecurityAlert] = []
    window_start = now_ms - (thresholds.synWindowSec * 1000)

    syn_senders = defaultdict(lambda: {"syns": 0, "acks": 0, "targets": set(), "maxTs": 0, "isSim": False})

    for p in packets:
        if p.epochMs < window_start:
            continue
        flags = p.tcpFlags
        entry = syn_senders[(p.sourceIp, p.isSimulated)]
        if p.epochMs > entry["maxTs"]: entry["maxTs"] = p.epochMs
        entry["isSim"] = p.isSimulated
        entry["targets"].add(p.destinationIp)

        if "SYN" in flags and "ACK" not in flags:
            entry["syns"] += 1
        elif "ACK" in flags:
            entry["acks"] += 1

    for (src_ip, is_sim), data in syn_senders.items():
        if data["syns"] >= thresholds.synSpikeCount and data["acks"] < (data["syns"] * 0.25):
            base_score = 45
            unack_ratio = (data["syns"] - data["acks"]) / max(1, data["syns"])
            vol_factor = min(25, round(unack_ratio * 25))
            score = min(100, base_score + vol_factor + 15)
            severity: SeverityLevel = 'Critical' if score >= 85 else 'High'

            breakdown = RiskBreakdown(
                baseScore=base_score,
                volumeFactor=vol_factor,
                breadthFactor=10,
                persistenceFactor=5,
                formula=f"{base_score} (base) + {vol_factor} (half-open ratio {round(unack_ratio, 2)}) + 15 = {score}/100"
            )

            tag = "[SIMULATED] " if is_sim else ""

            alerts.append(SecurityAlert(
                id=f"alt-syn-{data['maxTs']}-{src_ip.replace(':', '_')}",
                timestamp=datetime.datetime.fromtimestamp(data["maxTs"] / 1000.0, tz=datetime.timezone.utc).isoformat(),
                epochMs=data["maxTs"],
                sourceIp=src_ip,
                destinationIp=next(iter(data["targets"])) if len(data["targets"]) == 1 else "Multiple",
                category="syn_anomaly",
                severity=severity,
                riskScore=score,
                riskBreakdown=breakdown,
                classification="Confirmed Incident" if score >= 75 else "Heuristic Alert",
                ruleName=f"{tag}Half-Open SYN Flood Burst Heuristic (SYN-02)",
                summary=f"{tag}High-frequency unacknowledged TCP SYN burst from {src_ip} ({data['syns']} SYNs vs {data['acks']} ACKs).",
                evidence=[
                    f"SYN count in {thresholds.synWindowSec}s window: {data['syns']} (Threshold: {thresholds.synSpikeCount})",
                    f"Matching ACKs observed: {data['acks']}",
                    f"Half-open ratio: {round(unack_ratio * 100, 1)}%",
                    f"Target host(s): {', '.join(list(data['targets'])[:4])}"
                ],
                recommendedSteps=[
                    f"Check firewall state tables for SYN exhaustion against target {', '.join(list(data['targets'])[:2])}.",
                    "Enable TCP SYN cookies on target hosts if not already enabled.",
                    f"Consider rate-limiting or blocking {src_ip} at edge gateway."
                ],
                status="new",
                falsePositive=False,
                notes="",
                isSimulated=is_sim
            ))

    return alerts
