import time
from typing import List, Optional, Set

from app.schemas.packet_schema import (
    PacketRecord, SecurityAlert, DetectionThresholds
)
from app.detection.port_scan_detector import detect_port_scans
from app.detection.traffic_spike_detector import detect_traffic_spikes, detect_syn_anomalies
from app.detection.dns_anomaly_detector import detect_dns_anomalies, detect_connection_fanout

DEFAULT_THRESHOLDS = DetectionThresholds()


def analyze_traffic_for_threats(
    packets: List[PacketRecord],
    thresholds: Optional[DetectionThresholds] = None,
    existing_alerts: Optional[List[SecurityAlert]] = None,
    now_ms: Optional[int] = None
) -> List[SecurityAlert]:
    if not packets:
        return []

    th = thresholds or DEFAULT_THRESHOLDS
    now = now_ms or int(time.time() * 1000)
    existing = existing_alerts or []

    # Track alert keys to prevent re-alerting within cooldown window (e.g. 60s)
    existing_keys: Set[str] = set()
    for a in existing:
        if now - a.epochMs < 60000:
            existing_keys.add(f"{a.category}|{a.sourceIp}|{a.isSimulated}")

    new_alerts: List[SecurityAlert] = []

    detectors = [
        detect_port_scans,
        detect_syn_anomalies,
        detect_traffic_spikes,
        detect_dns_anomalies,
        detect_connection_fanout,
    ]

    for det in detectors:
        candidates = det(packets, th, now)
        for cand in candidates:
            cand_key = f"{cand.category}|{cand.sourceIp}|{cand.isSimulated}"
            if cand.isSimulated or cand_key not in existing_keys:
                existing_keys.add(cand_key)
                new_alerts.append(cand)

    return new_alerts


def build_rule_based_investigation(alert: SecurityAlert) -> str:
    """
    Generates a structured, professional SOC analyst incident response narrative
    when external LLM APIs are unavailable or offline.
    """
    rec_bullets = "\n".join([f"- {s}" for s in alert.recommendedSteps])
    ev_bullets = "\n".join([f"- {e}" for e in alert.evidence])

    return f"""### NETSCOPE X SOC FORENSIC INVESTIGATION REPORT
**Incident Identifier:** {alert.id}
**Detection Rule:** {alert.ruleName}
**Severity Level:** {alert.severity} (Calculated Risk Score: {alert.riskScore}/100)
**Classification:** {alert.classification}
**Timestamp (UTC):** {alert.timestamp}

---

#### 1. Executive Summary
The NetScope X detection engine flagged host **{alert.sourceIp}** for **{alert.category.replace('_', ' ').title()}**.
The activity exceeded calibrated detection thresholds with a risk breakdown formula of:
`{alert.riskBreakdown.formula}`.

#### 2. Corroborating Forensic Evidence
{ev_bullets}

#### 3. Threat Assessment & Technical Impact
- **Attacker TTP:** MITRE ATT&CK reconnaissance / discovery or denial-of-service pattern.
- **Target Exposure:** {alert.destinationIp or 'Internal Subnet Broadcast / Multicast Scope'}.
- **Confidence Rating:** High heuristic confidence based on observed network packets and timing analysis.

#### 4. Mandatory Remediation & Containment Actions
{rec_bullets}

#### 5. Investigation Notes
- Automated heuristic analysis confirmed by NetScope X real-time rule engine.
- Analyst review status: **{alert.status.upper()}**.
- False positive status: **{str(alert.falsePositive)}**.
"""
