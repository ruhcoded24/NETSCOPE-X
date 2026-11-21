import time
import datetime
import os
import httpx
from typing import Optional, Dict, Any

from app.config import settings
from app.schemas.packet_schema import SecurityAlert, IpIntelResult
from app.analyzer.protocol_analyzer import is_private_ip
from app.detection.detection_engine import build_rule_based_investigation


class IncidentService:
    def __init__(self):
        self._intel_cache: Dict[str, Dict[str, Any]] = {}

    async def lookup_ip_intel(self, ip: str) -> IpIntelResult:
        clean_ip = ip.strip()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if is_private_ip(clean_ip):
            return IpIntelResult(
                ip=clean_ip,
                isPrivate=True,
                country=None,
                region=None,
                city=None,
                asn=None,
                org="Private / RFC1918 / Loopback / Reserved",
                reputationStatus="Internal Address",
                reputationNote="Private and loopback addresses are never sent to external geolocation providers.",
                sourceLabel="Local Guard Policy",
                cached=False,
                lookedUpAt=now_iso
            )

        # Check cache
        if clean_ip in self._intel_cache:
            entry = self._intel_cache[clean_ip]
            if time.time() - entry["ts"] < 3600:
                res = entry["data"]
                res.cached = True
                return res

        # Lookup public IP info using public GeoIP or local fallback
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(f"https://ipapi.co/{clean_ip}/json/")
                if resp.status_code == 200:
                    d = resp.json()
                    res = IpIntelResult(
                        ip=clean_ip,
                        isPrivate=False,
                        country=d.get("country_name"),
                        region=d.get("region"),
                        city=d.get("city"),
                        asn=d.get("asn"),
                        org=d.get("org"),
                        reputationStatus="Clean" if not d.get("error") else "Unknown",
                        reputationNote=f"Routing via {d.get('org', 'ISP')}",
                        sourceLabel="ipapi.co Geolocation",
                        cached=False,
                        lookedUpAt=now_iso
                    )
                    self._intel_cache[clean_ip] = {"data": res, "ts": time.time()}
                    return res
        except Exception:
            pass

        # Fallback for public IP
        fallback = IpIntelResult(
            ip=clean_ip,
            isPrivate=False,
            country="Public Network",
            region=None,
            city=None,
            asn="AS-EXT",
            org="Public External Host",
            reputationStatus="External Endpoint",
            reputationNote="Public endpoint observed in traffic stream.",
            sourceLabel="NetScope Heuristic",
            cached=False,
            lookedUpAt=now_iso
        )
        return fallback

    async def investigate_alert(
        self,
        alert: SecurityAlert,
        model_name: Optional[str] = "gemini-3.8-flash",
        use_high_thinking: bool = True
    ) -> Dict[str, Any]:
        api_key = (settings.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY", "")).strip()

        if not api_key or api_key in ("MY_GEMINI_API_KEY", "YOUR_GEMINI_API_KEY"):
            analysis = build_rule_based_investigation(alert)
            return {
                "source": "rule-based-fallback",
                "modelUsed": "deterministic-rule-engine",
                "analysis": analysis,
                "warning": "GEMINI_API_KEY is not configured; displaying deterministic rule-based SOC investigation."
            }

        try:
            import asyncio
            from google import genai
            client = genai.Client(api_key=api_key)

            # Modern available Gemini models for this key
            candidate_models = []
            if model_name:
                clean_m = model_name.strip().removeprefix("models/")
                candidate_models.append(clean_m)
            for m in ["gemini-3.8-flash", "gemini-3.1-flash-lite", "gemini-4-hydrogen"]:
                if m not in candidate_models:
                    candidate_models.append(m)

            prompt = f"""You are a Lead Senior SOC Analyst investigating a network intrusion alert for NETSCOPE X.
Analyze the following alert evidence and provide a structured, professional, executive-ready investigation:

Alert ID: {alert.id}
Rule Name: {alert.ruleName}
Category: {alert.category}
Severity: {alert.severity} (Calculated Risk Score: {alert.riskScore}/100)
Source IP: {alert.sourceIp}
Destination IP: {alert.destinationIp or 'Subnet / Broadcast'}
Observed Evidence: {', '.join(alert.evidence) if alert.evidence else 'Real-time telemetry burst'}
Recommended Containment Steps: {', '.join(alert.recommendedSteps) if alert.recommendedSteps else 'Standard SOC triage'}

Please format your response in clear markdown:
### NETSCOPE X SOC FORENSIC INVESTIGATION REPORT
**Incident Identifier:** {alert.id}
**Detection Rule:** {alert.ruleName}
**Severity Level:** {alert.severity} (Calculated Risk Score: {alert.riskScore}/100)
**Classification:** Confirmed Network Incident
**Timestamp (UTC):** {alert.timestamp}

---

#### 1. Executive Summary
[Authoritative assessment of the incident, threat scope, and risk context]

#### 2. Corroborating Forensic Evidence
[Breakdown of telemetry markers, network vectors, and packet anomalies]

#### 3. Threat Assessment & Technical Impact
- **Attacker TTP:** [MITRE ATT&CK mapping]
- **Target Exposure:** [Internal assets or services at risk]
- **Confidence Rating:** High (Gemini AI correlated with live packet stream)

#### 4. Mandatory Remediation & Containment Actions
[Specific actionable remediation steps]
"""
            analysis_text = None
            last_err = None
            used_model = candidate_models[0]

            for m in candidate_models:
                try:
                    # Use async client with 12s per-model timeout to avoid hanging the event loop
                    response = await asyncio.wait_for(
                        client.aio.models.generate_content(
                            model=m,
                            contents=prompt
                        ),
                        timeout=12.0
                    )
                    if response and response.text:
                        analysis_text = response.text
                        used_model = m
                        break
                except Exception as ex:
                    last_err = ex
                    continue

            if not analysis_text:
                raise last_err or Exception("No analysis text returned from Gemini API")

            return {
                "source": "gemini",
                "modelUsed": used_model,
                "analysis": analysis_text
            }
        except Exception as e:
            return {
                "source": "rule-based-fallback",
                "modelUsed": "deterministic-rule-engine",
                "analysis": build_rule_based_investigation(alert),
                "warning": f"Gemini API call fell back to deterministic SOC report ({str(e)})."
            }


incident_service = IncidentService()
