import time
import datetime
import asyncio
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from collections import deque

from app.config import settings
from app.schemas.packet_schema import (
    PacketRecord, SecurityAlert, TerminalEvent, TrafficStats,
    NetworkDeviceNode, NetworkEdge, AppSettings, DetectionThresholds,
    UpdateAlertRequest
)
from app.analyzer.traffic_analyzer import compute_traffic_stats, build_network_topology
from app.detection.detection_engine import analyze_traffic_for_threats
from app.database.repositories import Repository


class StatisticsService:
    def __init__(self):
        self.packets: deque[PacketRecord] = deque(maxlen=settings.MAX_BUFFERED_PACKETS)
        self.alerts: List[SecurityAlert] = []
        self.events: List[TerminalEvent] = []
        self.settings: AppSettings = AppSettings(
            defaultInterface=settings.DEFAULT_INTERFACE,
            maxPackets=settings.MAX_BUFFERED_PACKETS,
            retentionMinutes=60,
            thresholds=DetectionThresholds(),
            reducedMotion=False,
            preferredAiModel="gemini-3.8-flash",
            useHighThinking=True
        )
        self._simulation_task: Optional[asyncio.Task] = None
        self._simulation_active: bool = False
        self._active_scenario: Optional[str] = None
        self._load_initial_data()

    def _load_initial_data(self):
        # Load recent alerts and events from DB
        try:
            db_alerts = Repository.get_alerts(include_simulated=True)
            self.alerts = db_alerts
            db_events = Repository.get_events()
            self.events = db_events
        except Exception:
            pass

    def add_packet(self, packet: PacketRecord) -> List[SecurityAlert]:
        self.packets.append(packet)

        # Run threat detection periodically or every batch
        new_alerts: List[SecurityAlert] = []
        # Check for threats every 5 packets or on simulated bursts
        if packet.isSimulated or len(self.packets) % 5 == 0:
            new_alerts = analyze_traffic_for_threats(
                list(self.packets),
                self.settings.thresholds,
                self.alerts,
                now_ms=packet.epochMs
            )
            for alert in new_alerts:
                self.alerts.append(alert)
                Repository.save_alert(alert)
                self.add_event(
                    category="alert",
                    severity="alert",
                    message=f"Alert triggered: {alert.ruleName} for {alert.sourceIp} (Risk: {alert.riskScore})",
                    is_simulated=alert.isSimulated
                )

        return new_alerts

    def get_packets(
        self,
        search: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        source_port: Optional[str] = None,
        destination_port: Optional[str] = None,
        protocol: Optional[str] = None,
        min_size: Optional[int] = None,
        max_size: Optional[int] = None,
        tcp_flag: Optional[str] = None,
        include_simulated: bool = True,
        only_simulated: bool = False,
        sort_by: str = "timestamp",
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int = 50
    ) -> Tuple[List[PacketRecord], int]:
        pkts = list(self.packets)

        filtered = []
        for p in pkts:
            if only_simulated and not p.isSimulated:
                continue
            if not include_simulated and p.isSimulated:
                continue
            if protocol and protocol != "ALL" and p.protocol != protocol:
                continue
            if source_ip and source_ip.lower() not in p.sourceIp.lower():
                continue
            if destination_ip and destination_ip.lower() not in p.destinationIp.lower():
                continue
            if destination_port and str(p.destinationPort) != destination_port:
                continue
            if source_port and str(p.sourcePort) != source_port:
                continue
            if min_size is not None and p.size < min_size:
                continue
            if max_size is not None and p.size > max_size:
                continue
            if tcp_flag and tcp_flag != "ALL" and tcp_flag not in p.tcpFlags:
                continue
            if search:
                q = search.lower()
                match = (
                    q in p.sourceIp.lower()
                    or q in p.destinationIp.lower()
                    or q in p.protocol.lower()
                    or q in p.summary.lower()
                    or (p.dnsQuery and q in p.dnsQuery.lower())
                    or (p.httpHost and q in p.httpHost.lower())
                )
                if not match:
                    continue
            filtered.append(p)

        reverse = (sort_dir.lower() == "desc")
        if sort_by == "size":
            filtered.sort(key=lambda x: x.size, reverse=reverse)
        elif sort_by == "protocol":
            filtered.sort(key=lambda x: x.protocol, reverse=reverse)
        else:
            filtered.sort(key=lambda x: x.epochMs, reverse=reverse)

        total = len(filtered)
        start = (page - 1) * page_size
        end = start + page_size
        items = filtered[start:end]

        return items, total

    def get_stats(self, window_seconds: int = 300, include_simulated: bool = False) -> TrafficStats:
        pkts = [p for p in self.packets if (include_simulated or not p.isSimulated)]
        alrts = [a for a in self.alerts if (include_simulated or not a.isSimulated)]
        return compute_traffic_stats(pkts, alrts, window_seconds)

    def get_topology(self, protocol: str = "ALL", include_simulated: bool = True) -> Tuple[List[NetworkDeviceNode], List[NetworkEdge]]:
        pkts = [p for p in self.packets if (include_simulated or not p.isSimulated)]
        alrts = [a for a in self.alerts if (include_simulated or not a.isSimulated)]
        return build_network_topology(pkts, alrts, protocol)

    def get_alerts(self, include_simulated: bool = True) -> List[SecurityAlert]:
        if include_simulated:
            return list(self.alerts)
        return [a for a in self.alerts if not a.isSimulated]

    def update_alert(self, alert_id: str, patch: UpdateAlertRequest) -> Optional[SecurityAlert]:
        # Update in memory
        for idx, a in enumerate(self.alerts):
            if a.id == alert_id:
                updated = Repository.update_alert(alert_id, patch)
                if updated:
                    self.alerts[idx] = updated
                return updated
        return Repository.update_alert(alert_id, patch)

    def add_event(
        self,
        category: str,
        severity: str,
        message: str,
        is_simulated: bool = False
    ) -> TerminalEvent:
        event = TerminalEvent(
            id=f"evt-{int(time.time() * 1000)}",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            category=category,  # type: ignore
            severity=severity,  # type: ignore
            message=message,
            isSimulated=is_simulated
        )
        self.events.append(event)
        if len(self.events) > 200:
            self.events.pop(0)
        Repository.save_event(event)
        return event

    def get_events(self) -> List[TerminalEvent]:
        return list(self.events)

    def _persist_gemini_key_to_env(self, key: str):
        try:
            env_file = Path(settings.model_config.get("env_file", ".env"))
            if not env_file.is_absolute():
                env_file = Path(__file__).resolve().parent.parent.parent / env_file
            
            lines = []
            if env_file.exists():
                lines = env_file.read_text(encoding="utf-8").splitlines()
            
            found = False
            new_lines = []
            for line in lines:
                if line.strip().startswith("GEMINI_API_KEY="):
                    new_lines.append(f"GEMINI_API_KEY={key}")
                    found = True
                else:
                    new_lines.append(line)
            if not found:
                new_lines.append(f"GEMINI_API_KEY={key}")
            
            env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        except Exception:
            pass

    def get_settings(self) -> AppSettings:
        current = self.settings.model_copy()
        raw_key = settings.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY", "")
        current.hasGeminiApiKey = bool(raw_key and raw_key.strip() not in ("", "MY_GEMINI_API_KEY", "YOUR_GEMINI_API_KEY"))
        if raw_key and len(raw_key.strip()) > 8:
            clean = raw_key.strip()
            current.geminiApiKey = f"{clean[:4]}...{clean[-4:]}"
        elif current.hasGeminiApiKey:
            current.geminiApiKey = "****"
        else:
            current.geminiApiKey = ""
        return current

    def update_settings(self, patch: Dict[str, Any]) -> AppSettings:
        # Check if a new Gemini API Key is submitted
        new_key = patch.get("geminiApiKey")
        if new_key is not None and isinstance(new_key, str):
            clean_key = new_key.strip()
            if clean_key == "":
                settings.GEMINI_API_KEY = ""
                os.environ["GEMINI_API_KEY"] = ""
                self._persist_gemini_key_to_env("")
                self.add_event("system", "info", "Cleared Gemini API key.", is_simulated=False)
            elif not clean_key.startswith("****") and "..." not in clean_key:
                settings.GEMINI_API_KEY = clean_key
                os.environ["GEMINI_API_KEY"] = clean_key
                self._persist_gemini_key_to_env(clean_key)
                self.add_event("system", "info", "Updated and persisted Gemini API key.", is_simulated=False)

        current = self.settings.model_dump()
        for k, v in patch.items():
            if k in current and v is not None and k != "geminiApiKey":
                current[k] = v
        self.settings = AppSettings(**current)
        return self.get_settings()

    # Simulation Lab Support
    def start_simulation(self, scenario: str):
        self._simulation_active = True
        self._active_scenario = scenario
        start_event = self.add_event("simulation", "info", f"Started simulation scenario: {scenario}", is_simulated=True)

        # Generate simulation packets
        now = int(time.time() * 1000)
        sim_pkts: List[PacketRecord] = []

        if scenario == "port_scan":
            for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]:
                sim_pkts.append(PacketRecord(
                    id=f"sim-ps-{port}-{now}",
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    epochMs=now + (port * 10),
                    sourceIp="10.240.0.99",
                    destinationIp="10.240.0.10",
                    sourcePort=45000 + port,
                    destinationPort=port,
                    protocol="TCP",
                    transportProtocol="TCP",
                    size=64,
                    tcpFlags=["SYN"],
                    ttl=64,
                    interfaceName="sim-loopback",
                    direction="inbound",
                    isSimulated=True,
                    summary=f"TCP 10.240.0.99:{45000+port} -> 10.240.0.10:{port} [SYN]",
                    layerStack=["Ethernet II", "IP", "TCP"]
                ))
        elif scenario == "syn_flood_metadata":
            for i in range(25):
                sim_pkts.append(PacketRecord(
                    id=f"sim-syn-{i}-{now}",
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    epochMs=now + (i * 20),
                    sourceIp=f"198.51.100.{10 + (i % 5)}",
                    destinationIp="10.240.0.50",
                    sourcePort=50000 + i,
                    destinationPort=80,
                    protocol="TCP",
                    transportProtocol="TCP",
                    size=64,
                    tcpFlags=["SYN"],
                    ttl=64,
                    interfaceName="sim-loopback",
                    direction="inbound",
                    isSimulated=True,
                    summary=f"TCP SYN Flood Probe #{i} -> 10.240.0.50:80",
                    layerStack=["Ethernet II", "IP", "TCP"]
                ))
        elif scenario == "traffic_spike":
            for i in range(35):
                sim_pkts.append(PacketRecord(
                    id=f"sim-vol-{i}-{now}",
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    epochMs=now + (i * 15),
                    sourceIp="10.240.0.77",
                    destinationIp="10.240.0.5",
                    sourcePort=52000,
                    destinationPort=443,
                    protocol="HTTPS/TLS",
                    transportProtocol="TCP",
                    size=1514,
                    tcpFlags=["ACK", "PSH"],
                    ttl=64,
                    interfaceName="sim-loopback",
                    direction="inbound",
                    isSimulated=True,
                    summary=f"High MTU Volume Burst #{i} (1514 bytes)",
                    layerStack=["Ethernet II", "IP", "TCP", "TLS"]
                ))
        elif scenario == "dns_anomaly":
            for i in range(20):
                sim_pkts.append(PacketRecord(
                    id=f"sim-dns-{i}-{now}",
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    epochMs=now + (i * 25),
                    sourceIp="10.240.0.88",
                    destinationIp="1.1.1.1",
                    sourcePort=53000 + i,
                    destinationPort=53,
                    protocol="DNS",
                    transportProtocol="UDP",
                    size=120,
                    tcpFlags=[],
                    ttl=64,
                    interfaceName="sim-loopback",
                    direction="outbound",
                    isSimulated=True,
                    summary=f"DNS Query probe-{i}.c2-domain.xyz",
                    layerStack=["Ethernet II", "IP", "UDP", "DNS"],
                    dnsQuery=f"probe-{i}.c2-domain.xyz",
                    dnsResponseCode="NXDOMAIN" if i % 2 == 0 else "NOERROR"
                ))
        elif scenario == "repeated_connections":
            for i in range(16):
                sim_pkts.append(PacketRecord(
                    id=f"sim-fan-{i}-{now}",
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    epochMs=now + (i * 30),
                    sourceIp="10.240.0.150",
                    destinationIp=f"10.240.0.{100 + i}",
                    sourcePort=49000,
                    destinationPort=445,
                    protocol="TCP",
                    transportProtocol="TCP",
                    size=64,
                    tcpFlags=["SYN"],
                    ttl=64,
                    interfaceName="sim-loopback",
                    direction="outbound",
                    isSimulated=True,
                    summary=f"Lateral Connection -> 10.240.0.{100+i}:445 [SMB]",
                    layerStack=["Ethernet II", "IP", "TCP"]
                ))

        all_new_alerts: List[SecurityAlert] = []
        for sp in sim_pkts:
            alerts = self.add_packet(sp)
            all_new_alerts.extend(alerts)

        return sim_pkts, all_new_alerts, start_event

    def stop_simulation(self):
        self._simulation_active = False
        self._active_scenario = None
        self.add_event("simulation", "info", "Simulation stopped.", is_simulated=True)

    def clear_simulation_data(self):
        self.packets = deque([p for p in self.packets if not p.isSimulated], maxlen=settings.MAX_BUFFERED_PACKETS)
        self.alerts = [a for a in self.alerts if not a.isSimulated]
        self.events = [e for e in self.events if not e.isSimulated]
        return {"status": "cleared", "simulationActive": False}


statistics_service = StatisticsService()
