from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime
from app.database.database import Base


class CaptureSessionModel(Base):
    __tablename__ = "capture_sessions"

    id = Column(String(128), primary_key=True, index=True)
    interface_name = Column(String(128), nullable=False)
    mode = Column(String(64), default="Live TShark")
    started_at = Column(String(64), nullable=False)
    stopped_at = Column(String(64), nullable=True)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    alert_count = Column(Integer, default=0)
    active = Column(Boolean, default=True)


class PacketModel(Base):
    __tablename__ = "packets"

    id = Column(String(128), primary_key=True, index=True)
    timestamp = Column(String(64), nullable=False)
    epoch_ms = Column(Integer, index=True, nullable=False)
    source_ip = Column(String(64), index=True, nullable=False)
    destination_ip = Column(String(64), index=True, nullable=False)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(32), index=True, nullable=False)
    transport_protocol = Column(String(32), default="")
    size = Column(Integer, default=0)
    tcp_flags = Column(String(128), default="")
    ttl = Column(Integer, nullable=True)
    interface_name = Column(String(128), default="")
    direction = Column(String(16), default="local")
    is_simulated = Column(Boolean, default=False)
    summary = Column(Text, default="")
    layer_stack = Column(Text, default="")
    dns_query = Column(String(255), nullable=True)
    dns_response_code = Column(String(32), nullable=True)
    http_method = Column(String(16), nullable=True)
    http_host = Column(String(255), nullable=True)
    tls_sni = Column(String(255), nullable=True)


class SecurityAlertModel(Base):
    __tablename__ = "security_alerts"

    id = Column(String(128), primary_key=True, index=True)
    timestamp = Column(String(64), nullable=False)
    epoch_ms = Column(Integer, index=True, nullable=False)
    source_ip = Column(String(64), index=True, nullable=False)
    destination_ip = Column(String(64), nullable=True)
    category = Column(String(64), index=True, nullable=False)
    severity = Column(String(32), index=True, nullable=False)
    risk_score = Column(Integer, default=0)
    risk_breakdown = Column(Text, default="{}")
    classification = Column(String(64), default="Heuristic Alert")
    rule_name = Column(String(128), nullable=False)
    summary = Column(Text, nullable=False)
    evidence = Column(Text, default="[]")
    recommended_steps = Column(Text, default="[]")
    status = Column(String(32), default="new")
    false_positive = Column(Boolean, default=False)
    notes = Column(Text, default="")
    is_simulated = Column(Boolean, default=False)
    ai_analysis = Column(Text, nullable=True)


class TerminalEventModel(Base):
    __tablename__ = "terminal_events"

    id = Column(String(128), primary_key=True, index=True)
    timestamp = Column(String(64), nullable=False)
    category = Column(String(32), default="system")
    severity = Column(String(16), default="info")
    message = Column(Text, nullable=False)
    is_simulated = Column(Boolean, default=False)


class InvestigationNoteModel(Base):
    __tablename__ = "investigation_notes"

    id = Column(String(128), primary_key=True, index=True)
    alert_id = Column(String(128), index=True, nullable=False)
    author = Column(String(64), default="SOC Analyst")
    note = Column(Text, nullable=False)
    created_at = Column(String(64), nullable=False)
