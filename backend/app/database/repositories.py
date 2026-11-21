import json
import logging
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.database import SessionLocal
from app.database.models import (
    CaptureSessionModel, PacketModel, SecurityAlertModel,
    TerminalEventModel, InvestigationNoteModel
)
from app.schemas.packet_schema import (
    PacketRecord, SecurityAlert, CaptureSessionSummary,
    TerminalEvent, RiskBreakdown, UpdateAlertRequest
)

logger = logging.getLogger("netscope.repositories")


class Repository:
    @staticmethod
    def save_packet(packet: PacketRecord):
        db: Session = SessionLocal()
        try:
            model = PacketModel(
                id=packet.id,
                timestamp=packet.timestamp,
                epoch_ms=packet.epochMs,
                source_ip=packet.sourceIp,
                destination_ip=packet.destinationIp,
                source_port=packet.sourcePort,
                destination_port=packet.destinationPort,
                protocol=packet.protocol,
                transport_protocol=packet.transportProtocol,
                size=packet.size,
                tcp_flags=",".join(packet.tcpFlags),
                ttl=packet.ttl,
                interface_name=packet.interfaceName,
                direction=packet.direction,
                is_simulated=packet.isSimulated,
                summary=packet.summary,
                layer_stack=json.dumps(packet.layerStack),
                dns_query=packet.dnsQuery,
                dns_response_code=packet.dnsResponseCode,
                http_method=packet.httpMethod,
                http_host=packet.httpHost,
                tls_sni=packet.tlsSni,
            )
            db.merge(model)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to persist packet {packet.id}: {e}")
        finally:
            db.close()

    @staticmethod
    def save_packets_batch(packets: List[PacketRecord]):
        if not packets:
            return
        db: Session = SessionLocal()
        try:
            models = [
                PacketModel(
                    id=p.id,
                    timestamp=p.timestamp,
                    epoch_ms=p.epochMs,
                    source_ip=p.sourceIp,
                    destination_ip=p.destinationIp,
                    source_port=p.sourcePort,
                    destination_port=p.destinationPort,
                    protocol=p.protocol,
                    transport_protocol=p.transportProtocol,
                    size=p.size,
                    tcp_flags=",".join(p.tcpFlags),
                    ttl=p.ttl,
                    interface_name=p.interfaceName,
                    direction=p.direction,
                    is_simulated=p.isSimulated,
                    summary=p.summary,
                    layer_stack=json.dumps(p.layerStack),
                    dns_query=p.dnsQuery,
                    dns_response_code=p.dnsResponseCode,
                    http_method=p.httpMethod,
                    http_host=p.httpHost,
                    tls_sni=p.tlsSni,
                )
                for p in packets
            ]
            db.bulk_save_objects(models)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to batch persist packets: {e}")
        finally:
            db.close()

    @staticmethod
    def save_alert(alert: SecurityAlert):
        db: Session = SessionLocal()
        try:
            model = SecurityAlertModel(
                id=alert.id,
                timestamp=alert.timestamp,
                epoch_ms=alert.epochMs,
                source_ip=alert.sourceIp,
                destination_ip=alert.destinationIp,
                category=alert.category,
                severity=alert.severity,
                risk_score=alert.riskScore,
                risk_breakdown=json.dumps(alert.riskBreakdown.model_dump()),
                classification=alert.classification,
                rule_name=alert.ruleName,
                summary=alert.summary,
                evidence=json.dumps(alert.evidence),
                recommended_steps=json.dumps(alert.recommendedSteps),
                status=alert.status,
                false_positive=alert.falsePositive,
                notes=alert.notes,
                is_simulated=alert.isSimulated,
                ai_analysis=alert.aiAnalysis,
            )
            db.merge(model)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to save alert {alert.id}: {e}")
        finally:
            db.close()

    @staticmethod
    def get_alerts(include_simulated: bool = True) -> List[SecurityAlert]:
        db: Session = SessionLocal()
        try:
            query = db.query(SecurityAlertModel)
            if not include_simulated:
                query = query.filter(SecurityAlertModel.is_simulated == False)
            rows = query.order_by(desc(SecurityAlertModel.epoch_ms)).limit(200).all()

            alerts = []
            for r in rows:
                rb_data = {}
                try:
                    rb_data = json.loads(r.risk_breakdown or "{}")
                except Exception:
                    pass
                ev_data = []
                try:
                    ev_data = json.loads(r.evidence or "[]")
                except Exception:
                    pass
                rec_data = []
                try:
                    rec_data = json.loads(r.recommended_steps or "[]")
                except Exception:
                    pass

                alerts.append(SecurityAlert(
                    id=r.id,
                    timestamp=r.timestamp,
                    epochMs=r.epoch_ms,
                    sourceIp=r.source_ip,
                    destinationIp=r.destination_ip,
                    category=r.category,  # type: ignore
                    severity=r.severity,  # type: ignore
                    riskScore=r.risk_score,
                    riskBreakdown=RiskBreakdown(**rb_data) if rb_data else RiskBreakdown(),
                    classification=r.classification,  # type: ignore
                    ruleName=r.rule_name,
                    summary=r.summary,
                    evidence=ev_data,
                    recommendedSteps=rec_data,
                    status=r.status,  # type: ignore
                    falsePositive=r.false_positive,
                    notes=r.notes,
                    isSimulated=r.is_simulated,
                    aiAnalysis=r.ai_analysis,
                ))
            return alerts
        finally:
            db.close()

    @staticmethod
    def update_alert(alert_id: str, patch: UpdateAlertRequest) -> Optional[SecurityAlert]:
        db: Session = SessionLocal()
        try:
            alert = db.query(SecurityAlertModel).filter(SecurityAlertModel.id == alert_id).first()
            if not alert:
                return None

            if patch.status is not None:
                alert.status = patch.status
            if patch.notes is not None:
                alert.notes = patch.notes
            if patch.falsePositive is not None:
                alert.false_positive = patch.falsePositive
            if patch.classification is not None:
                alert.classification = patch.classification
            if patch.aiAnalysis is not None:
                alert.ai_analysis = patch.aiAnalysis

            db.commit()
            db.refresh(alert)

            rb_data = json.loads(alert.risk_breakdown or "{}")
            ev_data = json.loads(alert.evidence or "[]")
            rec_data = json.loads(alert.recommended_steps or "[]")

            return SecurityAlert(
                id=alert.id,
                timestamp=alert.timestamp,
                epochMs=alert.epoch_ms,
                sourceIp=alert.source_ip,
                destinationIp=alert.destination_ip,
                category=alert.category,  # type: ignore
                severity=alert.severity,  # type: ignore
                riskScore=alert.risk_score,
                riskBreakdown=RiskBreakdown(**rb_data) if rb_data else RiskBreakdown(),
                classification=alert.classification,  # type: ignore
                ruleName=alert.rule_name,
                summary=alert.summary,
                evidence=ev_data,
                recommendedSteps=rec_data,
                status=alert.status,  # type: ignore
                falsePositive=alert.false_positive,
                notes=alert.notes,
                isSimulated=alert.is_simulated,
                aiAnalysis=alert.ai_analysis,
            )
        finally:
            db.close()

    @staticmethod
    def save_session(session: CaptureSessionSummary):
        db: Session = SessionLocal()
        try:
            model = CaptureSessionModel(
                id=session.id,
                interface_name=session.interfaceName,
                mode=session.mode,
                started_at=session.startedAt,
                stopped_at=session.stoppedAt,
                packet_count=session.packetCount,
                byte_count=session.byteCount,
                alert_count=session.alertCount,
                active=session.active,
            )
            db.merge(model)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to persist session {session.id}: {e}")
        finally:
            db.close()

    @staticmethod
    def get_sessions() -> List[CaptureSessionSummary]:
        db: Session = SessionLocal()
        try:
            rows = db.query(CaptureSessionModel).order_by(desc(CaptureSessionModel.started_at)).limit(50).all()
            return [
                CaptureSessionSummary(
                    id=r.id,
                    interfaceName=r.interface_name,
                    mode=r.mode,
                    startedAt=r.started_at,
                    stoppedAt=r.stopped_at,
                    packetCount=r.packet_count,
                    byteCount=r.byte_count,
                    alertCount=r.alert_count,
                    active=r.active,
                )
                for r in rows
            ]
        finally:
            db.close()

    @staticmethod
    def save_event(event: TerminalEvent):
        db: Session = SessionLocal()
        try:
            model = TerminalEventModel(
                id=event.id,
                timestamp=event.timestamp,
                category=event.category,
                severity=event.severity,
                message=event.message,
                is_simulated=event.isSimulated,
            )
            db.merge(model)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to save event {event.id}: {e}")
        finally:
            db.close()

    @staticmethod
    def get_events() -> List[TerminalEvent]:
        db: Session = SessionLocal()
        try:
            rows = db.query(TerminalEventModel).order_by(desc(TerminalEventModel.timestamp)).limit(100).all()
            return [
                TerminalEvent(
                    id=r.id,
                    timestamp=r.timestamp,
                    category=r.category,  # type: ignore
                    severity=r.severity,  # type: ignore
                    message=r.message,
                    isSimulated=r.is_simulated,
                )
                for r in rows
            ]
        finally:
            db.close()
