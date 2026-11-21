from fastapi import APIRouter, HTTPException
from typing import Optional

from app.schemas.packet_schema import (
    SecurityAlert, UpdateAlertRequest, SimulationRunRequest,
    AiInvestigateRequest, AiVisualRequest
)
from app.services.statistics_service import statistics_service
from app.services.incident_service import incident_service
from app.capture.tshark_manager import tshark_manager
from app.websocket.packet_stream import ws_manager

router = APIRouter(tags=["Detection & Incidents"])


@router.get("/alerts")
async def get_alerts(includeSimulated: bool = True):
    alerts = statistics_service.get_alerts(includeSimulated)
    return {"alerts": [a.model_dump() for a in alerts]}


@router.patch("/alerts/{alert_id}", response_model=SecurityAlert)
async def update_alert(alert_id: str, patch: UpdateAlertRequest):
    updated = statistics_service.update_alert(alert_id, patch)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")

    await ws_manager.broadcast_alert_updated(updated)
    return updated


@router.post("/simulation/run")
async def run_simulation(req: SimulationRunRequest):
    sim_pkts, new_alerts, sim_event = statistics_service.start_simulation(req.scenario)

    # 1. Broadcast active simulation status and event over WebSocket
    status = tshark_manager.get_status()
    await ws_manager.broadcast_status(status)
    await ws_manager.broadcast_event(sim_event)

    # 2. Queue all simulated packets to live WebSocket stream
    for p in sim_pkts:
        ws_manager.queue_packet(p)

    # 3. Broadcast all generated alerts immediately over WebSocket
    for a in new_alerts:
        await ws_manager.broadcast_alert(a)

    return {
        "simulationActive": True,
        "scenario": req.scenario,
        "packetsGenerated": len(sim_pkts),
        "alertsTriggered": [a.model_dump() for a in new_alerts]
    }


@router.post("/simulation/stop")
async def stop_simulation():
    statistics_service.stop_simulation()
    status = tshark_manager.get_status()
    await ws_manager.broadcast_status(status)
    return {"status": "stopped", "simulationActive": False}


@router.post("/simulation/clear")
async def clear_simulation():
    res = statistics_service.clear_simulation_data()
    status = tshark_manager.get_status()
    await ws_manager.broadcast_status(status)
    await ws_manager.broadcast_json({"type": "simulation_cleared"})
    return res


@router.post("/ai/investigate")
async def investigate_alert(req: AiInvestigateRequest):
    alert = req.alert
    if not alert and req.alertId:
        alerts = statistics_service.get_alerts(include_simulated=True)
        alert = next((a for a in alerts if a.id == req.alertId), None)

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found for AI investigation")

    res = await incident_service.investigate_alert(
        alert=alert,
        model_name=req.model,
        use_high_thinking=bool(req.useHighThinking)
    )

    # Persist the analysis onto the alert
    if res.get("analysis"):
        statistics_service.update_alert(
            alert.id,
            UpdateAlertRequest(aiAnalysis=res["analysis"])
        )

    statistics_service.add_event(
        category="ai",
        severity="info",
        message=f"AI SOC investigation completed for {alert.id} using {res.get('modelUsed')}",
        is_simulated=alert.isSimulated
    )

    return res


@router.post("/ai/generate-visual")
async def generate_threat_visual(req: AiVisualRequest):
    # Returns prompt / metadata for visual schematic rendering
    alert = req.alert
    if not alert and req.alertId:
        alerts = statistics_service.get_alerts(include_simulated=True)
        alert = next((a for a in alerts if a.id == req.alertId), None)

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {
        "ok": True,
        "alertId": alert.id,
        "title": f"Threat Vector: {alert.ruleName}",
        "imageSize": req.imageSize or "1K",
        "schematic": {
            "source": alert.sourceIp,
            "target": alert.destinationIp,
            "category": alert.category,
            "severity": alert.severity,
            "riskScore": alert.riskScore
        }
    }
