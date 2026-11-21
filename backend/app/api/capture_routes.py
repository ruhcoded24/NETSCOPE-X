from fastapi import APIRouter, HTTPException
from typing import List, Optional

from app.schemas.packet_schema import (
    NetworkInterfaceInfo, CaptureStatusState,
    CaptureSessionSummary, StartCaptureRequest
)
from app.capture.interface_manager import interface_manager
from app.capture.tshark_manager import tshark_manager
from app.database.repositories import Repository

router = APIRouter(tags=["Capture"])


@router.get("/interfaces")
async def get_interfaces():
    interfaces = interface_manager.get_interfaces()
    return {"interfaces": [i.model_dump() for i in interfaces]}


@router.get("/capture/status", response_model=CaptureStatusState)
async def get_capture_status():
    return tshark_manager.get_status()


@router.post("/capture/start", response_model=CaptureStatusState)
async def start_capture(req: Optional[StartCaptureRequest] = None):
    try:
        iface_name = (req.interfaceName or req.interface) if req else None
        status = await tshark_manager.start_capture(iface_name)
        if status.activeSession:
            Repository.save_session(status.activeSession)
        return status
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/capture/stop", response_model=CaptureStatusState)
async def stop_capture():
    status = await tshark_manager.stop_capture()
    if status.activeSession:
        Repository.save_session(status.activeSession)
    return status


@router.get("/sessions")
async def get_sessions():
    sessions = Repository.get_sessions()
    return {"sessions": [s.model_dump() for s in sessions]}
