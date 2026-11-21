import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel

from app.config import settings
from app.database.supabase_client import get_supabase_client, get_current_user, require_auth_user
from app.services.statistics_service import statistics_service

router = APIRouter(prefix="/auth", tags=["Supabase Auth & Cloud"])


class UserProfileResponse(BaseModel):
    authenticated: bool
    user: Optional[Dict[str, Any]] = None
    profile: Optional[Dict[str, Any]] = None
    cloudConfigured: bool


class SaveIncidentRequest(BaseModel):
    alertId: Optional[str] = None
    title: str
    severity: str
    sourceIp: Optional[str] = None
    targetIp: Optional[str] = None
    mitreTechnique: Optional[str] = None
    notes: Optional[str] = ""
    aiAnalysis: Optional[str] = ""


class SaveReportRequest(BaseModel):
    title: str
    reportType: str = "forensic"
    contentMarkdown: str
    metadata: Optional[Dict[str, Any]] = None


@router.get("/status", response_model=UserProfileResponse)
async def get_auth_status(user: Optional[Dict[str, Any]] = Depends(get_current_user)):
    if not settings.has_supabase:
        return UserProfileResponse(
            authenticated=False,
            user=None,
            profile=None,
            cloudConfigured=False
        )

    if not user:
        return UserProfileResponse(
            authenticated=False,
            user=None,
            profile=None,
            cloudConfigured=True
        )

    # Fetch user profile from Supabase profiles table
    client = get_supabase_client()
    profile = None
    if client:
        try:
            res = client.table("profiles").select("*").eq("id", user["id"]).maybe_single().execute()
            if res and res.data:
                profile = res.data
        except Exception:
            pass

    return UserProfileResponse(
        authenticated=True,
        user=user,
        profile=profile,
        cloudConfigured=True
    )


@router.get("/cloud-incidents")
async def get_cloud_incidents(user: Dict[str, Any] = Depends(require_auth_user)):
    client = get_supabase_client()
    if not client:
        raise HTTPException(status_code=503, detail="Supabase client not available")

    try:
        res = client.table("incidents").select("*").eq("user_id", user["id"]).order("created_at", desc=True).execute()
        return {"incidents": res.data or []}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/cloud-incidents")
async def save_cloud_incident(req: SaveIncidentRequest, user: Dict[str, Any] = Depends(require_auth_user)):
    client = get_supabase_client()
    if not client:
        raise HTTPException(status_code=503, detail="Supabase client not available")

    incident_id = f"inc_{int(datetime.datetime.now().timestamp())}"
    data = {
        "id": incident_id,
        "user_id": user["id"],
        "alert_id": req.alertId,
        "title": req.title,
        "severity": req.severity,
        "status": "open",
        "source_ip": req.sourceIp,
        "target_ip": req.targetIp,
        "mitre_technique": req.mitreTechnique,
        "notes": req.notes,
        "ai_analysis": req.aiAnalysis,
    }

    try:
        res = client.table("incidents").insert(data).execute()
        return {"ok": True, "incident": res.data[0] if res.data else data}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/cloud-reports")
async def get_cloud_reports(user: Dict[str, Any] = Depends(require_auth_user)):
    client = get_supabase_client()
    if not client:
        raise HTTPException(status_code=503, detail="Supabase client not available")

    try:
        res = client.table("saved_reports").select("*").eq("user_id", user["id"]).order("created_at", desc=True).execute()
        return {"reports": res.data or []}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/cloud-reports")
async def save_cloud_report(req: SaveReportRequest, user: Dict[str, Any] = Depends(require_auth_user)):
    client = get_supabase_client()
    if not client:
        raise HTTPException(status_code=503, detail="Supabase client not available")

    report_id = f"rep_{int(datetime.datetime.now().timestamp())}"
    data = {
        "id": report_id,
        "user_id": user["id"],
        "title": req.title,
        "report_type": req.reportType,
        "content_markdown": req.contentMarkdown,
        "metadata": req.metadata or {},
    }

    try:
        res = client.table("saved_reports").insert(data).execute()
        return {"ok": True, "report": res.data[0] if res.data else data}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
