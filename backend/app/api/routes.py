import datetime
from fastapi import APIRouter

from app.api.capture_routes import router as capture_router
from app.api.analytics_routes import router as analytics_router
from app.api.detection_routes import router as detection_router
from app.api.pcap_routes import router as pcap_router

api_router = APIRouter(prefix="/api")


@api_router.get("/health")
async def health_check():
    return {
        "ok": True,
        "service": "netscope-x",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


# Include sub-routers
api_router.include_router(capture_router)
api_router.include_router(analytics_router)
api_router.include_router(detection_router)
api_router.include_router(pcap_router)
