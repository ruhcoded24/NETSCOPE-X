import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings, BACKEND_ROOT
from app.database.database import init_db
from app.api.routes import api_router
from app.websocket.packet_stream import ws_manager
from app.capture.tshark_manager import tshark_manager
from app.services.statistics_service import statistics_service

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netscope")


# Lifecycle manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing NETSCOPE X Backend...")
    # Initialize database
    init_db()

    # Start WebSocket batch broadcast worker if not under test
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        ws_manager.start_broadcaster()

    # Wire up TShark packet capture listeners
    def on_packet(packet):
        new_alerts = statistics_service.add_packet(packet)
        ws_manager.queue_packet(packet)
        for a in new_alerts:
            # Trigger async broadcast
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(ws_manager.broadcast_alert(a))
            except Exception:
                pass

    def on_status(status):
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(ws_manager.broadcast_status(status))
        except Exception:
            pass

    def on_error(err_text):
        evt = statistics_service.add_event("capture", "warn", err_text)
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(ws_manager.broadcast_event(evt))
        except Exception:
            pass

    tshark_manager.register_on_packet(on_packet)
    tshark_manager.register_on_status(on_status)
    tshark_manager.register_on_error(on_error)

    logger.info(f"NETSCOPE X Backend started on {settings.HOST}:{settings.PORT}")
    yield

    logger.info("Shutting down NETSCOPE X Backend...")
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        await ws_manager.stop_broadcaster()
    if tshark_manager.capturing:
        await tshark_manager.stop_capture()


app = FastAPI(
    title="NETSCOPE X API",
    description="High-performance real-time network traffic capture, packet inspection and threat detection engine.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits local GUI and web access
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST API routes
app.include_router(api_router)


# WebSocket Endpoints
@app.websocket("/ws")
async def websocket_endpoint_root(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep socket open and listen for any incoming client messages
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket closed: {e}")
        ws_manager.disconnect(websocket)


@app.websocket("/ws/packets")
async def websocket_endpoint_packets(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket closed: {e}")
        ws_manager.disconnect(websocket)


# Static serving for built frontend if present
frontend_dist = BACKEND_ROOT.parent / "frontend" / "dist"
src_assets = BACKEND_ROOT.parent / "frontend" / "src" / "assets"

if src_assets.exists():
    app.mount("/src/assets", StaticFiles(directory=str(src_assets)), name="src-assets")

if frontend_dist.exists() and (frontend_dist / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        file_path = frontend_dist / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(frontend_dist / "index.html")
