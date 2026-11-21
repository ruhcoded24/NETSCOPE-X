import asyncio
import json
import logging
from typing import Set, List, Any
from fastapi import WebSocket, WebSocketDisconnect

from app.schemas.packet_schema import PacketRecord, SecurityAlert, TerminalEvent, CaptureStatusState
from app.services.statistics_service import statistics_service
from app.capture.tshark_manager import tshark_manager

logger = logging.getLogger("netscope.websocket")


class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._pending_packets: List[PacketRecord] = []
        self._broadcast_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        self._running: bool = False

    def start_broadcaster(self):
        self._running = True
        if self._broadcast_task is None or self._broadcast_task.done():
            self._broadcast_task = asyncio.create_task(self._packet_batch_worker())

    async def stop_broadcaster(self):
        self._running = False
        if self._broadcast_task and not self._broadcast_task.done():
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except asyncio.CancelledError:
                pass

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

        # Send 'init' payload
        status = tshark_manager.get_status()
        stats = statistics_service.get_stats(300, include_simulated=True)
        alerts = statistics_service.get_alerts(include_simulated=True)[:50]
        events = statistics_service.get_events()[:80]
        recent_pkts, _ = statistics_service.get_packets(page=1, page_size=80, include_simulated=True)

        init_msg = {
            "type": "init",
            "data": {
                "status": status.model_dump(),
                "stats": stats.model_dump(),
                "alerts": [a.model_dump() for a in alerts],
                "events": [e.model_dump() for e in events],
                "packets": [p.model_dump() for p in recent_pkts],
            }
        }
        await websocket.send_text(json.dumps(init_msg))

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Remaining clients: {len(self.active_connections)}")

    async def broadcast_json(self, message: dict):
        if not self.active_connections:
            return

        payload = json.dumps(message)
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for d in dead:
            self.disconnect(d)

    def queue_packet(self, packet: PacketRecord):
        self._pending_packets.append(packet)

    async def _packet_batch_worker(self):
        """Batches packets and broadcasts to connected clients every 250ms."""
        while self._running:
            try:
                await asyncio.sleep(0.25)
                if self._pending_packets and self.active_connections:
                    batch = self._pending_packets[:60]
                    self._pending_packets = self._pending_packets[60:]
                    msg = {
                        "type": "packets",
                        "data": [p.model_dump() for p in batch]
                    }
                    await self.broadcast_json(msg)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch broadcast worker: {e}")

    async def broadcast_alert(self, alert: SecurityAlert):
        await self.broadcast_json({
            "type": "alert",
            "data": alert.model_dump()
        })

    async def broadcast_status(self, status: CaptureStatusState):
        await self.broadcast_json({
            "type": "status",
            "data": status.model_dump()
        })

    async def broadcast_event(self, event: TerminalEvent):
        await self.broadcast_json({
            "type": "event",
            "data": event.model_dump()
        })

    async def broadcast_alert_updated(self, alert: SecurityAlert):
        await self.broadcast_json({
            "type": "alert_updated",
            "data": alert.model_dump()
        })


ws_manager = ConnectionManager()
