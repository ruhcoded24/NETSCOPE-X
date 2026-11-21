import asyncio
import logging
import os
import time
import datetime
from typing import Optional, Callable, List, Set, Dict, Any
from app.config import settings
from app.schemas.packet_schema import PacketRecord, CaptureSessionSummary, CaptureStatusState
from app.capture.packet_parser import parse_tshark_line
from app.capture.interface_manager import interface_manager

logger = logging.getLogger("netscope.tshark")


class TSharkManager:
    def __init__(self):
        self.tshark_path: str = settings.TSHARK_PATH
        self.process: Optional[asyncio.subprocess.Process] = None
        self._reader_task: Optional[asyncio.Task] = None
        self.capturing: bool = False
        self.active_interface: str = ""
        self.active_interface_friendly: str = ""
        self.current_session: Optional[CaptureSessionSummary] = None
        self.packet_count: int = 0
        self.byte_count: int = 0
        self.alert_count: int = 0
        self.host_ips: Set[str] = set()

        # Callbacks for packet streaming and state changes
        self._on_packet_callbacks: List[Callable[[PacketRecord], Any]] = []
        self._on_status_callbacks: List[Callable[[CaptureStatusState], Any]] = []
        self._on_error_callbacks: List[Callable[[str], Any]] = []

    def register_on_packet(self, cb: Callable[[PacketRecord], Any]):
        self._on_packet_callbacks.append(cb)

    def register_on_status(self, cb: Callable[[CaptureStatusState], Any]):
        self._on_status_callbacks.append(cb)

    def register_on_error(self, cb: Callable[[str], Any]):
        self._on_error_callbacks.append(cb)

    def _refresh_host_ips(self):
        ips = set()
        try:
            for iface in interface_manager.get_interfaces():
                if iface.ipv4:
                    ips.add(iface.ipv4)
                if iface.ipv6:
                    ips.add(iface.ipv6)
        except Exception as e:
            logger.warning(f"Failed to refresh host IPs: {e}")
        self.host_ips = ips

    async def start_capture(self, requested_interface: Optional[str] = None) -> CaptureStatusState:
        if self.capturing:
            logger.warning("Capture is already active. Stopping existing session before restart.")
            await self.stop_capture()

        # Check executable existence
        if not os.path.exists(self.tshark_path):
            err_msg = f"TShark executable not found at {self.tshark_path}. Please check Wireshark installation."
            logger.error(err_msg)
            for cb in self._on_error_callbacks:
                cb(err_msg)
            raise FileNotFoundError(err_msg)

        # Resolve interface
        dev_arg, friendly_name = interface_manager.resolve_tshark_interface(requested_interface)
        self.active_interface = dev_arg
        self.active_interface_friendly = friendly_name
        self._refresh_host_ips()

        session_id = f"sess_{int(time.time())}_{friendly_name.replace(' ', '_')}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.current_session = CaptureSessionSummary(
            id=session_id,
            interfaceName=friendly_name,
            mode="Live TShark Capture",
            startedAt=now_iso,
            active=True
        )
        self.packet_count = 0
        self.byte_count = 0

        # Construct TShark command with tab-separated field output
        cmd = [
            self.tshark_path,
            "-i", dev_arg,
            "-l",  # Line-buffered stdout
            "-n",  # Disable network object name resolution for high performance
            "-T", "fields",
            "-E", "separator=/t",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "tcp.flags.str",
            "-e", "ip.ttl",
            "-e", "dns.qry.name",
            "-e", "dns.flags.rcode",
            "-e", "http.request.method",
            "-e", "http.host",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "_ws.col.Info"
        ]

        logger.info(f"Starting TShark capture on '{friendly_name}' (device: {dev_arg}): {' '.join(cmd[:6])}")

        try:
            self.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.capturing = True
            self._reader_task = asyncio.create_task(self._read_tshark_output())
        except Exception as e:
            self.capturing = False
            self.current_session = None
            err_msg = f"Failed to spawn TShark subprocess: {str(e)}"
            logger.error(err_msg)
            for cb in self._on_error_callbacks:
                cb(err_msg)
            raise RuntimeError(err_msg)

        status = self.get_status()
        for cb in self._on_status_callbacks:
            cb(status)
        return status

    async def _read_tshark_output(self):
        """Asynchronously reads and parses lines from TShark stdout."""
        if not self.process or not self.process.stdout:
            return

        try:
            while self.capturing and not self.process.stdout.at_eof():
                line_bytes = await self.process.stdout.readline()
                if not line_bytes:
                    break

                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                packet = parse_tshark_line(line, self.active_interface_friendly, self.host_ips)
                if packet:
                    self.packet_count += 1
                    self.byte_count += packet.size
                    if self.current_session:
                        self.current_session.packetCount = self.packet_count
                        self.current_session.byteCount = self.byte_count

                    # Dispatch to listeners
                    for cb in self._on_packet_callbacks:
                        try:
                            cb(packet)
                        except Exception as ex:
                            logger.error(f"Error in packet callback: {ex}")

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"TShark stream reader encountered exception: {e}")
        finally:
            # Check stderr for any driver or permission error
            if self.process and self.process.stderr:
                try:
                    err_bytes = await self.process.stderr.read()
                    err_text = err_bytes.decode("utf-8", errors="replace").strip()
                    if err_text and ("permission" in err_text.lower() or "error" in err_text.lower()):
                        logger.error(f"TShark stderr: {err_text}")
                        for cb in self._on_error_callbacks:
                            cb(f"TShark warning: {err_text}")
                except Exception:
                    pass

    async def stop_capture(self) -> CaptureStatusState:
        if not self.capturing and not self.process:
            return self.get_status()

        logger.info("Stopping TShark packet capture session.")
        self.capturing = False

        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()

        if self.process:
            try:
                self.process.terminate()
                try:
                    await asyncio.wait_for(self.process.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    self.process.kill()
                    await self.process.wait()
            except Exception as e:
                logger.warning(f"Error terminating TShark process: {e}")
            finally:
                self.process = None

        if self.current_session:
            self.current_session.active = False
            self.current_session.stoppedAt = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.current_session.packetCount = self.packet_count
            self.current_session.byteCount = self.byte_count

        status = self.get_status()
        for cb in self._on_status_callbacks:
            cb(status)
        return status

    def get_status(self) -> CaptureStatusState:
        return CaptureStatusState(
            capturing=self.capturing,
            activeInterface=self.active_interface_friendly or settings.DEFAULT_INTERFACE,
            captureMode="Live TShark Capture" if self.capturing else "Stopped",
            activeSession=self.current_session,
            packetCount=self.packet_count,
            alertCount=self.alert_count,
            simulationActive=False,
            activeScenario=None
        )


tshark_manager = TSharkManager()
