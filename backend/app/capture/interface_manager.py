import subprocess
import re
import socket
import logging
from typing import List, Dict, Optional, Tuple
import psutil

from app.config import settings
from app.schemas.packet_schema import NetworkInterfaceInfo

logger = logging.getLogger("netscope.interface_manager")


class InterfaceManager:
    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_path = tshark_path or settings.TSHARK_PATH
        self._cached_interfaces: List[NetworkInterfaceInfo] = []
        self._tshark_device_map: Dict[str, Dict[str, str]] = {}  # friendly_name -> {index, device_id}
        self._last_tshark_scan_ts: float = 0.0

    def _query_tshark_interfaces(self) -> Dict[str, Dict[str, str]]:
        """
        Parses `tshark -D` output, e.g.:
        1. \\Device\\NPF_{GUID} (Wi-Fi)
        11. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)
        """
        import time
        now = time.time()
        if (now - self._last_tshark_scan_ts < 60.0):
            return self._tshark_device_map

        device_map = {}
        try:
            res = subprocess.run(
                [self.tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=12,
                check=False
            )
            if res.returncode == 0:
                for line in res.stdout.strip().splitlines():
                    line = line.strip()
                    # Pattern: <index>. <device_path> (<description>)
                    match = re.match(r"^(\d+)\.\s+(\\Device\\NPF_\S+|[^\s(]+)(?:\s+\((.*)\))?", line)
                    if match:
                        idx = match.group(1)
                        dev_path = match.group(2)
                        desc = match.group(3) or dev_path
                        friendly = desc.strip()
                        device_map[friendly] = {
                            "index": idx,
                            "device": dev_path,
                            "raw": line
                        }
                        # Also index by device path and index number
                        device_map[dev_path] = {
                            "index": idx,
                            "device": dev_path,
                            "raw": line
                        }
                        device_map[idx] = {
                            "index": idx,
                            "device": dev_path,
                            "raw": line
                        }
        except Exception as e:
            logger.warning(f"Failed to query tshark -D: {e}")
        finally:
            self._last_tshark_scan_ts = now
            self._tshark_device_map = device_map

        return device_map

    def get_interfaces(self) -> List[NetworkInterfaceInfo]:
        """
        Combines TShark discovery with psutil network adapter details (IPs, MAC, counters, status).
        """
        tshark_map = self._query_tshark_interfaces()
        self._tshark_device_map = tshark_map

        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)

        interfaces: List[NetworkInterfaceInfo] = []
        seen_names = set()

        for iface_name, addr_list in addrs.items():
            seen_names.add(iface_name)
            ipv4: Optional[str] = None
            ipv6: Optional[str] = None
            mac: Optional[str] = None

            for a in addr_list:
                if a.family == socket.AF_INET:
                    ipv4 = a.address
                elif a.family == socket.AF_INET6:
                    # Strip interface index if present
                    clean_v6 = a.address.split('%')[0]
                    ipv6 = clean_v6
                elif hasattr(psutil, 'AF_LINK') and a.family == psutil.AF_LINK:
                    mac = a.address

            is_up = True
            if iface_name in stats:
                is_up = stats[iface_name].isup

            rx_bytes = 0
            tx_bytes = 0
            rx_packets = 0
            tx_packets = 0
            if iface_name in io_counters:
                ioc = io_counters[iface_name]
                rx_bytes = ioc.bytes_recv
                tx_bytes = ioc.bytes_sent
                rx_packets = ioc.packets_recv
                tx_packets = ioc.packets_sent

            is_loopback = bool("loopback" in iface_name.lower() or (ipv4 and ipv4.startswith("127.")))

            # Match friendly name with TShark
            tshark_info = tshark_map.get(iface_name)

            interfaces.append(NetworkInterfaceInfo(
                name=iface_name,
                ipv4=ipv4,
                ipv6=ipv6,
                mac=mac,
                internal=bool(is_loopback),
                rxBytes=int(rx_bytes or 0),
                txBytes=int(tx_bytes or 0),
                rxPackets=int(rx_packets or 0),
                txPackets=int(tx_packets or 0),
                status="up" if is_up else "down"
            ))

        # Check any TShark interfaces not in psutil (e.g. NPF_Loopback)
        for name, data in tshark_map.items():
            if name.isdigit() or name.startswith("\\Device\\"):
                continue
            if name not in seen_names:
                interfaces.append(NetworkInterfaceInfo(
                    name=name,
                    ipv4="127.0.0.1" if "loopback" in name.lower() else None,
                    ipv6=None,
                    mac=None,
                    internal=bool("loopback" in name.lower()),
                    rxBytes=0,
                    txBytes=0,
                    rxPackets=0,
                    txPackets=0,
                    status="up"
                ))
                seen_names.add(name)

        # Sort so active interfaces with real packet traffic (e.g. Wi-Fi) are prioritized at top
        def sort_key(i: NetworkInterfaceInfo):
            score = 0
            if i.status == "up":
                score += 10
            if i.ipv4 and not i.internal:
                score += 20
            # Strongly prioritize the active interface with actual network traffic
            total_traffic = (i.rxPackets or 0) + (i.txPackets or 0)
            if total_traffic > 100:
                score += 100
            if total_traffic > 10000:
                score += 200
            if "wi-fi" in i.name.lower():
                score += 50
            elif "ethernet" in i.name.lower() and "vmware" not in i.name.lower() and "virtual" not in i.name.lower():
                score += 15
            return -score

        interfaces.sort(key=sort_key)
        self._cached_interfaces = interfaces
        return interfaces

    def resolve_tshark_interface(self, requested_name: Optional[str]) -> Tuple[str, str]:
        """
        Resolves a requested interface name into:
        (tshark_interface_identifier, friendly_name)
        Returns interface suitable for passing to `tshark -i <identifier>`.
        """
        tshark_map = self._query_tshark_interfaces()
        interfaces = self.get_interfaces()

        if not requested_name or requested_name == "default":
            # Pick first active non-internal interface with IPv4
            for iface in interfaces:
                if iface.status == "up" and iface.ipv4 and not iface.internal:
                    requested_name = iface.name
                    break
            if not requested_name and interfaces:
                requested_name = interfaces[0].name
            elif not requested_name:
                requested_name = "1"

        # Check if requested name exists in TShark map
        if requested_name in tshark_map:
            mapping = tshark_map[requested_name]
            return mapping["index"], requested_name

        # Fuzzy check: look for partial match in friendly names
        for friendly_name, mapping in tshark_map.items():
            if requested_name.lower() in friendly_name.lower() or friendly_name.lower() in requested_name.lower():
                return mapping["index"], friendly_name

        # Fallback to device path or index directly
        return requested_name, requested_name


interface_manager = InterfaceManager()
