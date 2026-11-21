import io
import csv
import json
import datetime
from fastapi import APIRouter, Query, Response, HTTPException
from typing import Optional, Dict, Any

from app.schemas.packet_schema import (
    TrafficStats, AppSettings, IpIntelResult
)
from app.services.statistics_service import statistics_service
from app.services.incident_service import incident_service

router = APIRouter(tags=["Analytics"])


@router.get("/packets")
async def get_packets(
    search: Optional[str] = None,
    sourceIp: Optional[str] = None,
    destinationIp: Optional[str] = None,
    sourcePort: Optional[str] = None,
    destinationPort: Optional[str] = None,
    protocol: Optional[str] = "ALL",
    minSize: Optional[int] = None,
    maxSize: Optional[int] = None,
    tcpFlag: Optional[str] = "ALL",
    includeSimulated: bool = True,
    onlySimulated: bool = False,
    sortBy: str = "timestamp",
    sortDir: str = "desc",
    page: int = 1,
    pageSize: int = 50,
):
    items, total = statistics_service.get_packets(
        search=search,
        source_ip=sourceIp,
        destination_ip=destinationIp,
        source_port=sourcePort,
        destination_port=destinationPort,
        protocol=protocol,
        min_size=minSize,
        max_size=maxSize,
        tcp_flag=tcpFlag,
        include_simulated=includeSimulated,
        only_simulated=onlySimulated,
        sort_by=sortBy,
        sort_dir=sortDir,
        page=page,
        page_size=pageSize
    )
    return {
        "items": [p.model_dump() for p in items],
        "total": total
    }


@router.get("/packets/export")
async def export_packets(
    format: str = "json",
    includeSimulated: bool = False,
    confirmPrivacy: bool = False
):
    pkts, _ = statistics_service.get_packets(
        include_simulated=includeSimulated,
        page=1,
        page_size=10000
    )

    fmt = format.lower()
    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Timestamp", "EpochMs", "Source IP", "Destination IP",
            "Source Port", "Destination Port", "Protocol", "Size", "TCP Flags", "Summary"
        ])
        for p in pkts:
            writer.writerow([
                p.id, p.timestamp, p.epochMs, p.sourceIp, p.destinationIp,
                p.sourcePort or "", p.destinationPort or "", p.protocol,
                p.size, "|".join(p.tcpFlags), p.summary
            ])
        csv_data = output.getvalue()
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="netscope-capture.csv"'}
        )

    if fmt == "pcap":
        if not confirmPrivacy:
            raise HTTPException(status_code=400, detail="PCAP export requires explicit privacy confirmation (?confirmPrivacy=true).")

        # Create basic PCAP global header and packet records (tcpdump format)
        pcap_buf = bytearray()
        # PCAP Global Header: magic (0xa1b2c3d4), version 2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
        pcap_buf += b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'
        for p in pkts:
            sec = int(p.epochMs // 1000)
            usec = int((p.epochMs % 1000) * 1000)
            length = min(p.size, 1514)
            # Packet header: ts_sec (4B), ts_usec (4B), incl_len (4B), orig_len (4B)
            pcap_buf += sec.to_bytes(4, byteorder='little')
            pcap_buf += usec.to_bytes(4, byteorder='little')
            pcap_buf += length.to_bytes(4, byteorder='little')
            pcap_buf += length.to_bytes(4, byteorder='little')
            # Simulated dummy packet bytes
            pcap_buf += b'\x00' * length

        return Response(
            content=bytes(pcap_buf),
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": 'attachment; filename="netscope-capture.pcap"'}
        )

    # JSON export
    data = {
        "exportedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "count": len(pkts),
        "packets": [p.model_dump() for p in pkts]
    }
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="netscope-capture.json"'}
    )


@router.get("/stats", response_model=TrafficStats)
async def get_stats(windowSeconds: int = 300, includeSimulated: bool = False):
    return statistics_service.get_stats(windowSeconds, includeSimulated)


@router.get("/topology")
async def get_topology(protocol: str = "ALL", includeSimulated: bool = True):
    nodes, edges = statistics_service.get_topology(protocol, includeSimulated)
    return {
        "nodes": [n.model_dump() for n in nodes],
        "edges": [e.model_dump() for e in edges]
    }


@router.get("/events")
async def get_events():
    events = statistics_service.get_events()
    return {"events": [e.model_dump() for e in events]}


@router.get("/settings", response_model=AppSettings)
async def get_settings():
    return statistics_service.get_settings()


@router.put("/settings", response_model=AppSettings)
async def update_settings(patch: Dict[str, Any]):
    return statistics_service.update_settings(patch)


@router.get("/intel/{ip}", response_model=IpIntelResult)
async def get_ip_intel(ip: str):
    return await incident_service.lookup_ip_intel(ip)
