import base64
import uuid
from pathlib import Path
from fastapi import APIRouter, HTTPException

from app.config import settings
from app.schemas.packet_schema import ForensicReport, PcapUploadRequest
from app.forensics.pcap_analyzer import pcap_analyzer
from app.services.statistics_service import statistics_service

router = APIRouter(prefix="/forensics", tags=["PCAP Forensics"])


@router.post("/upload", response_model=ForensicReport)
async def upload_pcap(req: PcapUploadRequest):
    if not req.base64Data:
        raise HTTPException(status_code=400, detail="No PCAP/PCAPNG file payload supplied.")

    fn = req.fileName.lower()
    if not (fn.endswith(".pcap") or fn.endswith(".pcapng") or fn.endswith(".cap")):
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, or .cap binary files are permitted.")

    try:
        raw_bytes = base64.b64decode(req.base64Data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Base64 payload.")

    if len(raw_bytes) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {settings.MAX_UPLOAD_SIZE_MB} MB safety limit."
        )

    # Save to uploads directory
    safe_name = f"{uuid.uuid4().hex}_{req.fileName}"
    target_path = settings.uploads_path / safe_name
    with open(target_path, "wb") as f:
        f.write(raw_bytes)

    try:
        report = pcap_analyzer.analyze_pcap_file(str(target_path), req.fileName)
        statistics_service.add_event(
            category="forensics",
            severity="success",
            message=f"PCAP analysis completed for {req.fileName}: {report.packetCount} packets, {len(report.alerts)} alerts."
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to analyze capture: {str(e)}")


@router.post("/sample", response_model=ForensicReport)
async def analyze_sample_pcap():
    # Create sample synthetic PCAP in uploads and analyze it
    sample_path = settings.uploads_path / "sample_lab_recon.pcap"

    # Write a standard PCAP file if not already existing
    pcap_buf = bytearray()
    pcap_buf += b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'

    now_sec = int(1795195000)
    for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]:
        sec = now_sec + (port % 10)
        usec = 1000 * port
        length = 64
        pcap_buf += sec.to_bytes(4, byteorder='little')
        pcap_buf += usec.to_bytes(4, byteorder='little')
        pcap_buf += length.to_bytes(4, byteorder='little')
        pcap_buf += length.to_bytes(4, byteorder='little')
        pcap_buf += b'\x00' * length

    with open(sample_path, "wb") as f:
        f.write(pcap_buf)

    report = pcap_analyzer.analyze_pcap_file(str(sample_path), "sample_lab_recon.pcap")
    return report
