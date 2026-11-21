# NETSCOPE X — Real-time Network Monitoring & Forensics Platform

NETSCOPE X is a modern, high-performance network security operations center (SOC) application for real-time traffic analysis, live packet inspection, explainable threat detection, and offline PCAP forensics on Windows.

---

## Architecture Overview

```
NETSCOPE-X/
├── frontend/                     # React + TypeScript + Vite GUI
│   ├── src/                      # UI components, pages, state management
│   ├── public/                   # Static assets & emblems
│   ├── package.json              # Frontend scripts & dependencies
│   └── vite.config.ts            # Reverse proxy (/api, /ws -> :8000)
│
├── backend/                      # Python FastAPI Backend
│   ├── app/
│   │   ├── main.py               # FastAPI entry point, CORS, lifespan, SPA mount
│   │   ├── config.py             # App configuration & environment loader
│   │   ├── api/                  # REST API route handlers
│   │   │   ├── routes.py         # Consolidated API router & /api/health
│   │   │   ├── capture_routes.py # /api/interfaces, /api/capture/*
│   │   │   ├── analytics_routes.py # /api/packets, /api/stats, /api/topology
│   │   │   ├── detection_routes.py # /api/alerts, /api/simulation/*, /api/ai/*
│   │   │   └── pcap_routes.py    # /api/forensics/*
│   │   ├── capture/              # Live TShark packet capture & interface discovery
│   │   │   ├── tshark_manager.py # Subprocess management & streaming
│   │   │   ├── interface_manager.py # Npcap device discovery & psutil stats
│   │   │   └── packet_parser.py  # High-throughput packet parser
│   │   ├── analyzer/             # Real-time traffic analysis
│   │   │   ├── traffic_analyzer.py # Stats aggregation & network topology graph
│   │   │   ├── protocol_analyzer.py # Protocol & RFC1918 classification
│   │   │   └── connection_tracker.py # 5-tuple state tracking
│   │   ├── detection/            # Explainable rule-based threat engine
│   │   │   ├── detection_engine.py # Correlating threat engine & risk scoring
│   │   │   ├── port_scan_detector.py # Port enumeration (PS-01)
│   │   │   ├── traffic_spike_detector.py # Surge (VOL-03) & SYN anomaly (SYN-02)
│   │   │   └── dns_anomaly_detector.py # DNS tunneling & lateral fanout (CON-05)
│   │   ├── database/             # SQLite persistent storage
│   │   │   ├── database.py       # SQLAlchemy engine & session maker
│   │   │   ├── models.py         # Sessions, packets, alerts, events models
│   │   │   └── repositories.py   # Data access layer
│   │   ├── websocket/            # Real-time streaming
│   │   │   └── packet_stream.py  # WebSocket broadcast & bounded packet queue
│   │   ├── forensics/            # Offline PCAP & PCAPNG forensics
│   │   │   └── pcap_analyzer.py  # TShark-powered PCAP trace parser
│   │   ├── services/             # Business logic layer
│   │   │   ├── statistics_service.py # In-memory ring buffer & simulation lab
│   │   │   └── incident_service.py # IP intelligence & AI SOC investigator
│   │   └── schemas/              # Pydantic validation schemas
│   │       └── packet_schema.py  # Types matching frontend TypeScript contracts
│   ├── tests/                    # Automated test suite
│   ├── data/                     # Persistent SQLite databases
│   ├── uploads/                  # Managed PCAP uploads
│   ├── logs/                     # Application logs
│   ├── requirements.txt          # Python dependencies
│   ├── .env.example              # Environment variables template
│   └── .gitignore
│
├── README.md                     # Documentation
├── run_backend.bat               # One-click Windows backend launcher
└── run_frontend.bat              # One-click Windows frontend launcher
```

---

## Prerequisites

1. **Operating System:** Windows 10 / 11 (64-bit)
2. **Python:** Python 3.10+ (Python 3.12 recommended)
3. **Wireshark & TShark:** [Wireshark](https://www.wireshark.org/) installed with **Npcap**.
   - Default TShark path: `C:\Program Files\Wireshark\tshark.exe`
4. **Node.js:** Node.js 18+ and npm (for frontend development)

---

## Quick Start (Windows)

### 1. Launch the Backend
Double-click `run_backend.bat` or run in terminal:
```cmd
run_backend.bat
```
This script will:
- Verify Python and TShark installations.
- Install backend dependencies (`pip install -r backend\requirements.txt`).
- Initialize the SQLite database.
- Start the FastAPI backend on **`http://127.0.0.1:8000`** with auto-reload.

### 2. Launch the Frontend
Double-click `run_frontend.bat` or run in terminal:
```cmd
cd frontend
npm install
npm run dev
```
Open **`http://localhost:3000`** in your browser to access NETSCOPE X.

---

## API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check & service status |
| `GET` | `/api/interfaces` | List available network interfaces (Npcap + psutil) |
| `GET` | `/api/capture/status` | Current capture state, active interface, packet count |
| `POST` | `/api/capture/start` | Start live TShark packet capture on selected interface |
| `POST` | `/api/capture/stop` | Stop live packet capture session |
| `GET` | `/api/sessions` | List past capture sessions |
| `GET` | `/api/packets` | Query, filter, and paginate live and historic packets |
| `GET` | `/api/packets/export` | Export packets as JSON, CSV, or raw PCAP (`?format=csv/json/pcap`) |
| `GET` | `/api/stats` | Real-time traffic statistics and time-series buckets |
| `GET` | `/api/topology` | Network topology nodes & conversation edges |
| `GET` | `/api/alerts` | List security alerts and threat detections |
| `PATCH` | `/api/alerts/{id}` | Update alert status, analyst notes, or false positive flag |
| `GET` | `/api/events` | SOC terminal activity log feed |
| `GET` | `/api/settings` | Get detection thresholds and application configuration |
| `PUT` | `/api/settings` | Update thresholds or GUI preferences |
| `GET` | `/api/intel/{ip}` | ASN, Geolocation, and reputation lookup (RFC1918 protected) |
| `POST` | `/api/forensics/upload` | Upload `.pcap`, `.pcapng`, or `.cap` trace for analysis |
| `POST` | `/api/forensics/sample` | Analyze bundled sample forensic reconnaissance trace |
| `POST` | `/api/simulation/run` | Execute controlled attack scenario in Simulation Lab |
| `POST` | `/api/simulation/stop` | Halt active simulation |
| `POST` | `/api/simulation/clear`| Clear simulation artifacts |
| `POST` | `/api/ai/investigate` | AI SOC analyst investigation report (Gemini or deterministic) |
| `WS` | `/ws` / `/ws/packets` | High-frequency packet and alert streaming |

---

## Threat Detection Rules

1. **Multi-Port Enumeration (PS-01):** Detects sequential/random port scanning across unique ports within a rolling observation window.
2. **Half-Open SYN Flood Heuristic (SYN-02):** Detects excessive unacknowledged SYN packets without corresponding completions.
3. **Bandwidth & Rate Surge (VOL-03):** Flags abnormal throughput surges exceeding baseline rate multipliers.
4. **DNS Query Burst & Tunneling (DNS-04):** Identifies high-frequency DNS query rates and elevated NXDOMAIN failure ratios.
5. **Lateral Connection Fanout (CON-05):** Flags rapid internal peer spread indicating potential lateral movement.

Every alert includes:
- Calculated deterministic risk score (0-100) with explicit formula breakdown.
- Severity rating (`Informational`, `Low`, `Medium`, `High`, `Critical`).
- Corroborating forensic evidence and packet counts.
- Recommended containment steps.

---

## Running Automated Tests

Run backend tests using pytest:
```cmd
cd backend
python -m pytest tests/ -v
```
All 13 integration and unit tests cover:
- Health and REST API contracts
- Interface discovery & TShark argument resolution
- Live packet parsing & TCP flag extraction
- Threat detection engine (port scans, SYN anomalies)
- Protocol classification and private IP validation

---

## Troubleshooting

- **Permission Denied on Interface:**
  - Make sure Npcap was installed with the option "Support raw 802.11 traffic" or run the backend from an elevated terminal if your Windows user lacks permission to access raw Npcap adapter devices.
- **TShark not found:**
  - Check that Wireshark is installed at `C:\Program Files\Wireshark\tshark.exe`. If installed in another folder, edit `TSHARK_PATH` in `backend\.env`.
- **Frontend cannot reach Backend:**
  - Verify the backend is running on `http://127.0.0.1:8000` (check `http://127.0.0.1:8000/api/health`).
  - Vite dev server automatically proxies `/api` and `/ws` to port 8000.
