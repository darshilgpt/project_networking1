# Deep Packet Inspection (DPI) & Network IDS/IPS Platform with React SOC Dashboard

A modular, high-performance Network Intrusion Detection & Prevention System (IDS/IPS) and Deep Packet Inspection (DPI) telemetry engine with a React SOC Dashboard.

---

## 1. Architecture Overview

- **Packet Capture & Dispatching**: Scapy/Npcap socket ingestion and PCAP replay with L2-L4 protocol decoding (Ethernet, VLAN, IPv4, IPv6, TCP, UDP, ICMP, ARP).
- **Stream Reassembly & DPI**: TCP stream reassembly, out-of-order buffer tracking, and L7 protocol inspection (HTTP, DNS, TLS SNI).
- **Intrusion Detection**: Heuristic signature detectors (SQL injection, XSS, Path traversal, Command injection, Port scanning, SYN flood, DNS tunneling/DGA) and Threat Intelligence IOC reputation matching.
- **Machine Learning**: Asynchronous dual-engine runtime combining supervised attack classification (Random Forest) and unsupervised behavioral anomaly detection (Isolation Forest).
- **Mitigation & IPS**: Stateful IP blocking enforcer supporting safe simulation mode and Windows Defender Firewall (`netsh advfirewall`) integration within a restricted laboratory subnet (`10.10.0.0/24`).
- **REST & Real-Time APIs**: Centralized Python FastAPI backend providing REST endpoints and WebSocket live event streaming (`WS /ws/monitor`).
- **SOC Frontend**: Modern dark-themed Single Page Application built with React 19, TypeScript, Vite, Tailwind CSS v4, Lucide React, and Recharts.

---

## 2. Requirements & Prerequisites

### System Requirements
- **OS**: Windows 10/11 (or Linux)
- **Python**: Python 3.12+ (64-bit)
- **Node.js**: Node.js 18+ (Node.js 20+ recommended)
- **Capture Driver (Optional for Live Interfaces)**: [Npcap](https://npcap.com/) (installed with WinPcap API-compatible mode). If absent, synthetic replay and socket processing remain fully operational.

---

## 3. Quick Start (Run on Any Machine)

### Step 1: Clone the Repository
```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd dpi
```

### Step 2: Set Up Python Backend Environment
```powershell
# Create Python virtual environment
python -m venv .venv

# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install all backend dependencies
python -m pip install --upgrade pip
pip install -r project_networking/requirements.txt
```

### Step 3: Set Up React Frontend Environment
```bash
cd frontend
npm install
cd ..
```

### Step 4: Environment Configuration (Optional)
The backend and frontend come with built-in development defaults (`http://127.0.0.1:8000` and `http://127.0.0.1:5173`).
To customize environment variables:
```powershell
# Backend environment template
copy project_networking\.env.example project_networking\.env

# Frontend environment template
copy frontend\.env.example frontend\.env.local
```

---

## 4. Launching the System

### Automated One-Click Launcher (Windows PowerShell)
```powershell
.\start_soc_system.ps1
```
This launches the FastAPI backend on port 8000 and the React Vite development server on port 5173 in synchronized windows.

### Manual Launch

**Terminal 1 — Python Backend:**
```powershell
cd project_networking
$env:PYTHONPATH="."
..\.venv\Scripts\python -m uvicorn backend.api.main:create_app --factory --host 127.0.0.1 --port 8000
```

**Terminal 2 — React Frontend:**
```powershell
cd frontend
npm run dev
```

Open your browser at **`http://127.0.0.1:5173`**. The topbar indicator will display `WS CONNECTED`.

---

## 5. Verification & Testing

### Backend Unit & Integration Tests (137 tests)
```powershell
cd project_networking
$env:PYTHONPATH="."
..\.venv\Scripts\python -m pytest tests/
```

### Frontend Tests (Vitest)
```bash
cd frontend
npm test
```

### Production Build
```bash
cd frontend
npm run build
```

---

## 6. Directory Structure

```
├── .gitignore                     # Global repository ignore rules
├── README.md                      # Complete setup and execution guide
├── pyproject.toml                 # Root Python project configuration
├── start_soc_system.ps1           # Full-stack PowerShell launcher script
├── docs/                          # Architecture, audit, and remediation documentation
├── frontend/                      # React SOC Dashboard
│   ├── src/                       # TypeScript components, pages, context, and API services
│   ├── package.json               # Frontend dependencies (React, Vite, Recharts, Tailwind v4)
│   └── vite.config.ts             # Rollup code-splitting manual chunks configuration
└── project_networking/            # Core DPI, IDS/IPS, ML & FastAPI Backend
    ├── backend/                   # FastAPI REST routes, schemas, and WebSocket manager
    ├── dpi/                       # Deep Packet Inspection & TCP stream reassembly
    ├── ids/                       # Signature heuristics & Threat Intelligence IOC engine
    ├── ips/                       # Windows Firewall enforcer & blocking manager
    ├── ml/                        # Isolation Forest & Random Forest models and runtime
    ├── parser/                    # Packet dispatcher & protocol decoders
    ├── requirements.txt           # Python dependency specifications
    └── tests/                     # 137 unit and integration test suites
```
