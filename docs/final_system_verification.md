# Final System Verification & Architecture Specification

## 1. System Architecture

The DPI/IDS/IPS network security operations platform is organized as a decoupled, high-performance cybersecurity telemetry suite:

```
+-----------------------------------------------------------------------------------+
|                            REACT SOC DASHBOARD (SPA)                              |
|   (Vite 8, React 19, TypeScript, Tailwind CSS v4, Lucide React, Recharts)         |
|                                                                                   |
|  [Overview]  [Live Monitor]  [Alerts]  [Flows]  [Packets]  [ML]  [Firewall] ...   |
+------------------------------------+----------------------------------------------+
                                     |
              REST APIs (Axios)      |  WebSocket Real-Time Stream (wsManager)
         GET /api/v1/* (JSON)        |  WS /ws/monitor (JSON Envelopes)
                                     v
+-----------------------------------------------------------------------------------+
|                        FASTAPI CENTRAL BACKEND (Port 8000)                        |
|                                                                                   |
|  [Routers]      /stats, /alerts, /flows, /packets, /ml, /firewall, /notifications |
|  [Adapters]     PipelineAdapter, FirewallAdapter, DPIAdapter                      |
|  [Broadcaster]  PeriodicTrafficBroadcaster (1.0s interval), ws_manager            |
|  [Workers]      NotificationWorker (asynchronous non-blocking queue)              |
+------------------------------------+----------------------------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------------+
|                     DEEP PACKET INSPECTION & IDS/IPS ENGINE                       |
|                                                                                   |
|  - Packet Dispatcher: L2-L4 Protocol Parsing & Flow Tracking (5-tuple table)      |
|  - DPI Engine: L7 Payload Inspection (HTTP, DNS, TLS SNI, SSH, SMTP)             |
|  - IDS Engine: Signature Heuristics, Pattern Detectors, Threat Intelligence IOCs  |
|  - ML Runtime: Dual-Engine Pipeline (Random Forest + Isolation Forest)            |
|  - IPS Enforcer: Stateful IP Blocking (Simulated Gateway vs Windows Netsh)       |
+-----------------------------------------------------------------------------------+
```

---

## 2. Startup Instructions

### Automated One-Click Startup (PowerShell)
Execute the provided script from the repository root:
```powershell
.\start_soc_system.ps1
```

### Manual Individual Service Startup

1. **Start FastAPI Backend**:
   ```powershell
   cd D:\dpi\project_networking
   $env:PYTHONPATH="D:\dpi\project_networking"
   ..\.venv\Scripts\python -m uvicorn backend.api.main:create_app --factory --host 127.0.0.1 --port 8000
   ```
2. **Start Frontend Development Server**:
   ```powershell
   cd D:\dpi\frontend
   npm run dev
   ```
3. **Access Dashboard**:
   Navigate to `http://127.0.0.1:5173`. The topbar will show `WS CONNECTED` with green telemetry indicators.

---

## 3. Attack Simulation & Verification Matrix

The end-to-end attack simulation was executed using synthetic packets and PCAP replay facilities. Detection results were matched directly across the DPI pipeline and dashboard views:

| Attack Scenario | Input Vector | Detected? | Alert Category | Severity | Frontend Target Page | Verification Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. TCP Port Scan** | Synthetic TCP SYN probes across 19 ports | **YES** | `PORT_SCAN` | `HIGH` | Security Alerts & Overview | **VERIFIED** |
| **2. SYN Flood Burst** | Rapid burst of 35 SYN packets (0.01s interval) | **YES** | `SYN_FLOOD` | `CRITICAL` | Alerts & Live Monitoring | **VERIFIED** |
| **3. HTTP SQL Injection** | HTTP URI with `UNION SELECT` statement | **YES** | `SQL_INJECTION` | `HIGH` | Security Alerts (Detail Modal) | **VERIFIED** |
| **4. HTTP XSS** | HTTP URI with `<script>alert(1)</script>` | **YES** | `XSS` | `HIGH` | Security Alerts | **VERIFIED** |
| **5. Directory Traversal** | HTTP request referencing `../../etc/passwd` | **YES** | `PATH_TRAVERSAL` | `HIGH` | Security Alerts | **VERIFIED** |
| **6. DNS Tunneling** | High-entropy pseudo-hex subdomain query | **YES** | `SUSPICIOUS_DNS` | `MEDIUM` | Security Alerts | **VERIFIED** |
| **7. Threat Intel C2 IP** | Traffic from known C2 IOC IP (`198.51.100.23`) | **YES** | `MALICIOUS_IP` | `HIGH` | Alerts & Overview | **VERIFIED** |
| **8. ML Anomaly / Classifier** | Feature vector inference | **YES** | `ML_ANOMALY` | `MEDIUM` | ML Analytics Page | **VERIFIED** |
| **9. Benign Traffic** | Standard HTTP GET for static `index.html` | **NO** | `N/A (Clean)` | `N/A` | Flows & Packets (`ALLOW`) | **VERIFIED** |

*Note: All attack simulations were conducted using synthetic packet generators in an isolated environment. They do not represent promiscuous capture on external untrusted physical networks.*

---

## 4. Firewall Enforcement Distinctions & Safety

The platform strictly differentiates four distinct firewall states:
1. **Alert Generated**: Detection event recorded by signature or anomaly rules. Does **not** automatically drop packets unless prevention policy triggers it.
2. **Block Requested**: An administrative operator submitted `POST /api/v1/firewall/block` with valid `X-API-Key`.
3. **Simulated Block (`SIMULATION`)**: The DPI ingestion pipeline tags the IP 5-tuple as dropped. Does **not** modify operating system kernel rules (default safe laboratory mode).
4. **Active Firewall Block (`ACTUAL_ENFORCEMENT`)**: Explicitly configured Windows `netsh advfirewall` or Linux `iptables` drop rule. Clearly distinguished in the UI badge.

---

## 5. Performance Measurements

- **Initial Frontend Route Load**: 2.61s (initial cold Vite start), subsequent client SPA transitions **< 1.55s**.
- **WebSocket Event-to-UI Latency**: Measured at **< 15ms** local loopback.
- **Console Errors**: **0 console errors** and **0 React warnings** across all 9 pages during live E2E browser inspection.
- **Production Bundle**: `835.79 kB` (`247.20 kB` gzipped), built cleanly in 1.41s.

