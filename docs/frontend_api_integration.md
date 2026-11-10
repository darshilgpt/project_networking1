# Frontend REST API & WebSocket Integration Guide

## 1. Overview

The Deep Packet Inspection & Intrusion Detection/Prevention SOC dashboard communicates with the central Python FastAPI backend via:
1. **REST APIs** (`/api/v1/*`): Resource querying, alert filtering, flow inspection, bounded packet header inspection, ML status telemetry, and administrative firewall block/unblock mutations.
2. **WebSocket Stream** (`WS /ws/monitor`): Low-latency real-time event delivery including live packet throughput velocity, new security alert broadcasts, flow lifecycle events, ML classification updates, and firewall changes.

---

## 2. Integrated REST Endpoints

All endpoints are invoked using a centralized Axios client in `frontend/src/services/api/client.ts` with typed contracts defined in `types.ts`:

| Method | Endpoint | Query / Body Parameters | Response Schema | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/stats` | None | `StatisticsResponse` | Aggregated DPI ingestion rates, flow counts, alert tallies, and protocol breakdown. |
| `GET` | `/api/v1/alerts` | `limit`, `offset`, `severity`, `category`, `source_ip` | `AlertListResponse` | Paginated security alerts with filtering. |
| `GET` | `/api/v1/alerts/{alert_id}` | Path param `alert_id` | `AlertItem` | Detailed alert forensic record. |
| `GET` | `/api/v1/flows` | `limit`, `offset`, `protocol`, `source_ip`, `destination_ip`, `is_active` | `FlowListResponse` | Active and historical IP 5-tuple flow records. |
| `GET` | `/api/v1/flows/{flow_id}` | Path param `flow_id` | `FlowItem` | Flow details and TCP state transition details. |
| `GET` | `/api/v1/packets` | `limit` (max 100), `offset` | `PacketListResponse` | Bounded packet header metadata (payload bytes strictly excluded). |
| `GET` | `/api/v1/ml/status` | None | `MLStatusResponse` | Operational availability of Random Forest & Isolation Forest, queue depth and capacity. |
| `GET` | `/api/v1/ml/metrics` | None | `MLMetricsResponse` | Ingestion latency, classification counts, anomaly detections, and worker metrics. |
| `GET` | `/api/v1/firewall/rules` | None | `FirewallRulesListResponse` | Active firewall mitigation rules and enforcement mode (`SIMULATION` vs `ACTUAL_ENFORCEMENT`). |
| `POST` | `/api/v1/firewall/block` | Body: `{ ip_address, duration_seconds, reason }` | `FirewallOperationResponse` | Dynamically block an IP. Requires `X-API-Key` or `Authorization: Bearer <key>`. |
| `DELETE` | `/api/v1/firewall/block/{rule_id}` | Path param `rule_id` | `FirewallOperationResponse` | Remove dynamic IP block. Requires administrative API key authorization. |
| `GET` | `/api/v1/notifications/status` | None | `NotificationStatusResponse` | Delivery counts, suppression counts, and worker queue health. Secrets excluded. |

---

## 3. WebSocket Real-Time Stream

### Endpoint
`WS /ws/monitor?token=<token>` (or `Sec-WebSocket-Protocol` header)

### Standard Message Envelope
```json
{
  "event": "event_name",
  "timestamp": "2026-11-10T09:40:00.000000+00:00",
  "data": {}
}
```

### Supported Event Types
1. `new_alert`: Fired when signature heuristics or ML models flag hostile traffic.
2. `traffic_update`: Broadcast periodically (cadence: 1.0s) with live PPS, bytes/sec, active flows, and workers.
3. `new_flow`: Broadcast when a new 5-tuple TCP/UDP session is established.
4. `ml_event`: Broadcast when an anomaly or high-confidence classification occurs.
5. `firewall_event`: Broadcast when an IP block or unblock rule takes effect.
6. `notification_event`: Broadcast on email dispatch or duplicate cooldown suppression.
7. `system_status`: Initial state pushed upon connection handshake.

### Robustness & Safety
- **Reconnection with Backoff**: Reconnects automatically on network interruption using exponential backoff with random jitter.
- **Malformed Packet Protection**: Corrupted or non-JSON WebSocket frames are discarded without throwing exceptions.
- **Bounded State Growth**: Frontend stores a maximum of 50 recent live alerts in memory to prevent memory leaks during prolonged monitoring.

---

## 4. Environment Variables

Configure environment settings in `frontend/.env.local` (see `frontend/.env.example`):

```bash
# REST API Base URL
VITE_API_BASE_URL=http://127.0.0.1:8000

# WebSocket Base URL
VITE_WS_URL=ws://127.0.0.1:8000/ws/monitor

# WebSocket Token (optional in local development if WS_ALLOW_ANONYMOUS_DEV=true)
VITE_WS_TOKEN=dpi-admin-secret-key
```

---

## 5. Security & Authorization Policy

1. **In-Memory Admin API Key**: Administrative credentials required for firewall mutations (`POST /block`, `DELETE /block`) are held exclusively in React state memory via `SecurityContext`. Keys are **never** persisted to `localStorage`, `sessionStorage`, or cookies.
2. **Payload Protection**: Packet inspection displays bounded L3/L4/L7 headers. Raw packet payload hex/ASCII bytes are omitted to prevent credential exfiltration.
3. **Truthful Mitigation Reporting**: The UI explicitly flags whether the firewall is running in `SIMULATION` mode or active OS kernel enforcement (`Netsh / IPTables`).

---

## 6. How to Run Frontend and Backend Together Locally

### Step 1: Start Python FastAPI Backend
```powershell
cd D:\dpi
# Activate virtual environment
.\.venv\Scripts\Activate.ps1
cd project_networking

# Run uvicorn on port 8000
python -m uvicorn backend.api.main:create_app --factory --host 127.0.0.1 --port 8000
```

### Step 2: Start React Frontend Development Server
```powershell
cd D:\dpi\frontend
npm run dev
```

### Step 3: Open SOC Dashboard
Navigate to `http://127.0.0.1:5173` in your browser. Telemetry will automatically stream from the backend.

