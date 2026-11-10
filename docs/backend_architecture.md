# Backend Architecture Documentation — Phase 7 (Complete)

## Overview
The DPI/IDS/IPS central security backend provides a unified, production-grade asynchronous FastAPI service that exposes:
1. Standardized REST APIs for alerts, network flows, bounded packet metadata, ML metrics, and administrative firewall controls (Phase 7.1 & 7.2).
2. Automated background security email notification pipeline with qualification criteria, cooldown deduplication, and non-blocking delivery (Phase 7.1).
3. Real-time WebSocket event streaming at `/ws/monitor` with thread-safe worker handoff, bounded outgoing client queues, backpressure handling, and ping/pong heartbeats for the React frontend dashboard (Phase 7.3).

All features integrate seamlessly into the existing packet processing pipeline without duplicating engines, without blocking packet processing threads, and without exposing sensitive credentials or raw packet payloads.

```
                           +----------------------------+
                           |   Live Network / PCAP      |
                           +--------------+-------------+
                                          |
                                          v
                           +----------------------------+
                           |    Existing DPI Pipeline   |
                           |  (Dispatcher, Reassembler, |
                           |   DPI Engine, IDS Engine)  |
                           +--------------+-------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------------+
|                               FastAPI Service Container                                 |
|                                                                                         |
|    +----------------------+   read-only   +---------------------------------------+     |
|    |   PipelineAdapter    | <------------ |          PipelineWorkerPool           |     |
|    |   & FirewallAdapter  |               |          & MLRuntimeEngine            |     |
|    +-----------+----------+               +---------------------------------------+     |
|                |                                      |                                 |
|                |                                      | thread-safe handoff             |
|                |                                      v                                 |
|                |                          +---------------------------------------+     |
|                |                          |       WebSocket Event Manager         |     |
|                |                          |      (Bounded Bridge Queue: 1000)     |     |
|                |                          +-------------------+-------------------+     |
|                |                                              |                         |
|                |                                              v fan-out (non-blocking)  |
|                |                          +---------------------------------------+     |
|                |                          |    Connected WebSocket Clients        |     |
|                |                          |     (WS /ws/monitor, Bounded 100)     |     |
|                |                          +---------------------------------------+     |
|                v                                                                        |
|    +------------------------------------------------------------------------------+     |
|    |                            FastAPI REST API Layer                            |     |
|    |   - GET /api/v1/health                                                       |     |
|    |   - GET /api/v1/alerts, GET /api/v1/alerts/{alert_id}                        |     |
|    |   - GET /api/v1/flows, GET /api/v1/flows/{flow_id}                           |     |
|    |   - GET /api/v1/packets (Metadata only, payload strictly redacted)           |     |
|    |   - GET /api/v1/stats                                                        |     |
|    |   - GET /api/v1/ml/metrics, GET /api/v1/ml/status                            |     |
|    |   - GET /api/v1/firewall/rules                                               |     |
|    |   - POST /api/v1/firewall/block (Admin auth protected)                       |     |
|    |   - DELETE /api/v1/firewall/block/{rule_id} (Admin auth protected)           |     |
|    |   - GET /api/v1/notifications/status (Secrets strictly excluded)             |     |
|    +------------------------------------------------------------------------------+     |
|                                                                                         |
|    +-------------------------------------------------------------------------------+    |
|    |                      Notification Subsystem (Background)                      |    |
|    |                                                                               |    |
|    |  +--------------------+   qualify &   +-----------------------------+         |    |
|    |  | IDS Alert Raised   | ------------> |     NotificationManager     |         |    |
|    |  +--------------------+   cooldown    | (Default: 300s, max 10,000) |         |    |
|    |                                       +--------------+--------------+         |    |
|    |                                                      | enqueue                |    |
|    |                                                      v                        |    |
|    |                                       +-----------------------------+         |    |
|    |                                       |     NotificationWorker      |         |    |
|    |                                       | (Bounded Queue: 500 items)  |         |    |
|    |                                       +--------------+--------------+         |    |
|    |                                                      | SMTP / TLS             |    |
|    |                                                      v                        |    |
|    |                                       +-----------------------------+         |    |
|    |                                       |    EmailDeliveryService     |         |    |
|    |                                       | (kanvav.ec23@bmsce.ac.in)   |         |    |
|    |                                       +-----------------------------+         |    |
+----+------------------------------------------------------------------------------------+
```

---

## 1. Directory Structure

```
backend/
    __init__.py
    api/
        __init__.py
        main.py                 # FastAPI application factory, lifespan, CORS & exception handling
        dependencies.py         # ServiceContainer & dependency injection providers (including API key security)
        routes/
            __init__.py
            health.py           # GET /api/v1/health endpoint
            alerts.py           # GET /api/v1/alerts and /api/v1/alerts/{alert_id}
            flows.py            # GET /api/v1/flows and /api/v1/flows/{flow_id}
            packets.py          # GET /api/v1/packets (Metadata only)
            stats.py            # GET /api/v1/stats (Unified telemetry)
            ml.py               # GET /api/v1/ml/metrics and /api/v1/ml/status
            firewall.py         # GET /rules, POST /block, DELETE /block/{rule_id}
            notifications.py    # GET /api/v1/notifications/status
            websocket.py        # WS /ws/monitor real-time streaming endpoint
        schemas/
            __init__.py
            health_schema.py    # SubsystemStatus and HealthResponse models
            rest_schemas.py     # Pydantic models for all REST endpoints & pagination
        websocket/
            __init__.py
            events.py           # WebSocketEventType enum & WebSocketMessage schema
            manager.py          # Thread-safe WebSocketConnectionManager & ClientConnection
            traffic_broadcaster.py # Periodic aggregate traffic broadcaster task
    integrations/
        __init__.py
        pipeline_adapter.py     # Adapter connecting FastAPI to PipelineWorkerPool & ClientManager
        firewall_adapter.py     # Adapter interfacing with BlockingManager and WindowsFirewallEnforcer
        dpi_adapter.py          # Adapter interfacing with DPI protocol statistics
    services/
        __init__.py
        alert_service.py        # Security alerts domain query service
        flow_service.py         # Active connection flow domain service
        traffic_service.py      # Network bandwidth and client metrics service
        firewall_service.py     # Firewall administrative operations domain service
        ml_service.py           # Machine learning telemetry service
        notification/
            __init__.py
            notification_config.py      # Environment-backed email notification settings
            notification_manager.py     # Qualification filter and duplicate suppression cache
            notification_worker.py      # Dedicated asynchronous background thread worker
            email_service.py            # SMTP client with TLS, timeouts, and exception handling
            email_templates.py          # HTML/plain-text alert template rendering and sanitization
```

---

## 2. WebSocket Architecture & Event Streaming

### 2.1 Endpoint
- **URL**: `WS /ws/monitor`
- **Query Parameter / Header**: `?token=<TOKEN>` or `Authorization: Bearer <TOKEN>` or `Sec-WebSocket-Protocol: <TOKEN>`.
- **Authentication**: Validated against `DASHBOARD_WS_TOKEN` or `ADMIN_API_KEY` (default: `dpi-admin-secret-key`).

### 2.2 Event Envelope Contract
All outgoing messages follow a uniform JSON structure:
```json
{
  "event": "new_alert",
  "timestamp": "2026-11-10T14:30:00.123456Z",
  "data": { ... }
}
```

### 2.3 Supported Real-Time Events
- `new_alert`: Dispatched whenever `NetworkSecurityServer` or `PipelineWorkerPool` generates an IDS alert.
- `traffic_update`: Broadcast periodically (default 1.0s) with active flow counts, PPS, BPS, total packets, and protocol breakdowns.
- `new_flow`: Broadcast when new flows transition into tracking.
- `ml_event`: Broadcast for ML inference milestones and classifications.
- `firewall_event`: Broadcast when administrative blocks or unblocks are performed.
- `notification_event`: Dispatched upon email qualification, delivery, or cooldown suppression.
- `system_status`: Pushed immediately upon client connection to synchronize frontend dashboard state.

### 2.4 Thread Safety & Backpressure Guarantee
- **Thread-Safe Handoff**: Worker threads enqueue events via `ws_manager.publish_event_threadsafe(...)` using an internal non-blocking bridge queue (`queue.Queue(maxsize=1000)`). Worker threads never interact with async event loops or block waiting on network I/O.
- **Slow-Client Isolation**: Each connected client possesses an independent bounded queue (`asyncio.Queue(maxsize=100)`). If a slow client lags, low-priority events are discarded, dropping metrics are tracked, and healthy clients continue receiving live streams uninterrupted.

---

## 3. How to Start the Backend

1. **Configure Environment Variables**:
   Create a `.env` file from `.env.example`:
   ```bash
   cp .env.example .env
   ```
2. **Run with Uvicorn**:
   ```bash
   python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
   ```

---

## 4. How to Connect a Frontend WebSocket Client

In JavaScript/TypeScript (React):
```javascript
const token = "dpi-admin-secret-key";
const socket = new WebSocket(`ws://localhost:8000/ws/monitor?token=${token}`);

socket.onopen = () => {
  console.log("Connected to DPI/IDS Security WebSocket");
};

socket.onmessage = (event) => {
  const message = JSON.parse(event.data);
  switch (message.event) {
    case "system_status":
      console.log("System Status:", message.data);
      break;
    case "new_alert":
      console.warn("Security Alert:", message.data);
      break;
    case "traffic_update":
      console.log("Traffic Stats:", message.data);
      break;
    case "firewall_event":
      console.log("Firewall Block Event:", message.data);
      break;
  }
};

// Periodic heartbeat ping
setInterval(() => {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send("ping");
  }
}, 30000);
```

---

## 5. Security and Safety Guarantees
1. **Zero Raw Payload Leakage**: Raw packet payloads are never transmitted over REST or WebSocket streams.
2. **Credential Protection**: Passwords, tokens, and private keys are strictly excluded from all schemas and serialization models.
3. **ML Non-Enforcement**: Machine learning alerts alone never trigger automated firewall bans.
4. **Subnet Containment**: Core infrastructure addresses cannot be blocked via administrative endpoints.
