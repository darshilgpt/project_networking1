"""Thread-safe WebSocket Connection and Event Manager for Phase 7.3."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import queue
import threading
from typing import Any, Dict, List, Optional, Set
from fastapi import WebSocket, WebSocketDisconnect

from backend.api.websocket.events import WebSocketEventType, WebSocketMessage

logger = logging.getLogger("dpi_ids_ips.backend.websocket.manager")


class ClientConnection:
    """Represents a connected WebSocket client with a bounded outgoing queue."""

    def __init__(self, websocket: WebSocket, queue_size: int = 100) -> None:
        self.websocket = websocket
        self.queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
        self.connected_at: float = datetime.now(timezone.utc).timestamp()
        self.messages_sent: int = 0
        self.messages_dropped: int = 0
        self._sender_task: Optional[asyncio.Task] = None

    def start_sender(self) -> None:
        """Launches the dedicated client sender task in the current event loop."""
        self._sender_task = asyncio.create_task(self._send_loop())

    async def _send_loop(self) -> None:
        """Continuously dequeues and delivers JSON messages to the client."""
        try:
            while True:
                msg = await self.queue.get()
                try:
                    await self.websocket.send_json(msg)
                    self.messages_sent += 1
                except Exception as e:
                    logger.debug(f"Client send error: {e}")
                    break
                finally:
                    self.queue.task_done()
        except asyncio.CancelledError:
            pass


class WebSocketConnectionManager:
    """
    Central connection manager supporting:
    - Thread-safe event submission from packet processing threads.
    - Asynchronous event loop dispatching via an internal bridge queue and worker task.
    - Multiple simultaneous connections with bounded outgoing queues.
    - Slow-client drop policies to prevent backpressure from impacting the IDS pipeline.
    - Heartbeat / Ping support and clean shutdown.
    """

    def __init__(self, bridge_queue_size: int = 1000, client_queue_size: int = 100) -> None:
        self.client_queue_size = client_queue_size
        self._clients: Set[ClientConnection] = set()
        self._lock = threading.Lock()

        # Thread-safe handoff queue: worker threads put_nowait into this thread queue
        self._bridge_queue: queue.Queue[WebSocketMessage] = queue.Queue(maxsize=bridge_queue_size)

        # Event loop references for handoff
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._dispatcher_task: Optional[asyncio.Task] = None
        self._is_running = False

        # Metrics
        self.total_events_published = 0
        self.total_events_dropped_bridge = 0
        self.total_client_drops = 0

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Stores the active ASGI event loop and launches the dispatcher task."""
        self._loop = loop
        self._is_running = True
        if self._dispatcher_task is None or self._dispatcher_task.done():
            self._dispatcher_task = asyncio.create_task(self._dispatcher_loop())
            logger.info("WebSocket Event Dispatcher worker task started.")

    async def _dispatcher_loop(self) -> None:
        """
        Runs inside the asyncio event loop. Drains the thread-safe bridge queue
        using polling or asyncio.sleep so task cancellation is immediate and responsive.
        """
        while self._is_running:
            try:
                # Drain all currently available messages non-blocking
                drained = []
                while not self._bridge_queue.empty():
                    try:
                        item = self._bridge_queue.get_nowait()
                        drained.append(item)
                    except queue.Empty:
                        break

                for msg in drained:
                    await self._broadcast_to_clients(msg)
                    self._bridge_queue.task_done()

                # Yield control briefly
                await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in WebSocket dispatcher loop: {e}")
                await asyncio.sleep(0.02)

    async def _broadcast_to_clients(self, msg: WebSocketMessage) -> None:
        """Fans out an event to all active clients using non-blocking queue puts."""
        payload = msg.model_dump()
        dead_clients = []

        with self._lock:
            clients_snapshot = list(self._clients)

        for client in clients_snapshot:
            try:
                # Attempt non-blocking put into client queue
                client.queue.put_nowait(payload)
            except asyncio.QueueFull:
                # Drop policy: Coalesce / drop for slow clients to protect pipeline
                client.messages_dropped += 1
                self.total_client_drops += 1
                logger.warning(f"Client queue full ({client.queue.maxsize}). Dropping event '{msg.event}'.")
            except Exception as ex:
                logger.debug(f"Error enqueuing to client: {ex}")
                dead_clients.append(client)

        for dead in dead_clients:
            await self.disconnect(dead)

    def publish_event_threadsafe(self, event_type: WebSocketEventType | str, data: Dict[str, Any]) -> bool:
        """
        Thread-safe entrypoint called from packet-processing threads, worker pool,
        or notification worker. Enqueues event without waiting or blocking.
        """
        ev_name = event_type.value if hasattr(event_type, "value") else str(event_type)
        msg = WebSocketMessage(event=ev_name, data=data)

        try:
            self._bridge_queue.put_nowait(msg)
            self.total_events_published += 1
            return True
        except queue.Full:
            self.total_events_dropped_bridge += 1
            logger.warning(f"WebSocket bridge queue full ({self._bridge_queue.maxsize}). Dropped event '{ev_name}'.")
            return False

    async def connect(self, websocket: WebSocket, subprotocol: Optional[str] = None) -> ClientConnection:
        """Accepts and registers a new client connection with optional subprotocol negotiation."""
        await websocket.accept(subprotocol=subprotocol)
        client = ClientConnection(websocket, queue_size=self.client_queue_size)
        client.start_sender()

        with self._lock:
            self._clients.add(client)

        logger.info(f"WebSocket client connected (subprotocol: {subprotocol}). Active clients: {len(self._clients)}")
        return client

    async def disconnect(self, client: ClientConnection) -> None:
        """Safely unregisters a client connection and stops its sender task."""
        with self._lock:
            self._clients.discard(client)

        if client._sender_task and not client._sender_task.done():
            client._sender_task.cancel()

        try:
            await client.websocket.close()
        except Exception:
            pass

        logger.info(f"WebSocket client disconnected. Active clients: {len(self._clients)}")

    def get_connection_metrics(self) -> Dict[str, Any]:
        """Provides snapshot metrics regarding WebSocket clients and event rates."""
        with self._lock:
            client_count = len(self._clients)
            total_sent = sum(c.messages_sent for c in self._clients)
            total_client_drops = self.total_client_drops + sum(c.messages_dropped for c in self._clients)

        return {
            "active_clients": client_count,
            "bridge_queue_depth": self._bridge_queue.qsize(),
            "bridge_queue_capacity": self._bridge_queue.maxsize,
            "total_events_published": self.total_events_published,
            "total_events_dropped_bridge": self.total_events_dropped_bridge,
            "total_client_drops": total_client_drops,
            "total_messages_sent": total_sent,
        }

    async def shutdown(self) -> None:
        """Gracefully disconnects all clients and terminates dispatcher task."""
        self._is_running = False
        with self._lock:
            clients = list(self._clients)
            self._clients.clear()

        for client in clients:
            if client._sender_task and not client._sender_task.done():
                client._sender_task.cancel()
            try:
                await client.websocket.close(code=1001, reason="Server shutting down")
            except Exception:
                pass

        if self._dispatcher_task and not self._dispatcher_task.done():
            self._dispatcher_task.cancel()

        # Drain bridge queue
        while not self._bridge_queue.empty():
            try:
                self._bridge_queue.get_nowait()
            except Exception:
                break

        logger.info("WebSocket connection manager shut down successfully.")


# Global WebSocket manager singleton
ws_manager = WebSocketConnectionManager()
