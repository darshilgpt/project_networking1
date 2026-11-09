"""TCP Stream Reassembly Engine with out-of-order, duplicate, retransmission, and direction support."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import logging
import time
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from models.flow_model import FlowKey
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.reassembly.tcp_reassembler")


class TrafficDirection(str, Enum):
    """Direction of traffic within a TCP flow."""
    CLIENT_TO_SERVER = "CLIENT_TO_SERVER"
    SERVER_TO_CLIENT = "SERVER_TO_CLIENT"
    UNKNOWN = "UNKNOWN"


@dataclass
class PendingRequest:
    """Tracks in-flight HTTP request metadata for response framing correlation."""
    method: str
    uri: str
    timestamp: float
    seq_index: int


class DirectionalTCPStream:
    """Reassembles TCP payload in one direction of a connection with bounded consumption."""

    def __init__(self, max_buffer_bytes: int = 512 * 1024) -> None:
        self.max_buffer_bytes = max_buffer_bytes
        self.expected_seq: Optional[int] = None
        # Out-of-order buffer: {seq_num: payload_bytes}
        self.out_of_order: Dict[int, bytes] = {}
        # Contiguous reassembled buffer
        self.reassembled = bytearray()
        self.consumed_bytes: int = 0
        self.last_activity: float = time.time()
        self.is_terminated: bool = False
        self.termination_type: Optional[str] = None  # "FIN" or "RST"
        self.is_desynchronized: bool = False

        # Metrics
        self.total_payload_bytes: int = 0
        self.retransmitted_segments: int = 0
        self.out_of_order_segments: int = 0
        self.duplicate_segments: int = 0
        self.has_overlap_conflict: bool = False
        self.overlap_conflict_count: int = 0
        self.last_event: str = "INIT"
        self.is_truncated: bool = False
        self.truncation_reason: Optional[str] = None

        # Message tracking and deduplication
        self.message_sequence: int = 0
        self.inspected_message_ids: Deque[str] = deque(maxlen=512)

        # Incomplete message independent timer (30s timeout)
        self.incomplete_message_start_time: Optional[float] = None
        self.incomplete_message_timeout: float = 30.0

    @property
    def buffered_bytes_count(self) -> int:
        return sum(len(p) for p in self.out_of_order.values())

    def check_incomplete_timeout(self, now: Optional[float] = None) -> bool:
        """
        Checks if unconsumed bytes have been waiting for completion longer than the 30s timeout.
        If timed out, marks stream as truncated, clears unconsumed buffer, and returns True.
        """
        curr = now if now is not None else time.time()
        if self.consumed_bytes < len(self.reassembled):
            if self.incomplete_message_start_time is None:
                self.incomplete_message_start_time = curr
            elif curr - self.incomplete_message_start_time > self.incomplete_message_timeout:
                self.is_truncated = True
                self.truncation_reason = "INCOMPLETE_MESSAGE_TIMEOUT_30S"
                self.is_desynchronized = True
                # Drop unconsumed bytes that exceeded timeout to prevent memory leak
                self.consumed_bytes = len(self.reassembled)
                self.incomplete_message_start_time = None
                return True
        else:
            self.incomplete_message_start_time = None
        return False

    def get_unconsumed_bytes(self) -> bytes:
        """Returns contiguous reassembled bytes that have not yet been consumed by L7 parsers."""
        if self.consumed_bytes >= len(self.reassembled):
            return b""
        return bytes(self.reassembled[self.consumed_bytes:])

    def advance_consumed(self, count: int) -> None:
        """Advances consumed byte offset and compacts buffer when threshold is reached."""
        self.consumed_bytes = min(len(self.reassembled), self.consumed_bytes + count)
        # Compact buffer when consumed prefix exceeds 32 KB to keep memory bounded
        if self.consumed_bytes > 32 * 1024:
            self.reassembled = self.reassembled[self.consumed_bytes:]
            self.consumed_bytes = 0

    def get_sequence_holes(self) -> List[Tuple[int, int]]:
        """Returns list of pending sequence gaps (hole_start, hole_end)."""
        if self.expected_seq is None or not self.out_of_order:
            return []
        holes = []
        curr = self.expected_seq
        for off in sorted(self.out_of_order.keys()):
            if off > curr:
                holes.append((curr, off))
            curr = max(curr, off + len(self.out_of_order[off]))
        return holes

    def push_segment(self, seq: int, payload: bytes, flags: Any, timestamp: float) -> bytes:
        """
        Pushes a TCP segment into the reassembler.

        Args:
            seq: 32-bit TCP sequence number.
            payload: Segment payload bytes.
            flags: TCPFlags object from ParsedPacket.
            timestamp: Capture timestamp.

        Returns:
            Newly available contiguous bytes that were reassembled by this segment.
        """
        self.last_activity = timestamp
        if self.incomplete_message_start_time is None and payload:
            self.incomplete_message_start_time = timestamp
        newly_reassembled = bytearray()

        if flags.rst:
            self.is_terminated = True
            self.termination_type = "RST"
        elif flags.fin:
            self.is_terminated = True
            if not self.termination_type:
                self.termination_type = "FIN"

        # Handle SYN sequence consumption
        if flags.syn:
            self.expected_seq = (seq + 1) & 0xFFFFFFFF
            if not payload:
                self.last_event = "SYN"
                return b""
            seq = (seq + 1) & 0xFFFFFFFF

        if not payload:
            self.last_event = "ACK_ONLY"
            return b""

        if self.expected_seq is None:
            self.expected_seq = seq

        seq_len = len(payload)
        expected = self.expected_seq

        # 1. Check for complete duplicate / old retransmission
        diff = (seq - expected) & 0xFFFFFFFF
        if diff > 0x80000000:
            bytes_behind = (expected - seq) & 0xFFFFFFFF
            if bytes_behind >= seq_len:
                self.retransmitted_segments += 1
                self.duplicate_segments += 1
                self.last_event = "DUPLICATE"
                return b""
            else:
                self.retransmitted_segments += 1
                # Check for conflicting overlapping payload bytes
                prev_overlap = self.reassembled[len(self.reassembled) - (seq_len - bytes_behind) :]
                new_overlap = payload[: bytes_behind]
                if prev_overlap and new_overlap and prev_overlap != new_overlap:
                    self.has_overlap_conflict = True
                    self.overlap_conflict_count += 1
                    self.last_event = "OVERLAP_CONFLICT"
                else:
                    self.last_event = "RETRANSMISSION"

                payload = payload[bytes_behind:]
                seq = expected
                seq_len = len(payload)

        # 2. In-order arrival (seq matches expected)
        if seq == self.expected_seq:
            self.last_event = "IN_ORDER"
            
            # Check buffer limit
            if len(self.reassembled) - self.consumed_bytes + seq_len > self.max_buffer_bytes:
                self.is_truncated = True
                self.truncation_reason = "STREAM_BUFFER_LIMIT_EXCEEDED"
                self.is_desynchronized = True
                logger.warning("TCP reassembly buffer exceeded maximum bound; truncating.")
                # Compact / discard unconsumed prefix to prevent unbounded growth
                self.reassembled = self.reassembled[self.consumed_bytes:]
                self.consumed_bytes = 0
                if len(self.reassembled) + seq_len > self.max_buffer_bytes:
                    payload = payload[: max(0, self.max_buffer_bytes - len(self.reassembled))]
                    seq_len = len(payload)

            if payload:
                self.reassembled.extend(payload)
                newly_reassembled.extend(payload)
                self.expected_seq = (self.expected_seq + seq_len) & 0xFFFFFFFF
                self.total_payload_bytes += seq_len

                # Drain contiguous segments from out-of-order buffer
                self._drain_contiguous(newly_reassembled)

        # 3. Out-of-order arrival (seq > expected, a gap/hole exists)
        else:
            self.out_of_order_segments += 1
            self.last_event = "OUT_OF_ORDER"
            if self.buffered_bytes_count + seq_len <= self.max_buffer_bytes:
                # Check overlap conflict with any buffered segments
                for b_seq, b_data in self.out_of_order.items():
                    o_start = max(seq, b_seq)
                    o_end = min(seq + seq_len, b_seq + len(b_data))
                    if o_start < o_end:
                        sub_new = payload[o_start - seq : o_end - seq]
                        sub_buf = b_data[o_start - b_seq : o_end - b_seq]
                        if sub_new != sub_buf:
                            self.has_overlap_conflict = True
                            self.overlap_conflict_count += 1
                            self.last_event = "OVERLAP_CONFLICT"
                self.out_of_order[seq] = payload
            else:
                self.is_truncated = True
                self.truncation_reason = "OUT_OF_ORDER_BUFFER_LIMIT_EXCEEDED"
                logger.warning("TCP out-of-order buffer exceeded limit; dropping segment.")

        return bytes(newly_reassembled)

    def _drain_contiguous(self, target_buf: bytearray) -> None:
        """Drains any buffered out-of-order segments that have now become contiguous."""
        while self.expected_seq in self.out_of_order:
            buffered_payload = self.out_of_order.pop(self.expected_seq)
            target_buf.extend(buffered_payload)
            self.reassembled.extend(buffered_payload)
            self.expected_seq = (self.expected_seq + len(buffered_payload)) & 0xFFFFFFFF
            self.total_payload_bytes += len(buffered_payload)

    def get_stream_bytes(self) -> bytes:
        """Returns all contiguous data reassembled so far."""
        return bytes(self.reassembled)

    def clear(self) -> None:
        """Frees buffers."""
        self.out_of_order.clear()
        self.reassembled.clear()
        self.consumed_bytes = 0
        self.inspected_message_ids.clear()


class TCPReassembler:
    """Manages bidirectional TCP stream reassembly for active flows with direction discovery."""

    def __init__(
        self,
        max_buffer_per_stream: int = 512 * 1024,
        stream_timeout: float = 60.0,
    ) -> None:
        self.max_buffer_per_stream = max_buffer_per_stream
        self.stream_timeout = stream_timeout
        # Mapping: FlowKey -> (forward_stream, reverse_stream)
        self._streams: Dict[FlowKey, Tuple[DirectionalTCPStream, DirectionalTCPStream]] = {}
        # Flow initiator tracking: FlowKey -> initiator endpoint (src_ip, src_port)
        self._initiators: Dict[FlowKey, Tuple[str, int]] = {}
        # Bounded FIFO request queue for HTTP pipelining correlation: FlowKey -> Deque[PendingRequest]
        self._pending_requests: Dict[FlowKey, Deque[PendingRequest]] = {}
        # Tracks if correlation queue experienced eviction/overflow
        self._correlation_uncertain: Dict[FlowKey, bool] = {}

    def _discover_direction(
        self,
        key: FlowKey,
        packet: ParsedPacket,
        src_endpoint: Tuple[str, int],
    ) -> TrafficDirection:
        """
        Discovers traffic direction using TCP handshake, payloads, or standard port conventions.
        """
        # 1. Handshake-based: SYN without ACK is the client initiator
        if packet.tcp and packet.tcp.flags.syn and not packet.tcp.flags.ack:
            self._initiators[key] = src_endpoint
            return TrafficDirection.CLIENT_TO_SERVER

        # Check existing initiator record
        if key in self._initiators:
            if self._initiators[key] == src_endpoint:
                return TrafficDirection.CLIENT_TO_SERVER
            else:
                return TrafficDirection.SERVER_TO_CLIENT

        # 2. Midstream payload inspection: HTTP request vs response
        if packet.payload:
            first_word = packet.payload[:10].split(b" ", 1)[0].upper()
            if first_word in (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"):
                self._initiators[key] = src_endpoint
                return TrafficDirection.CLIENT_TO_SERVER
            elif packet.payload.startswith(b"HTTP/1.") or packet.payload.startswith(b"HTTP/2"):
                # Sender is server; other endpoint is client
                other_endpoint = (
                    key.ip_b if src_endpoint[0] == key.ip_a else key.ip_a,
                    key.port_b if src_endpoint[1] == key.port_a else key.port_a,
                )
                self._initiators[key] = other_endpoint
                return TrafficDirection.SERVER_TO_CLIENT

        # 3. Standard server ports fallback
        server_ports = {80, 443, 8080, 8443, 3000, 5000, 8000}
        if packet.tcp:
            if packet.tcp.dst_port in server_ports and packet.tcp.src_port not in server_ports:
                self._initiators[key] = src_endpoint
                return TrafficDirection.CLIENT_TO_SERVER
            elif packet.tcp.src_port in server_ports and packet.tcp.dst_port not in server_ports:
                other_endpoint = (
                    key.ip_b if src_endpoint[0] == key.ip_a else key.ip_a,
                    key.port_b if src_endpoint[1] == key.port_a else key.port_a,
                )
                self._initiators[key] = other_endpoint
                return TrafficDirection.SERVER_TO_CLIENT

        return TrafficDirection.UNKNOWN

    def process_packet(self, packet: ParsedPacket) -> Tuple[bytes, bytes]:
        """
        Processes a packet through TCP stream reassembly.
        Preserves backward compatibility return contract: (new_chunk, full_stream_so_far).
        """
        if not packet.tcp:
            return b"", b""

        key, is_forward = FlowKey.from_packet(packet)
        if key is None:
            return b"", b""

        if key not in self._streams:
            fwd_stream = DirectionalTCPStream(self.max_buffer_per_stream)
            rev_stream = DirectionalTCPStream(self.max_buffer_per_stream)
            self._streams[key] = (fwd_stream, rev_stream)
            self._pending_requests[key] = deque(maxlen=128)
            self._correlation_uncertain[key] = False

        # Track direction
        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
        src_port = packet.tcp.src_port
        self._discover_direction(key, packet, (src_ip, src_port))

        fwd_stream, rev_stream = self._streams[key]
        target_stream = fwd_stream if is_forward else rev_stream

        ts = packet.timestamp or time.time()
        new_chunk = target_stream.push_segment(
            seq=packet.tcp.seq_num,
            payload=packet.payload,
            flags=packet.tcp.flags,
            timestamp=ts,
        )

        return new_chunk, target_stream.get_stream_bytes()

    def get_directional_context(
        self,
        packet: ParsedPacket,
    ) -> Tuple[Optional[DirectionalTCPStream], TrafficDirection, Optional[Deque[PendingRequest]]]:
        """
        Retrieves the exact directional stream, resolved traffic direction, and correlation queue.
        """
        if not packet.tcp:
            return None, TrafficDirection.UNKNOWN, None

        key, is_forward = FlowKey.from_packet(packet)
        if key is None or key not in self._streams:
            return None, TrafficDirection.UNKNOWN, None

        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
        src_port = packet.tcp.src_port
        direction = self._discover_direction(key, packet, (src_ip, src_port))

        fwd_stream, rev_stream = self._streams[key]
        target_stream = fwd_stream if is_forward else rev_stream
        pending_q = self._pending_requests.get(key)

        return target_stream, direction, pending_q

    def is_correlation_uncertain(self, key: FlowKey) -> bool:
        """Returns True if correlation queue experienced eviction."""
        return self._correlation_uncertain.get(key, False)

    def add_pending_request(self, key: FlowKey, req: PendingRequest) -> bool:
        """
        Adds a pending request to the flow's bounded correlation queue.
        If queue length is at max (128), records correlation uncertainty on eviction.
        """
        if key not in self._pending_requests:
            self._pending_requests[key] = deque(maxlen=128)
            self._correlation_uncertain[key] = False

        q = self._pending_requests[key]
        if len(q) == q.maxlen:
            self._correlation_uncertain[key] = True
            logger.warning("Pending request queue reached capacity (128); evicting oldest. Correlation marked uncertain.")

        q.append(req)
        return self._correlation_uncertain.get(key, False)

    def get_stream(self, key: FlowKey) -> Optional[Tuple[DirectionalTCPStream, DirectionalTCPStream]]:
        """Retrieves bidirectional stream pair for a flow."""
        return self._streams.get(key)

    def expire_streams(self, current_time: Optional[float] = None) -> int:
        """Removes idle or terminated TCP streams and cleans up correlation queues."""
        now = current_time or time.time()
        keys_to_remove = []

        for key, (fwd, rev) in self._streams.items():
            last_activity = max(fwd.last_activity, rev.last_activity)
            if (now - last_activity > self.stream_timeout) or (fwd.is_terminated and rev.is_terminated):
                keys_to_remove.append(key)

        for k in keys_to_remove:
            fwd, rev = self._streams.pop(k)
            fwd.clear()
            rev.clear()
            self._initiators.pop(k, None)
            self._pending_requests.pop(k, None)

        return len(keys_to_remove)

